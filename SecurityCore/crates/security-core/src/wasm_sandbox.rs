//! WASM sandbox for user-defined custom detection rules.
//!
//! Users write detection rules in Rust/C/AssemblyScript, compile to .wasm.
//! wasmtime loads plugins with memory isolation (no filesystem, no network).
//!
//! Plugin interface:
//!   - `name() -> ptr, len` — returns the plugin name
//!   - `analyze(text_ptr, text_len) -> ptr, len` — returns JSON result
//!
//! Plugins are loaded from `~/.mac-security/rules/*.wasm`.

use std::path::{Path, PathBuf};
use wasmtime::*;

/// Result from a WASM plugin analysis.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PluginResult {
    pub plugin_name: String,
    pub matched: bool,
    pub label: Option<String>,
    pub severity: Option<String>,
    pub category: Option<String>,
}

/// Error from WASM plugin operations.
#[derive(Debug)]
pub enum PluginError {
    LoadFailed(String),
    ExecutionFailed(String),
    InvalidOutput(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoadFailed(msg) => write!(f, "Plugin load failed: {}", msg),
            Self::ExecutionFailed(msg) => write!(f, "Plugin execution failed: {}", msg),
            Self::InvalidOutput(msg) => write!(f, "Invalid plugin output: {}", msg),
        }
    }
}

impl std::error::Error for PluginError {}

/// A loaded WASM plugin instance.
pub struct WasmPlugin {
    store: Store<()>,
    instance: Instance,
    memory: Memory,
    name: String,
}

impl WasmPlugin {
    /// Load a plugin from a .wasm file.
    pub fn load(path: &Path) -> Result<Self, PluginError> {
        let engine = Engine::default();

        let wasm_bytes =
            std::fs::read(path).map_err(|e| PluginError::LoadFailed(format!("{}: {}", path.display(), e)))?;

        let module = Module::new(&engine, &wasm_bytes)
            .map_err(|e| PluginError::LoadFailed(format!("Compile: {}", e)))?;

        let mut store = Store::new(&engine, ());

        // No WASI — sandboxed with zero host capabilities
        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| PluginError::LoadFailed(format!("Instantiate: {}", e)))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| PluginError::LoadFailed("No 'memory' export".into()))?;

        // Get plugin name
        let name = Self::call_name(&mut store, &instance, &memory)?;

        Ok(Self {
            store,
            instance,
            memory,
            name,
        })
    }

    /// Get the plugin's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Run the plugin's analyze function on text, return structured result.
    pub fn analyze(&mut self, text: &str) -> Result<PluginResult, PluginError> {
        let alloc = self
            .instance
            .get_typed_func::<i32, i32>(&mut self.store, "alloc")
            .map_err(|e| PluginError::ExecutionFailed(format!("No 'alloc' export: {}", e)))?;

        let analyze_fn = self
            .instance
            .get_typed_func::<(i32, i32), i64>(&mut self.store, "analyze")
            .map_err(|e| PluginError::ExecutionFailed(format!("No 'analyze' export: {}", e)))?;

        // Allocate memory in guest and write text
        let text_bytes = text.as_bytes();
        let ptr = alloc
            .call(&mut self.store, text_bytes.len() as i32)
            .map_err(|e| PluginError::ExecutionFailed(format!("alloc: {}", e)))?;

        self.memory
            .write(&mut self.store, ptr as usize, text_bytes)
            .map_err(|e| PluginError::ExecutionFailed(format!("memory write: {}", e)))?;

        // Call analyze(ptr, len) -> packed(ptr, len) as i64
        let result = analyze_fn
            .call(&mut self.store, (ptr, text_bytes.len() as i32))
            .map_err(|e| PluginError::ExecutionFailed(format!("analyze: {}", e)))?;

        let result_ptr = (result >> 32) as usize;
        let result_len = (result & 0xFFFFFFFF) as usize;

        if result_len == 0 {
            return Ok(PluginResult {
                plugin_name: self.name.clone(),
                matched: false,
                label: None,
                severity: None,
                category: None,
            });
        }

        let mut buf = vec![0u8; result_len];
        self.memory
            .read(&self.store, result_ptr, &mut buf)
            .map_err(|e| PluginError::ExecutionFailed(format!("memory read: {}", e)))?;

        let json_str = String::from_utf8(buf)
            .map_err(|e| PluginError::InvalidOutput(format!("UTF-8: {}", e)))?;

        serde_json::from_str::<PluginResult>(&json_str)
            .map_err(|e| PluginError::InvalidOutput(format!("JSON: {}", e)))
    }

    fn call_name(
        store: &mut Store<()>,
        instance: &Instance,
        memory: &Memory,
    ) -> Result<String, PluginError> {
        let name_fn = instance
            .get_typed_func::<(), i64>(&mut *store, "name")
            .map_err(|e| PluginError::LoadFailed(format!("No 'name' export: {}", e)))?;

        let result = name_fn
            .call(&mut *store, ())
            .map_err(|e| PluginError::LoadFailed(format!("name(): {}", e)))?;

        let ptr = (result >> 32) as usize;
        let len = (result & 0xFFFFFFFF) as usize;

        if len == 0 || len > 256 {
            return Ok("unnamed".to_string());
        }

        let mut buf = vec![0u8; len];
        memory
            .read(&*store, ptr, &mut buf)
            .map_err(|e| PluginError::LoadFailed(format!("read name: {}", e)))?;

        String::from_utf8(buf).map_err(|_| PluginError::LoadFailed("Invalid name UTF-8".into()))
    }
}

/// Plugin loader — discovers and loads all .wasm files from a rules directory.
pub struct PluginLoader {
    rules_dir: PathBuf,
}

impl PluginLoader {
    pub fn new(rules_dir: &str) -> Self {
        Self {
            rules_dir: PathBuf::from(rules_dir),
        }
    }

    /// Discover all .wasm files in the rules directory.
    pub fn discover(&self) -> Vec<PathBuf> {
        if !self.rules_dir.exists() {
            return Vec::new();
        }

        let mut plugins = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
                    plugins.push(path);
                }
            }
        }
        plugins.sort();
        plugins
    }

    /// Load all discovered plugins. Returns (loaded, errors).
    pub fn load_all(&self) -> (Vec<WasmPlugin>, Vec<(PathBuf, PluginError)>) {
        let mut loaded = Vec::new();
        let mut errors = Vec::new();

        for path in self.discover() {
            match WasmPlugin::load(&path) {
                Ok(plugin) => loaded.push(plugin),
                Err(e) => errors.push((path, e)),
            }
        }

        (loaded, errors)
    }

    /// Run all loaded plugins against text, collecting results.
    pub fn analyze_all(plugins: &mut [WasmPlugin], text: &str) -> Vec<PluginResult> {
        let mut results = Vec::new();
        for plugin in plugins.iter_mut() {
            match plugin.analyze(text) {
                Ok(result) if result.matched => results.push(result),
                Ok(_) => {} // no match
                Err(e) => {
                    eprintln!("Plugin {} error: {}", plugin.name(), e);
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_loader_handles_missing_dir() {
        let loader = PluginLoader::new("/nonexistent/rules");
        assert!(loader.discover().is_empty());
    }

    #[test]
    fn plugin_loader_discovers_wasm_files() {
        let tmp = std::env::temp_dir().join("seccore_wasm_test");
        let _ = std::fs::create_dir_all(&tmp);

        // Create dummy files
        std::fs::write(tmp.join("rule1.wasm"), b"dummy").unwrap();
        std::fs::write(tmp.join("rule2.wasm"), b"dummy").unwrap();
        std::fs::write(tmp.join("not_a_rule.txt"), b"dummy").unwrap();

        let loader = PluginLoader::new(tmp.to_str().unwrap());
        let plugins = loader.discover();

        assert_eq!(plugins.len(), 2);
        assert!(plugins.iter().all(|p| p.extension().unwrap() == "wasm"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn invalid_wasm_fails_gracefully() {
        let tmp = std::env::temp_dir().join("seccore_wasm_invalid");
        let _ = std::fs::create_dir_all(&tmp);
        let path = tmp.join("bad.wasm");
        std::fs::write(&path, b"not valid wasm").unwrap();

        let result = WasmPlugin::load(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn plugin_result_serde() {
        let result = PluginResult {
            plugin_name: "test-rule".to_string(),
            matched: true,
            label: Some("Custom threat detected".to_string()),
            severity: Some("HIGH".to_string()),
            category: Some("custom_rule".to_string()),
        };

        let json = serde_json::to_string(&result).unwrap();
        let back: PluginResult = serde_json::from_str(&json).unwrap();

        assert_eq!(back.plugin_name, "test-rule");
        assert!(back.matched);
        assert_eq!(back.label.as_deref(), Some("Custom threat detected"));
    }
}
