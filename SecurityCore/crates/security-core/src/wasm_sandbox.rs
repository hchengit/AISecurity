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

/// Hard limits applied to every untrusted plugin, independent of what the
/// module itself declares — defense-in-depth against a hostile `.wasm`:
///   - `FUEL_PER_CALL` bounds executed instructions per guest call, so an
///     infinite loop traps instead of hanging the host.
///   - the memory limiter caps linear-memory growth (RAM-exhaustion DoS).
///   - `MAX_RESULT_BYTES` caps the host-side buffer we allocate for a plugin's
///     return value; the guest returns an arbitrary length, and without a cap
///     it could force a multi-GB host allocation.
const FUEL_PER_CALL: u64 = 1_000_000_000;
const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024; // 64 MB
const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024; // 4 MB

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
    store: Store<StoreLimits>,
    instance: Instance,
    memory: Memory,
    name: String,
}

impl WasmPlugin {
    /// Load a plugin from a .wasm file.
    pub fn load(path: &Path) -> Result<Self, PluginError> {
        // Enable fuel metering so guest execution is instruction-bounded.
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)
            .map_err(|e| PluginError::LoadFailed(format!("Engine: {}", e)))?;

        let wasm_bytes =
            std::fs::read(path).map_err(|e| PluginError::LoadFailed(format!("{}: {}", path.display(), e)))?;

        let module = Module::new(&engine, &wasm_bytes)
            .map_err(|e| PluginError::LoadFailed(format!("Compile: {}", e)))?;

        // The store's data IS the resource limiter — caps linear-memory growth.
        let limits = StoreLimitsBuilder::new().memory_size(MAX_MEMORY_BYTES).build();
        let mut store = Store::new(&engine, limits);
        store.limiter(|lim| lim);
        store
            .set_fuel(FUEL_PER_CALL)
            .map_err(|e| PluginError::LoadFailed(format!("set_fuel: {}", e)))?;

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
        // Fresh instruction budget for this call.
        self.store
            .set_fuel(FUEL_PER_CALL)
            .map_err(|e| PluginError::ExecutionFailed(format!("set_fuel: {}", e)))?;

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

        // Cap the host-side allocation — the guest controls result_len and could
        // otherwise force a multi-GB allocation (unbounded-allocation DoS).
        if result_len > MAX_RESULT_BYTES {
            return Err(PluginError::InvalidOutput(format!(
                "result too large: {} bytes (max {})",
                result_len, MAX_RESULT_BYTES
            )));
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
        store: &mut Store<StoreLimits>,
        instance: &Instance,
        memory: &Memory,
    ) -> Result<String, PluginError> {
        store
            .set_fuel(FUEL_PER_CALL)
            .map_err(|e| PluginError::LoadFailed(format!("set_fuel: {}", e)))?;

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

    // Compile inline WAT to a temp `.wasm` file (Module::new parses WAT when
    // the bytes aren't a binary module) and return its path.
    fn write_wat(dir: &Path, file: &str, wat: &str) -> PathBuf {
        let _ = std::fs::create_dir_all(dir);
        let p = dir.join(file);
        std::fs::write(&p, wat.as_bytes()).unwrap();
        p
    }

    #[test]
    fn loads_and_runs_a_real_plugin() {
        let dir = std::env::temp_dir().join("seccore_wasm_run");
        let _ = std::fs::remove_dir_all(&dir);
        let json = r#"{"plugin_name":"watrule","matched":true,"label":"hit","severity":"HIGH","category":"custom"}"#;
        let json_wat = json.replace('\\', "\\\\").replace('"', "\\\"");
        let wat = format!(
            r#"(module
  (memory (export "memory") 1)
  (data (i32.const 0) "watrule")
  (data (i32.const 16) "{json_wat}")
  (func (export "name") (result i64) (i64.const 7))
  (func (export "alloc") (param i32) (result i32) (i32.const 2048))
  (func (export "analyze") (param i32 i32) (result i64)
    (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const {len}))))"#,
            json_wat = json_wat,
            len = json.len()
        );
        let path = write_wat(&dir, "ok.wasm", &wat);

        let mut plugin = WasmPlugin::load(&path).expect("plugin should load");
        assert_eq!(plugin.name(), "watrule");
        let r = plugin.analyze("anything").expect("analyze should succeed");
        assert!(r.matched);
        assert_eq!(r.label.as_deref(), Some("hit"));
        assert_eq!(r.severity.as_deref(), Some("HIGH"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn infinite_loop_traps_on_fuel_not_hangs() {
        let dir = std::env::temp_dir().join("seccore_wasm_loop");
        let _ = std::fs::remove_dir_all(&dir);
        // analyze() spins forever; fuel metering must trap it instead of hanging.
        let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "name") (result i64) (i64.const 0))
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "analyze") (param i32 i32) (result i64)
    (loop $l (br $l))
    (i64.const 0)))"#;
        let path = write_wat(&dir, "loop.wasm", wat);

        let mut plugin = WasmPlugin::load(&path).expect("plugin should load");
        let r = plugin.analyze("x");
        assert!(r.is_err(), "infinite loop must trap (fuel), got {:?}", r);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_result_is_rejected() {
        let dir = std::env::temp_dir().join("seccore_wasm_big");
        let _ = std::fs::remove_dir_all(&dir);
        // analyze() claims a ~2GB result length; the host must refuse to
        // allocate it rather than OOM.
        let wat = r#"(module
  (memory (export "memory") 1)
  (func (export "name") (result i64) (i64.const 0))
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "analyze") (param i32 i32) (result i64)
    (i64.const 0x7FFFFFFF)))"#;
        let path = write_wat(&dir, "big.wasm", wat);

        let mut plugin = WasmPlugin::load(&path).expect("plugin should load");
        let r = plugin.analyze("x");
        assert!(
            matches!(r, Err(PluginError::InvalidOutput(_))),
            "oversized result must be rejected, got {:?}",
            r
        );

        let _ = std::fs::remove_dir_all(&dir);
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
