//! Model weight verification — SHA-256 hashing of LLM model files.
//!
//! Auto-detects model files in known directories (Ollama, LM Studio, HuggingFace, etc.).
//! Hashes them on first discovery, then re-verifies periodically.
//! If a hash changes without a new download, it's flagged as tampering.
//!
//! Behavior:
//! - New file appears → hash it → store in manifest (known-good baseline)
//! - Existing file, hash matches → verified (clean)
//! - Existing file, hash changed → ALERT: tampered
//! - File deleted → remove from manifest (no alert, user is managing their models)
//! - Same filename re-downloaded → new hash replaces old (legitimate update)

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::path_resolver::PathResolver;

/// Known model file extensions.
const MODEL_EXTENSIONS: &[&str] = &[
    ".gguf", ".ggml",                          // llama.cpp, ik_llama.cpp
    ".safetensors",                             // HuggingFace safetensors
    ".bin", ".pth", ".pt",                      // PyTorch
    ".onnx",                                    // ONNX
    ".mlmodel", ".mlpackage",                   // Core ML
    ".npz",                                     // Apple MLX (NumPy compressed)
    ".npy",                                     // NumPy array (MLX weights)
];

/// Directories to scan for model files (relative to home).
const DEFAULT_MODEL_DIRS: &[&str] = &[
    ".ollama/models",                           // Ollama
    ".lmstudio/models",                         // LM Studio (current default location)
    ".cache/lm-studio/models",                  // LM Studio (legacy location)
    ".cache/huggingface/hub",                   // HuggingFace
    ".cache/mlx",                               // Apple MLX cache
    "models",                                   // Common user convention
    "LeanInfer/models",                         // LeanInfer / custom llama.cpp builds
    ".local/share/nomic.ai/GPT4All",            // GPT4All
];

/// Result of verifying a single model file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub path: String,
    pub status: VerifyStatus,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyStatus {
    /// Hash matches manifest — file is clean.
    Verified,
    /// New file, not in manifest — hashed and recorded.
    NewModel,
    /// Hash changed since last verification — possible tampering.
    Tampered,
    /// File in manifest but no longer exists — removed from manifest.
    Removed,
    /// Could not read/hash the file.
    Error,
}

/// Manifest entry for a tracked model file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEntry {
    pub hash: String,
    pub size_bytes: u64,
    pub first_seen: String,
    pub last_verified: String,
}

/// The model manifest — maps file paths to their known-good hashes.
pub type ModelManifest = HashMap<String, ModelEntry>;

/// Compute SHA-256 hash of a file using streaming (8KB chunks).
/// Handles files of any size (70GB+ models).
pub fn hash_file(path: &str) -> Result<(String, u64), String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Cannot open {}: {}", path, e))?;

    let metadata = file.metadata()
        .map_err(|e| format!("Cannot stat {}: {}", path, e))?;
    let size = metadata.len();

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| format!("Read error on {}: {}", path, e))?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = format!("{:x}", hasher.finalize());
    Ok((hash, size))
}

/// Load the model manifest from disk.
pub fn load_manifest(security_dir: &str) -> ModelManifest {
    let path = PathBuf::from(security_dir).join("model-manifest.json");
    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// Save the model manifest to disk (atomic write).
pub fn save_manifest(security_dir: &str, manifest: &ModelManifest) -> Result<(), String> {
    let path = PathBuf::from(security_dir).join("model-manifest.json");
    let tmp = PathBuf::from(security_dir).join("model-manifest.json.tmp");
    let json = serde_json::to_string_pretty(manifest)
        .map_err(|e| format!("Serialize error: {}", e))?;
    fs::write(&tmp, &json)
        .map_err(|e| format!("Write error: {}", e))?;
    fs::rename(&tmp, &path)
        .map_err(|e| format!("Rename error: {}", e))?;
    Ok(())
}

/// Discover model files in the given directories.
pub fn scan_model_directories(paths: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for dir in paths {
        let expanded = expand_home(dir);
        if !Path::new(&expanded).exists() { continue; }
        walk_for_models(&expanded, &mut found, 0);
    }
    found
}

/// Get default model directory paths (expanded to absolute).
pub fn default_model_paths() -> Vec<String> {
    let resolver = PathResolver::new();
    let home = resolver.home();
    DEFAULT_MODEL_DIRS.iter()
        .map(|d| format!("{}/{}", home, d))
        .collect()
}

/// Verify all tracked models + discover new ones.
/// Returns a list of verification results.
pub fn verify_models(security_dir: &str, scan_paths: &[String]) -> Vec<VerificationResult> {
    let mut manifest = load_manifest(security_dir);
    let mut results = Vec::new();
    let now = chrono::Utc::now().to_rfc3339();

    // 1. Discover model files
    let discovered = scan_model_directories(scan_paths);

    // 2. Check each discovered file against manifest
    for path in &discovered {
        match hash_file(path) {
            Ok((hash, size)) => {
                let existing = manifest.get(path).cloned();
                if let Some(entry) = existing {
                    if entry.hash == hash {
                        // Hash matches — verified clean
                        let mut updated = entry.clone();
                        updated.last_verified = now.clone();
                        manifest.insert(path.clone(), updated);
                        results.push(VerificationResult {
                            path: path.clone(),
                            status: VerifyStatus::Verified,
                            expected_hash: Some(entry.hash),
                            actual_hash: Some(hash),
                            size_bytes: size,
                        });
                    } else {
                        // Hash changed — possible tampering OR re-download
                        results.push(VerificationResult {
                            path: path.clone(),
                            status: VerifyStatus::Tampered,
                            expected_hash: Some(entry.hash),
                            actual_hash: Some(hash.clone()),
                            size_bytes: size,
                        });
                        // Update manifest to new hash (user can investigate)
                        manifest.insert(path.clone(), ModelEntry {
                            hash,
                            size_bytes: size,
                            first_seen: entry.first_seen,
                            last_verified: now.clone(),
                        });
                    }
                } else {
                    // New model — record it
                    manifest.insert(path.clone(), ModelEntry {
                        hash: hash.clone(),
                        size_bytes: size,
                        first_seen: now.clone(),
                        last_verified: now.clone(),
                    });
                    results.push(VerificationResult {
                        path: path.clone(),
                        status: VerifyStatus::NewModel,
                        expected_hash: None,
                        actual_hash: Some(hash),
                        size_bytes: size,
                    });
                }
            }
            Err(_) => {
                results.push(VerificationResult {
                    path: path.clone(),
                    status: VerifyStatus::Error,
                    expected_hash: manifest.get(path).map(|e| e.hash.clone()),
                    actual_hash: None,
                    size_bytes: 0,
                });
            }
        }
    }

    // 3. Check for removed models (in manifest but not on disk)
    let discovered_set: std::collections::HashSet<&String> = discovered.iter().collect();
    let removed: Vec<String> = manifest.keys()
        .filter(|k| !discovered_set.contains(k))
        .cloned()
        .collect();
    for path in &removed {
        results.push(VerificationResult {
            path: path.clone(),
            status: VerifyStatus::Removed,
            expected_hash: manifest.get(path).map(|e| e.hash.clone()),
            actual_hash: None,
            size_bytes: 0,
        });
        manifest.remove(path);
    }

    // 4. Save updated manifest
    let _ = save_manifest(security_dir, &manifest);

    results
}

// -- Helpers --

fn is_model_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    // Standard model extensions
    if MODEL_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        return true;
    }
    // Ollama blob format: sha256-<hex> (no extension, large files)
    if lower.starts_with("sha256-") && lower.len() > 70 {
        return true;
    }
    false
}

fn walk_for_models(dir: &str, found: &mut Vec<String>, depth: u32) {
    if depth > 10 { return; } // prevent infinite recursion
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_for_models(path.to_str().unwrap_or(""), found, depth + 1);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if is_model_file(name) {
                if let Some(p) = path.to_str() {
                    found.push(p.to_string());
                }
            }
        }
    }
}

fn expand_home(path: &str) -> String {
    if path.starts_with("~/") {
        let resolver = PathResolver::new();
        format!("{}{}", resolver.home(), &path[1..])
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_small_file() {
        let dir = std::env::temp_dir().join("aisec_model_test");
        let _ = fs::create_dir_all(&dir);
        let model_path = dir.join("test.gguf");
        fs::write(&model_path, b"fake model weights for testing").unwrap();

        let (hash, size) = hash_file(model_path.to_str().unwrap()).unwrap();
        assert!(!hash.is_empty());
        assert_eq!(size, 30);
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hash_changes_on_modification() {
        let dir = std::env::temp_dir().join("aisec_model_test2");
        let _ = fs::create_dir_all(&dir);
        let model_path = dir.join("test.gguf");

        fs::write(&model_path, b"original weights").unwrap();
        let (hash1, _) = hash_file(model_path.to_str().unwrap()).unwrap();

        fs::write(&model_path, b"tampered weights").unwrap();
        let (hash2, _) = hash_file(model_path.to_str().unwrap()).unwrap();

        assert_ne!(hash1, hash2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_new_model() {
        let dir = std::env::temp_dir().join("aisec_model_verify");
        let _ = fs::create_dir_all(dir.join("models"));
        let model_path = dir.join("models/test.gguf");
        fs::write(&model_path, b"test model data").unwrap();

        let results = verify_models(
            dir.to_str().unwrap(),
            &[dir.join("models").to_str().unwrap().to_string()],
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, VerifyStatus::NewModel);

        // Second verify should be Verified (hash matches)
        let results2 = verify_models(
            dir.to_str().unwrap(),
            &[dir.join("models").to_str().unwrap().to_string()],
        );
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0].status, VerifyStatus::Verified);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_tampering() {
        let dir = std::env::temp_dir().join("aisec_model_tamper");
        let _ = fs::create_dir_all(dir.join("models"));
        let model_path = dir.join("models/test.gguf");

        // First: create and verify
        fs::write(&model_path, b"original model").unwrap();
        verify_models(dir.to_str().unwrap(), &[dir.join("models").to_str().unwrap().to_string()]);

        // Tamper with the file
        fs::write(&model_path, b"TAMPERED model!!").unwrap();
        let results = verify_models(
            dir.to_str().unwrap(),
            &[dir.join("models").to_str().unwrap().to_string()],
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, VerifyStatus::Tampered);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_deleted_model() {
        let dir = std::env::temp_dir().join("aisec_model_delete");
        let _ = fs::create_dir_all(dir.join("models"));
        let model_path = dir.join("models/test.gguf");

        // Create and register
        fs::write(&model_path, b"model data").unwrap();
        verify_models(dir.to_str().unwrap(), &[dir.join("models").to_str().unwrap().to_string()]);

        // Delete the file
        fs::remove_file(&model_path).unwrap();
        let results = verify_models(
            dir.to_str().unwrap(),
            &[dir.join("models").to_str().unwrap().to_string()],
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, VerifyStatus::Removed);

        // Manifest should be clean now
        let manifest = load_manifest(dir.to_str().unwrap());
        assert!(manifest.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_model_file_checks() {
        assert!(is_model_file("llama-3.1-8b.gguf"));
        assert!(is_model_file("model.safetensors"));
        assert!(is_model_file("weights.bin"));
        assert!(is_model_file("model.pth"));
        assert!(is_model_file("model.onnx"));
        assert!(is_model_file("model.npz")); // MLX
        // Ollama blob format
        assert!(is_model_file("sha256-005f95c7475154a17e84b85cd497949d6dd2a4f9d77c096e3c66e4d9c32acaf5"));
        assert!(!is_model_file("sha256-short")); // too short for blob
        assert!(!is_model_file("readme.txt"));
        assert!(!is_model_file("config.json"));
        assert!(!is_model_file("photo.jpg"));
    }
}
