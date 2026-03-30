//! Vault — file/folder protection with AES-256-GCM encryption.
//!
//! Supports three protection levels:
//!   - Locked:     AES-256-GCM encrypted in-place, original securely deleted
//!   - ReadOnly:   chmod 444, monitored for write attempts
//!   - LocalOnly:  read/write allowed, alert on network exfiltration
//!
//! All mutating operations require passphrase authentication.
//! The vault manifest itself is encrypted on disk.

use crate::encryption::{EncryptedData, Encryptor, EncryptionError};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

// ─── AAD tag for vault context ──────────────────────────────────────────────

pub const VAULT_AAD: &[u8] = b"securitycore:vault:v1";
pub const VAULT_MANIFEST_AAD: &[u8] = b"securitycore:vault-manifest:v1";

// ─── Types ──────────────────────────────────────────────────────────────────

/// Protection policy for a vault entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    /// Encrypted in-place. Original securely deleted. No access without passphrase.
    Locked,
    /// File set to read-only (chmod 444). Write attempts trigger alert.
    ReadOnly,
    /// Read/write allowed locally. Network exfiltration triggers alert.
    LocalOnly,
}

impl std::fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "locked"),
            Self::ReadOnly => write!(f, "read-only"),
            Self::LocalOnly => write!(f, "local-only"),
        }
    }
}

/// A single vault entry — one protected file or folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub original_path: String,
    pub vault_path: String,
    pub protection: ProtectionLevel,
    pub encrypted_at: String,
    pub size_bytes: u64,
    pub sha256_original: String,
    pub is_directory: bool,
    /// Currently unlocked (decrypted and accessible)?
    #[serde(default)]
    pub is_unlocked: bool,
}

/// The vault manifest — tracks all protected entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultManifest {
    pub version: u32,
    pub created: String,
    pub entries: Vec<VaultEntry>,
}

impl Default for VaultManifest {
    fn default() -> Self {
        Self {
            version: 1,
            created: chrono::Utc::now().to_rfc3339(),
            entries: Vec::new(),
        }
    }
}

/// Result of a vault operation.
#[derive(Debug)]
pub struct VaultResult {
    pub success: bool,
    pub message: String,
    pub entries_affected: usize,
}

/// Vault error.
#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Encryption(EncryptionError),
    InvalidPassphrase,
    FileNotFound(String),
    AlreadyProtected(String),
    NotInVault(String),
    ManifestCorrupted(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Encryption(e) => write!(f, "Encryption error: {}", e),
            Self::InvalidPassphrase => write!(f, "Invalid passphrase"),
            Self::FileNotFound(p) => write!(f, "File not found: {}", p),
            Self::AlreadyProtected(p) => write!(f, "Already protected: {}", p),
            Self::NotInVault(p) => write!(f, "Not in vault: {}", p),
            Self::ManifestCorrupted(m) => write!(f, "Manifest corrupted: {}", m),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

impl From<EncryptionError> for VaultError {
    fn from(e: EncryptionError) -> Self { Self::Encryption(e) }
}

// ─── Vault Engine ───────────────────────────────────────────────────────────

/// The vault engine — manages file protection lifecycle.
pub struct Vault {
    security_dir: PathBuf,
    manifest_path: PathBuf,
    salt_path: PathBuf,
}

impl Vault {
    /// Create a new vault instance rooted at the given security directory.
    pub fn new(security_dir: &str) -> Self {
        let security_dir = PathBuf::from(security_dir);
        let manifest_path = security_dir.join("vault.json.enc");
        let salt_path = security_dir.join(".vault-salt");
        Self { security_dir, manifest_path, salt_path }
    }

    /// Check if vault has been set up (salt + manifest exist).
    pub fn is_setup(&self) -> bool {
        self.salt_path.exists()
    }

    /// First-time setup — generate salt. Returns Ok(()) if already set up.
    pub fn setup(&self) -> Result<(), VaultError> {
        fs::create_dir_all(&self.security_dir)?;

        if !self.salt_path.exists() {
            let mut salt = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut salt);
            fs::write(&self.salt_path, salt)?;

            // Write initial empty manifest
            let manifest = VaultManifest::default();
            self.save_manifest_with_salt(&manifest, &salt)?;
        }

        // Write recovery instructions
        self.write_recovery_file()?;

        Ok(())
    }

    /// Verify passphrase is correct by trying to load the manifest.
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<bool, VaultError> {
        match self.load_manifest(passphrase) {
            Ok(_) => Ok(true),
            Err(VaultError::InvalidPassphrase) => Ok(false),
            Err(VaultError::Encryption(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// List all vault entries (loads manifest).
    pub fn list(&self, passphrase: &str) -> Result<Vec<VaultEntry>, VaultError> {
        let manifest = self.load_manifest(passphrase)?;
        Ok(manifest.entries)
    }

    /// Add files to the vault with the given protection level.
    pub fn add(
        &self,
        paths: &[&str],
        protection: ProtectionLevel,
        passphrase: &str,
    ) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;
        let encryptor = self.make_encryptor(passphrase)?;
        let mut affected = 0;

        for path_str in paths {
            let path = Path::new(path_str);
            if !path.exists() {
                return Err(VaultError::FileNotFound(path_str.to_string()));
            }

            // Check not already in vault
            if manifest.entries.iter().any(|e| e.original_path == *path_str) {
                continue; // skip silently
            }

            if path.is_dir() {
                // Recursively add directory contents
                affected += self.add_directory(path, protection, &encryptor, &mut manifest)?;
            } else {
                self.add_single_file(path, protection, &encryptor, &mut manifest)?;
                affected += 1;
            }
        }

        self.save_manifest_passphrase(&manifest, passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("{} file(s) protected with {} policy", affected, protection),
            entries_affected: affected,
        })
    }

    /// Unlock (decrypt) vault entries back to their original paths.
    pub fn unlock(&self, paths: &[&str], passphrase: &str) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;
        let encryptor = self.make_encryptor(passphrase)?;
        let mut affected = 0;

        for path_str in paths {
            if let Some(entry) = manifest.entries.iter_mut().find(|e| {
                e.original_path == *path_str || e.vault_path == *path_str
            }) {
                if entry.protection != ProtectionLevel::Locked {
                    continue;
                }
                if entry.is_unlocked {
                    continue;
                }

                let vault_path = Path::new(&entry.vault_path);
                if !vault_path.exists() {
                    continue;
                }

                // Decrypt
                let encrypted_bytes = fs::read(vault_path)?;
                let encrypted_data = EncryptedData::from_bytes(&encrypted_bytes)?;
                let plaintext = encryptor.decrypt(&encrypted_data, VAULT_AAD)?;

                // Write original
                fs::write(&entry.original_path, &plaintext)?;
                entry.is_unlocked = true;
                affected += 1;
            }
        }

        self.save_manifest_passphrase(&manifest, passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("{} file(s) unlocked", affected),
            entries_affected: affected,
        })
    }

    /// Lock (re-encrypt) previously unlocked entries.
    pub fn lock(&self, paths: &[&str], passphrase: &str) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;
        let encryptor = self.make_encryptor(passphrase)?;
        let mut affected = 0;

        for path_str in paths {
            if let Some(entry) = manifest.entries.iter_mut().find(|e| {
                e.original_path == *path_str || e.vault_path == *path_str
            }) {
                if entry.protection != ProtectionLevel::Locked || !entry.is_unlocked {
                    continue;
                }

                let original_path = Path::new(&entry.original_path);
                if !original_path.exists() {
                    continue;
                }

                // Re-encrypt
                let plaintext = fs::read(original_path)?;
                let encrypted = encryptor.encrypt(&plaintext, VAULT_AAD)?;
                fs::write(&entry.vault_path, encrypted.to_bytes())?;

                // Secure delete original
                secure_delete(original_path)?;
                entry.is_unlocked = false;
                affected += 1;
            }
        }

        self.save_manifest_passphrase(&manifest, passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("{} file(s) locked", affected),
            entries_affected: affected,
        })
    }

    /// Remove entries from vault — decrypt and restore originals permanently.
    pub fn remove(&self, paths: &[&str], passphrase: &str) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;
        let encryptor = self.make_encryptor(passphrase)?;
        let mut affected = 0;

        for path_str in paths {
            if let Some(idx) = manifest.entries.iter().position(|e| {
                e.original_path == *path_str || e.vault_path == *path_str
            }) {
                let entry = &manifest.entries[idx];

                match entry.protection {
                    ProtectionLevel::Locked if !entry.is_unlocked => {
                        // Decrypt first
                        let vault_path = Path::new(&entry.vault_path);
                        if vault_path.exists() {
                            let encrypted_bytes = fs::read(vault_path)?;
                            let encrypted_data = EncryptedData::from_bytes(&encrypted_bytes)?;
                            let plaintext = encryptor.decrypt(&encrypted_data, VAULT_AAD)?;
                            fs::write(&entry.original_path, &plaintext)?;
                            fs::remove_file(vault_path)?;
                        }
                    }
                    ProtectionLevel::Locked if entry.is_unlocked => {
                        // Already decrypted, just remove .vault file
                        let vault_path = Path::new(&entry.vault_path);
                        if vault_path.exists() { let _ = fs::remove_file(vault_path); }
                    }
                    ProtectionLevel::ReadOnly => {
                        // Restore write permissions
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let path = Path::new(&entry.original_path);
                            if path.exists() {
                                let perms = std::fs::Permissions::from_mode(0o644);
                                let _ = fs::set_permissions(path, perms);
                            }
                        }
                    }
                    _ => {}
                }

                manifest.entries.remove(idx);
                affected += 1;
            }
        }

        self.save_manifest_passphrase(&manifest, passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("{} file(s) removed from vault", affected),
            entries_affected: affected,
        })
    }

    /// Change vault passphrase — re-encrypts all locked files and the manifest.
    pub fn change_passphrase(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<VaultResult, VaultError> {
        let manifest = self.load_manifest(old_passphrase)?;
        let old_enc = self.make_encryptor(old_passphrase)?;
        let new_enc = self.make_encryptor(new_passphrase)?;
        let mut affected = 0;

        // Re-encrypt all locked files
        for entry in &manifest.entries {
            if entry.protection == ProtectionLevel::Locked && !entry.is_unlocked {
                let vault_path = Path::new(&entry.vault_path);
                if !vault_path.exists() { continue; }

                let encrypted_bytes = fs::read(vault_path)?;
                let encrypted_data = EncryptedData::from_bytes(&encrypted_bytes)?;
                let plaintext = old_enc.decrypt(&encrypted_data, VAULT_AAD)?;
                let new_encrypted = new_enc.encrypt(&plaintext, VAULT_AAD)?;
                fs::write(vault_path, new_encrypted.to_bytes())?;
                affected += 1;
            }
        }

        // Save manifest with new passphrase
        self.save_manifest_passphrase(&manifest, new_passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("Passphrase changed. {} encrypted file(s) re-keyed.", affected),
            entries_affected: affected,
        })
    }

    // ─── Private helpers ────────────────────────────────────────────────

    fn make_encryptor(&self, passphrase: &str) -> Result<Encryptor, VaultError> {
        let salt = fs::read(&self.salt_path)?;
        let salted = format!("{}{}", passphrase, hex_encode(&salt));
        Ok(Encryptor::new(&salted))
    }

    fn add_single_file(
        &self,
        path: &Path,
        protection: ProtectionLevel,
        encryptor: &Encryptor,
        manifest: &mut VaultManifest,
    ) -> Result<(), VaultError> {
        let path_str = path.to_string_lossy().to_string();
        let metadata = fs::metadata(path)?;
        let size = metadata.len();

        // Hash original
        let content = fs::read(path)?;
        let sha256 = sha256_hex(&content);

        let vault_path = format!("{}.vault", path_str);
        let now = chrono::Utc::now().to_rfc3339();

        match protection {
            ProtectionLevel::Locked => {
                let encrypted = encryptor.encrypt(&content, VAULT_AAD)?;
                fs::write(&vault_path, encrypted.to_bytes())?;
                secure_delete(path)?;
            }
            ProtectionLevel::ReadOnly => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o444);
                    fs::set_permissions(path, perms)?;
                }
            }
            ProtectionLevel::LocalOnly => {
                // No file modification — just add to monitoring list
            }
        }

        manifest.entries.push(VaultEntry {
            original_path: path_str,
            vault_path: if protection == ProtectionLevel::Locked { vault_path } else { String::new() },
            protection,
            encrypted_at: now,
            size_bytes: size,
            sha256_original: sha256,
            is_directory: false,
            is_unlocked: false,
        });

        Ok(())
    }

    fn add_directory(
        &self,
        dir: &Path,
        protection: ProtectionLevel,
        encryptor: &Encryptor,
        manifest: &mut VaultManifest,
    ) -> Result<usize, VaultError> {
        let mut count = 0;
        let entries = fs::read_dir(dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += self.add_directory(&path, protection, encryptor, manifest)?;
            } else if path.is_file() {
                let path_str = path.to_string_lossy().to_string();
                if manifest.entries.iter().any(|e| e.original_path == path_str) {
                    continue;
                }
                self.add_single_file(&path, protection, encryptor, manifest)?;
                count += 1;
            }
        }
        Ok(count)
    }

    fn load_manifest(&self, passphrase: &str) -> Result<VaultManifest, VaultError> {
        if !self.manifest_path.exists() {
            return Ok(VaultManifest::default());
        }

        let encryptor = self.make_encryptor(passphrase)?;
        let encrypted_bytes = fs::read(&self.manifest_path)?;
        let encrypted_data = EncryptedData::from_bytes(&encrypted_bytes)
            .map_err(|_| VaultError::ManifestCorrupted("cannot parse encrypted manifest".into()))?;

        let plaintext = encryptor.decrypt(&encrypted_data, VAULT_MANIFEST_AAD)
            .map_err(|_| VaultError::InvalidPassphrase)?;

        let json = String::from_utf8(plaintext)
            .map_err(|_| VaultError::ManifestCorrupted("invalid UTF-8".into()))?;

        serde_json::from_str(&json)
            .map_err(|e| VaultError::ManifestCorrupted(format!("JSON: {}", e)))
    }

    fn save_manifest_passphrase(&self, manifest: &VaultManifest, passphrase: &str) -> Result<(), VaultError> {
        let encryptor = self.make_encryptor(passphrase)?;
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| VaultError::ManifestCorrupted(format!("serialize: {}", e)))?;
        let encrypted = encryptor.encrypt(json.as_bytes(), VAULT_MANIFEST_AAD)?;
        fs::write(&self.manifest_path, encrypted.to_bytes())?;
        Ok(())
    }

    fn save_manifest_with_salt(&self, manifest: &VaultManifest, salt: &[u8]) -> Result<(), VaultError> {
        // Use a temporary passphrase approach — first setup uses empty string + salt
        // This gets overwritten when user sets their actual passphrase
        let salted = format!("{}{}", "", hex_encode(salt));
        let encryptor = Encryptor::new(&salted);
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| VaultError::ManifestCorrupted(format!("serialize: {}", e)))?;
        let encrypted = encryptor.encrypt(json.as_bytes(), VAULT_MANIFEST_AAD)?;
        fs::write(&self.manifest_path, encrypted.to_bytes())?;
        Ok(())
    }

    /// Set the initial passphrase (first-time setup, replaces empty passphrase).
    pub fn set_initial_passphrase(&self, passphrase: &str) -> Result<(), VaultError> {
        // Load with empty passphrase (initial state)
        let salt = fs::read(&self.salt_path)?;
        let salted_empty = format!("{}{}", "", hex_encode(&salt));
        let enc_old = Encryptor::new(&salted_empty);

        let manifest = if self.manifest_path.exists() {
            let encrypted_bytes = fs::read(&self.manifest_path)?;
            let encrypted_data = EncryptedData::from_bytes(&encrypted_bytes)?;
            let plaintext = enc_old.decrypt(&encrypted_data, VAULT_MANIFEST_AAD)?;
            let json = String::from_utf8(plaintext)
                .map_err(|_| VaultError::ManifestCorrupted("invalid UTF-8".into()))?;
            serde_json::from_str(&json)
                .map_err(|e| VaultError::ManifestCorrupted(format!("JSON: {}", e)))?
        } else {
            VaultManifest::default()
        };

        self.save_manifest_passphrase(&manifest, passphrase)?;
        Ok(())
    }

    fn write_recovery_file(&self) -> Result<(), VaultError> {
        let recovery_path = self.security_dir.join("VAULT-RECOVERY.txt");
        let content = r#"╔══════════════════════════════════════════════════════════════╗
║               AISecurity Vault — Recovery Guide              ║
╚══════════════════════════════════════════════════════════════╝

WHAT IS THE VAULT?
  AISecurity Vault encrypts your sensitive files with AES-256-GCM
  military-grade encryption. Only your vault passphrase can decrypt them.

WHERE ARE MY ENCRYPTED FILES?
  Encrypted files have the .vault extension appended to their original name.
  Example: tax-2025.pdf → tax-2025.pdf.vault

  The vault manifest is stored at:
    ~/.mac-security/vault.json.enc

HOW TO DECRYPT YOUR FILES:
  1. Open AISecurity (shield icon in menu bar)
  2. Click "Vault" → "Unlock Files..."
  3. Authenticate with Touch ID or system password
  4. Enter your vault passphrase
  5. Select files to decrypt

IF AISECURITY IS UNINSTALLED:
  Your .vault files remain on disk. To recover them:
  1. Reinstall AISecurity
  2. Your vault salt is stored at: ~/.mac-security/.vault-salt
  3. Use "Unlock Files..." with your original passphrase

IMPORTANT:
  ⚠ There is NO password reset. If you forget your vault passphrase,
    your encrypted files CANNOT be recovered.
  ⚠ Keep this file and your passphrase in a safe place.
  ⚠ The .vault-salt file in ~/.mac-security/ is required for decryption.
    Do not delete it.

SUPPORT:
  https://github.com/hchengit/AISecurity
"#;
        fs::write(recovery_path, content)?;
        Ok(())
    }
}

// ─── Utility functions ──────────────────────────────────────────────────────

/// Secure delete: overwrite with random bytes 3 times, then unlink.
fn secure_delete(path: &Path) -> Result<(), std::io::Error> {
    let size = fs::metadata(path)?.len() as usize;
    if size > 0 {
        for _ in 0..3 {
            let mut f = fs::OpenOptions::new().write(true).open(path)?;
            let mut random_bytes = vec![0u8; size];
            rand::rngs::OsRng.fill_bytes(&mut random_bytes);
            f.write_all(&random_bytes)?;
            f.sync_all()?;
        }
    }
    fs::remove_file(path)
}

fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vault_test_{}", rand::random::<u32>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn setup_creates_salt_and_manifest() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();

        assert!(dir.join(".vault-salt").exists());
        assert!(dir.join("vault.json.enc").exists());
        assert!(dir.join("VAULT-RECOVERY.txt").exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("test-pass-123").unwrap();

        // Create test file
        let test_file = dir.join("secret.txt");
        fs::write(&test_file, "my secret data").unwrap();
        let test_path = test_file.to_str().unwrap();

        // Add to vault (locked)
        let result = vault.add(&[test_path], ProtectionLevel::Locked, "test-pass-123").unwrap();
        assert_eq!(result.entries_affected, 1);
        assert!(!test_file.exists()); // original deleted
        assert!(dir.join("secret.txt.vault").exists()); // encrypted version exists

        // Unlock
        let result = vault.unlock(&[test_path], "test-pass-123").unwrap();
        assert_eq!(result.entries_affected, 1);
        assert!(test_file.exists());
        assert_eq!(fs::read_to_string(&test_file).unwrap(), "my secret data");

        // Lock again
        let result = vault.lock(&[test_path], "test-pass-123").unwrap();
        assert_eq!(result.entries_affected, 1);
        assert!(!test_file.exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("correct-pass").unwrap();

        let test_file = dir.join("data.txt");
        fs::write(&test_file, "data").unwrap();

        vault.add(&[test_file.to_str().unwrap()], ProtectionLevel::Locked, "correct-pass").unwrap();

        // Try with wrong passphrase
        let result = vault.verify_passphrase("wrong-pass");
        assert!(result.is_ok());
        assert!(!result.unwrap());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn change_passphrase_works() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("old-pass").unwrap();

        let test_file = dir.join("important.txt");
        fs::write(&test_file, "important content").unwrap();

        vault.add(&[test_file.to_str().unwrap()], ProtectionLevel::Locked, "old-pass").unwrap();

        // Change passphrase
        vault.change_passphrase("old-pass", "new-pass").unwrap();

        // Old passphrase should fail
        assert!(!vault.verify_passphrase("old-pass").unwrap());

        // New passphrase should work
        assert!(vault.verify_passphrase("new-pass").unwrap());

        // Can still unlock with new passphrase
        vault.unlock(&[test_file.to_str().unwrap()], "new-pass").unwrap();
        assert_eq!(fs::read_to_string(&test_file).unwrap(), "important content");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_only_sets_permissions() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("pass").unwrap();

        let test_file = dir.join("readonly.txt");
        fs::write(&test_file, "data").unwrap();

        vault.add(&[test_file.to_str().unwrap()], ProtectionLevel::ReadOnly, "pass").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&test_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o444);
        }

        // Remove from vault restores permissions
        vault.remove(&[test_file.to_str().unwrap()], "pass").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&test_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o644);
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn list_entries() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("pass").unwrap();

        let f1 = dir.join("a.txt");
        let f2 = dir.join("b.txt");
        fs::write(&f1, "aaa").unwrap();
        fs::write(&f2, "bbb").unwrap();

        vault.add(&[f1.to_str().unwrap(), f2.to_str().unwrap()], ProtectionLevel::Locked, "pass").unwrap();

        let entries = vault.list("pass").unwrap();
        assert_eq!(entries.len(), 2);

        fs::remove_dir_all(&dir).unwrap();
    }
}
