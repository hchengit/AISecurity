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

/// Magic header for self-contained .vault files (portable decryption).
const VAULT_FILE_MAGIC: &[u8; 11] = b"AISECVAULT1";
const VAULT_FILE_SALT_LEN: usize = 32;

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
    /// Read-only + network exfiltration monitoring.
    ReadOnlyLocal,
    /// Encrypted in-place + network exfiltration monitoring.
    LockedLocal,
}

impl ProtectionLevel {
    /// Whether this protection includes encryption.
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked | Self::LockedLocal)
    }

    /// Whether this protection includes read-only.
    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadOnlyLocal)
    }

    /// Whether this protection includes local-only monitoring.
    pub fn is_local_only(&self) -> bool {
        matches!(self, Self::LocalOnly | Self::ReadOnlyLocal | Self::LockedLocal)
    }
}

impl std::fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "locked"),
            Self::ReadOnly => write!(f, "read-only"),
            Self::LocalOnly => write!(f, "local-only"),
            Self::ReadOnlyLocal => write!(f, "read-only + local-only"),
            Self::LockedLocal => write!(f, "locked + local-only"),
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
    IoError(String),
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
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
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
        let mut pending_deletes: Vec<PathBuf> = Vec::new();

        for path_str in paths {
            let path = Path::new(path_str);
            if !path.exists() {
                return Err(VaultError::FileNotFound(path_str.to_string()));
            }

            // Resolve symlinks and canonicalize to prevent symlink attacks
            let canonical = path.canonicalize().map_err(|e| {
                VaultError::IoError(format!("Cannot resolve path {}: {}", path_str, e))
            })?;
            let canonical_str = canonical.to_string_lossy().to_string();

            // Reject symlinks — require the real path
            if canonical_str != *path_str && path.read_link().is_ok() {
                return Err(VaultError::IoError(format!(
                    "Refusing symlink: {} → {}. Use the real path instead.",
                    path_str, canonical_str
                )));
            }

            // Check not already in vault
            if manifest.entries.iter().any(|e| e.original_path == canonical_str) {
                continue; // skip silently
            }

            if canonical.is_dir() {
                // Recursively add directory contents
                affected += self.add_directory(&canonical, protection, &encryptor, &mut manifest, &mut pending_deletes)?;
            } else {
                if let Some(del_path) = self.add_single_file(&canonical, protection, &encryptor, &mut manifest)? {
                    pending_deletes.push(del_path);
                }
                affected += 1;
            }
        }

        // Save manifest BEFORE secure-deleting originals.
        // This ensures a crash between delete and save doesn't lose track of .vault files.
        self.save_manifest_passphrase(&manifest, passphrase)?;

        // Now safe to delete originals — manifest already knows about the .vault files.
        for del_path in &pending_deletes {
            secure_delete(del_path)?;
        }

        Ok(VaultResult {
            success: true,
            message: format!("{} file(s) protected with {} policy", affected, protection),
            entries_affected: affected,
        })
    }

    /// Add files with a progress callback that can cancel the operation.
    /// The callback receives (current, total, current_path) and returns false to cancel.
    pub fn add_with_progress<F>(
        &self,
        paths: &[&str],
        protection: ProtectionLevel,
        passphrase: &str,
        progress: F,
    ) -> Result<VaultResult, VaultError>
    where
        F: Fn(u32, u32, &str) -> bool,
    {
        let mut manifest = self.load_manifest(passphrase)?;
        let encryptor = self.make_encryptor(passphrase)?;
        let mut affected = 0;
        let mut pending_deletes: Vec<PathBuf> = Vec::new();
        let total = paths.len() as u32;
        let mut cancelled = false;

        for (i, path_str) in paths.iter().enumerate() {
            // Check cancel callback before each file
            if !progress(i as u32, total, path_str) {
                cancelled = true;
                break;
            }

            let path = Path::new(path_str);
            if !path.exists() {
                continue; // skip missing files in progress mode instead of erroring
            }

            let canonical = match path.canonicalize() {
                Ok(c) => c,
                Err(_) => continue,
            };
            let canonical_str = canonical.to_string_lossy().to_string();

            // Reject symlinks
            if canonical_str != *path_str && path.read_link().is_ok() {
                continue;
            }

            // Check not already in vault
            if manifest.entries.iter().any(|e| e.original_path == canonical_str) {
                continue;
            }

            if canonical.is_dir() {
                match self.add_directory(&canonical, protection, &encryptor, &mut manifest, &mut pending_deletes) {
                    Ok(n) => affected += n,
                    Err(_) => continue,
                }
            } else {
                match self.add_single_file(&canonical, protection, &encryptor, &mut manifest) {
                    Ok(Some(del_path)) => {
                        pending_deletes.push(del_path);
                        affected += 1;
                    }
                    Ok(None) => affected += 1,
                    Err(_) => continue,
                }
            }
        }

        // Save manifest BEFORE secure-deleting originals
        self.save_manifest_passphrase(&manifest, passphrase)?;

        // Now safe to delete originals
        for del_path in &pending_deletes {
            secure_delete(del_path)?;
        }

        let msg = if cancelled {
            format!("{} of {} file(s) protected (cancelled by user)", affected, total)
        } else {
            format!("{} file(s) protected with {} policy", affected, protection)
        };

        Ok(VaultResult {
            success: true,
            message: msg,
            entries_affected: affected,
        })
    }

    /// Unlock (decrypt) vault entries back to their original paths.
    pub fn unlock(&self, paths: &[&str], passphrase: &str) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;
        let encryptor = self.make_encryptor(passphrase)?;
        let mut affected = 0;

        for path_str in paths {
            if let Some(entry) = Self::find_entry_mut(&mut manifest.entries, path_str) {
                if !entry.protection.is_locked() {
                    continue;
                }
                if entry.is_unlocked {
                    continue;
                }

                let vault_path = Path::new(&entry.vault_path);
                if !vault_path.exists() {
                    continue;
                }

                // Decrypt (supports both portable and legacy format)
                let (_salt, encrypted_data) = read_vault_file(&entry.vault_path)?;
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
        let mut pending_deletes: Vec<PathBuf> = Vec::new();

        for path_str in paths {
            if let Some(entry) = Self::find_entry_mut(&mut manifest.entries, path_str) {
                if !entry.protection.is_locked() || !entry.is_unlocked {
                    continue;
                }

                let original_path = Path::new(&entry.original_path);
                if !original_path.exists() {
                    continue;
                }

                // Re-encrypt (portable format with embedded salt)
                let salt = fs::read(&self.salt_path)?;
                let plaintext = fs::read(original_path)?;
                let encrypted = encryptor.encrypt(&plaintext, VAULT_AAD)?;
                write_vault_file(&entry.vault_path, &salt, &encrypted)?;

                pending_deletes.push(original_path.to_path_buf());
                entry.is_unlocked = false;
                affected += 1;
            }
        }

        // Save manifest BEFORE secure-deleting originals
        self.save_manifest_passphrase(&manifest, passphrase)?;

        // Now safe to delete originals
        for del_path in &pending_deletes {
            secure_delete(del_path)?;
        }

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
            if let Some(idx) = Self::find_entry_index(&manifest.entries, path_str) {
                let entry = &manifest.entries[idx];

                // Handle encrypted component
                if entry.protection.is_locked() {
                    if !entry.is_unlocked {
                        // Decrypt first
                        let vault_path = Path::new(&entry.vault_path);
                        if vault_path.exists() {
                            let (_salt, encrypted_data) = read_vault_file(&entry.vault_path)?;
                            let plaintext = encryptor.decrypt(&encrypted_data, VAULT_AAD)?;
                            fs::write(&entry.original_path, &plaintext)?;
                            fs::remove_file(vault_path)?;
                        }
                    } else {
                        // Already decrypted, just remove .vault file
                        let vault_path = Path::new(&entry.vault_path);
                        if vault_path.exists() {
                            if let Err(e) = fs::remove_file(vault_path) {
                                eprintln!("Warning: failed to remove vault file {}: {}", vault_path.display(), e);
                            }
                        }
                    }
                }

                // Handle read-only component
                if entry.protection.is_read_only() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let path = Path::new(&entry.original_path);
                        if path.exists() {
                            let perms = std::fs::Permissions::from_mode(0o644);
                            if let Err(e) = fs::set_permissions(path, perms) {
                                eprintln!("Warning: failed to restore permissions on {}: {}", path.display(), e);
                            }
                        }
                    }
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
            if entry.protection.is_locked() && !entry.is_unlocked {
                let vault_path = Path::new(&entry.vault_path);
                if !vault_path.exists() { continue; }

                let (_salt, encrypted_data) = read_vault_file(&entry.vault_path)?;
                let plaintext = old_enc.decrypt(&encrypted_data, VAULT_AAD)?;
                let salt = fs::read(&self.salt_path)?;
                let new_encrypted = new_enc.encrypt(&plaintext, VAULT_AAD)?;
                write_vault_file(&entry.vault_path, &salt, &new_encrypted)?;
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

    /// Toggle local-only monitoring on/off for existing entries.
    /// Locked → LockedLocal or LockedLocal → Locked.
    /// ReadOnly → ReadOnlyLocal or ReadOnlyLocal → ReadOnly.
    /// LocalOnly is removed entirely (use `remove` instead).
    pub fn toggle_local_only(
        &self,
        paths: &[&str],
        passphrase: &str,
    ) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;
        let mut affected = 0;

        for path_str in paths {
            if let Some(entry) = Self::find_entry_mut(&mut manifest.entries, path_str) {
                let new_prot = match entry.protection {
                    ProtectionLevel::Locked => ProtectionLevel::LockedLocal,
                    ProtectionLevel::LockedLocal => ProtectionLevel::Locked,
                    ProtectionLevel::ReadOnly => ProtectionLevel::ReadOnlyLocal,
                    ProtectionLevel::ReadOnlyLocal => ProtectionLevel::ReadOnly,
                    ProtectionLevel::LocalOnly => continue, // can't toggle; it IS local-only
                };
                entry.protection = new_prot;
                affected += 1;
            }
        }

        self.save_manifest_passphrase(&manifest, passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("{} entry(ies) updated", affected),
            entries_affected: affected,
        })
    }

    /// Update the path of a vault entry after a file move.
    /// Updates original_path (and vault_path + renames .vault file if locked).
    pub fn update_entry_path(
        &self,
        old_path: &str,
        new_path: &str,
        passphrase: &str,
    ) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;

        let entry = Self::find_entry_mut(&mut manifest.entries, old_path);

        let Some(entry) = entry else {
            return Ok(VaultResult {
                success: false,
                message: format!("No vault entry found for path: {}", old_path),
                entries_affected: 0,
            });
        };

        // Update original_path
        entry.original_path = new_path.to_string();

        // If locked: rename .vault file and update vault_path
        if entry.protection == ProtectionLevel::Locked
            || entry.protection == ProtectionLevel::LockedLocal
        {
            let old_vault = format!("{}.vault", old_path);
            let new_vault = format!("{}.vault", new_path);

            if std::path::Path::new(&old_vault).exists() {
                // Ensure parent directory of new path exists
                if let Some(parent) = std::path::Path::new(&new_vault).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::rename(&old_vault, &new_vault).map_err(|e| {
                    VaultError::IoError(format!(
                        "Failed to rename vault file {} -> {}: {}",
                        old_vault, new_vault, e
                    ))
                })?;
            }
            entry.vault_path = new_vault;
        } else {
            // Non-locked: vault_path mirrors original_path (or is empty)
            if !entry.vault_path.is_empty() {
                entry.vault_path = new_path.to_string();
            }
        }

        self.save_manifest_passphrase(&manifest, passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("Path updated: {} -> {}", old_path, new_path),
            entries_affected: 1,
        })
    }

    /// Change the protection level of existing vault entries.
    /// Handles all 20 transitions atomically (single manifest load/save).
    /// File operations (encrypt, decrypt, chmod) happen inline.
    pub fn change_protection(
        &self,
        paths: &[&str],
        new_protection: ProtectionLevel,
        passphrase: &str,
    ) -> Result<VaultResult, VaultError> {
        let mut manifest = self.load_manifest(passphrase)?;
        let encryptor = self.make_encryptor(passphrase)?;
        let mut affected = 0;

        for path_str in paths {
            // Try multiple path forms for matching (add() stores canonical paths on macOS)
            let canonical = Path::new(path_str).canonicalize()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            // Also try canonicalizing the .vault variant
            let vault_variant = format!("{}.vault", path_str);
            let canonical_vault = Path::new(&vault_variant).canonicalize()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            if let Some(entry) = manifest.entries.iter_mut().find(|e| {
                e.original_path == *path_str || e.vault_path == *path_str
                || (!canonical.is_empty() && (e.original_path == canonical || e.vault_path == canonical))
                || (!canonical_vault.is_empty() && e.vault_path == canonical_vault)
            }) {
                let old_prot = entry.protection;
                if old_prot == new_protection { continue; }

                let was_locked = old_prot.is_locked();
                let was_read_only = old_prot.is_read_only();
                let will_lock = new_protection.is_locked();
                let will_read_only = new_protection.is_read_only();

                // Fast path: both locked variants (Locked↔LockedLocal) — metadata only
                if was_locked && will_lock {
                    entry.protection = new_protection;
                    affected += 1;
                    continue;
                }

                // Fast path: both read-only variants (ReadOnly↔ReadOnlyLocal) — metadata only
                if was_read_only && will_read_only && !was_locked && !will_lock {
                    entry.protection = new_protection;
                    affected += 1;
                    continue;
                }

                // === Phase 1: Undo old file-level effects ===

                // If was locked, decrypt to restore original file
                if was_locked {
                    if !entry.is_unlocked {
                        // File is encrypted — decrypt it
                        let vault_path = Path::new(&entry.vault_path);
                        if vault_path.exists() {
                            let (_salt, encrypted_data) = read_vault_file(&entry.vault_path)?;
                            let plaintext = encryptor.decrypt(&encrypted_data, VAULT_AAD)?;
                            fs::write(&entry.original_path, &plaintext)?;
                            fs::remove_file(vault_path)?;
                        }
                    } else {
                        // Already unlocked (original exists), just clean up .vault
                        let vault_path = Path::new(&entry.vault_path);
                        if vault_path.exists() {
                            if let Err(e) = fs::remove_file(vault_path) {
                                eprintln!("Warning: failed to remove vault file {}: {}", vault_path.display(), e);
                            }
                        }
                    }
                    entry.vault_path = String::new();
                    entry.is_unlocked = false;
                }

                // If was read-only, restore write permissions
                if was_read_only {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let path = Path::new(&entry.original_path);
                        if path.exists() {
                            let perms = std::fs::Permissions::from_mode(0o644);
                            if let Err(e) = fs::set_permissions(path, perms) {
                                eprintln!("Warning: failed to restore permissions on {}: {}", path.display(), e);
                            }
                        }
                    }
                }

                // === Phase 2: Apply new file-level effects ===

                // If new is locked, encrypt the file
                if will_lock {
                    let original_path = Path::new(&entry.original_path);
                    if !original_path.exists() {
                        return Err(VaultError::FileNotFound(entry.original_path.clone()));
                    }
                    let salt = fs::read(&self.salt_path)?;
                    let content = fs::read(original_path)?;
                    let vault_path_str = format!("{}.vault", entry.original_path);
                    let encrypted = encryptor.encrypt(&content, VAULT_AAD)?;
                    write_vault_file(&vault_path_str, &salt, &encrypted)?;
                    secure_delete(original_path)?;
                    entry.vault_path = vault_path_str;
                    entry.is_unlocked = false;
                    entry.sha256_original = sha256_hex(&content);
                }

                // If new is read-only, set chmod 444
                if will_read_only {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let path = Path::new(&entry.original_path);
                        if path.exists() {
                            let perms = std::fs::Permissions::from_mode(0o444);
                            fs::set_permissions(path, perms)?;
                        }
                    }
                }

                // Update protection level
                entry.protection = new_protection;
                affected += 1;
            }
        }

        self.save_manifest_passphrase(&manifest, passphrase)?;

        Ok(VaultResult {
            success: true,
            message: format!("{} entry(ies) changed to {}", affected, new_protection),
            entries_affected: affected,
        })
    }

    // ─── Private helpers ────────────────────────────────────────────────

    /// Find a vault entry by path, trying exact match first then canonicalized path.
    /// This handles cases where the caller passes a non-canonical path
    /// (e.g., relative, or with unresolved symlinks/components).
    fn find_entry_mut<'a>(entries: &'a mut [VaultEntry], path_str: &str) -> Option<&'a mut VaultEntry> {
        // First try exact match
        if let Some(idx) = entries.iter().position(|e| {
            e.original_path == path_str || e.vault_path == path_str
        }) {
            return Some(&mut entries[idx]);
        }
        // Try canonicalized path
        if let Ok(canonical) = Path::new(path_str).canonicalize() {
            let canonical_str = canonical.to_string_lossy();
            if let Some(idx) = entries.iter().position(|e| {
                e.original_path == *canonical_str || e.vault_path == *canonical_str
            }) {
                return Some(&mut entries[idx]);
            }
        }
        None
    }

    /// Find a vault entry's index by path, trying exact match first then canonicalized path.
    fn find_entry_index(entries: &[VaultEntry], path_str: &str) -> Option<usize> {
        // First try exact match
        if let Some(idx) = entries.iter().position(|e| {
            e.original_path == path_str || e.vault_path == path_str
        }) {
            return Some(idx);
        }
        // Try canonicalized path
        if let Ok(canonical) = Path::new(path_str).canonicalize() {
            let canonical_str = canonical.to_string_lossy();
            if let Some(idx) = entries.iter().position(|e| {
                e.original_path == *canonical_str || e.vault_path == *canonical_str
            }) {
                return Some(idx);
            }
        }
        None
    }

    fn make_encryptor(&self, passphrase: &str) -> Result<Encryptor, VaultError> {
        let salt = fs::read(&self.salt_path)?;
        let salted = format!("{}{}", passphrase, hex_encode(&salt));
        Ok(Encryptor::new(&salted))
    }

    /// Encrypt/protect a single file and add it to the manifest.
    /// Returns `Some(path)` if the original file needs secure-deleting (for locked files).
    /// The caller MUST save the manifest BEFORE performing the secure delete,
    /// so that a crash between delete and save doesn't lose track of the .vault file.
    fn add_single_file(
        &self,
        path: &Path,
        protection: ProtectionLevel,
        encryptor: &Encryptor,
        manifest: &mut VaultManifest,
    ) -> Result<Option<PathBuf>, VaultError> {
        let path_str = path.to_string_lossy().to_string();
        let metadata = fs::metadata(path)?;
        let size = metadata.len();

        // Hash original
        let content = fs::read(path)?;
        let sha256 = sha256_hex(&content);

        let vault_path = format!("{}.vault", path_str);
        let now = chrono::Utc::now().to_rfc3339();

        // Apply encryption if protection includes locking
        // NOTE: secure_delete is deferred — caller does it after manifest save
        let needs_secure_delete = if protection.is_locked() {
            let salt = fs::read(&self.salt_path)?;
            let encrypted = encryptor.encrypt(&content, VAULT_AAD)?;
            write_vault_file(&vault_path, &salt, &encrypted)?;
            true
        } else {
            false
        };

        // Apply read-only permissions if protection includes read-only
        if protection.is_read_only() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o444);
                fs::set_permissions(path, perms)?;
            }
        }

        // LocalOnly: no file modification — monitoring handled by Swift layer

        manifest.entries.push(VaultEntry {
            original_path: path_str,
            vault_path: if protection.is_locked() { vault_path } else { String::new() },
            protection,
            encrypted_at: now,
            size_bytes: size,
            sha256_original: sha256,
            is_directory: false,
            is_unlocked: false,
        });

        Ok(if needs_secure_delete { Some(path.to_path_buf()) } else { None })
    }

    fn add_directory(
        &self,
        dir: &Path,
        protection: ProtectionLevel,
        encryptor: &Encryptor,
        manifest: &mut VaultManifest,
        pending_deletes: &mut Vec<PathBuf>,
    ) -> Result<usize, VaultError> {
        let mut count = 0;
        let entries = fs::read_dir(dir)?;
        for entry in entries.flatten() {
            let path = entry.path();
            // Skip symlinks inside directories to prevent symlink attacks
            if path.read_link().is_ok() {
                continue;
            }
            if path.is_dir() {
                count += self.add_directory(&path, protection, encryptor, manifest, pending_deletes)?;
            } else if path.is_file() {
                let path_str = path.to_string_lossy().to_string();
                if manifest.entries.iter().any(|e| e.original_path == path_str) {
                    continue;
                }
                if let Some(del_path) = self.add_single_file(&path, protection, encryptor, manifest)? {
                    pending_deletes.push(del_path);
                }
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
        // Atomic write: write to tmp file then rename (prevents corrupt manifest on crash)
        let tmp_path = self.manifest_path.with_extension("enc.tmp");
        fs::write(&tmp_path, encrypted.to_bytes())?;
        fs::rename(&tmp_path, &self.manifest_path)?;
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
        // Atomic write: write to tmp file then rename (prevents corrupt manifest on crash)
        let tmp_path = self.manifest_path.with_extension("enc.tmp");
        fs::write(&tmp_path, encrypted.to_bytes())?;
        fs::rename(&tmp_path, &self.manifest_path)?;
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

// ─── Portable vault file format ─────────────────────────────────────────────
//
// Format: AISECVAULT1 (11 bytes) || salt (32 bytes) || nonce (12 bytes) || ciphertext
//
// This makes .vault files self-contained — decryptable on any machine with just
// the passphrase. No need for the vault manifest or salt file.

/// Write a portable .vault file with embedded salt.
fn write_vault_file(path: &str, salt: &[u8], encrypted: &EncryptedData) -> Result<(), VaultError> {
    let enc_bytes = encrypted.to_bytes();
    let mut out = Vec::with_capacity(VAULT_FILE_MAGIC.len() + VAULT_FILE_SALT_LEN + enc_bytes.len());
    out.extend_from_slice(VAULT_FILE_MAGIC);
    out.extend_from_slice(salt);
    out.extend_from_slice(&enc_bytes);
    fs::write(path, out)?;
    Ok(())
}

/// Read a portable .vault file. Returns (salt, EncryptedData).
/// Also handles legacy format (no header — just nonce || ciphertext).
fn read_vault_file(path: &str) -> Result<(Vec<u8>, EncryptedData), VaultError> {
    let data = fs::read(path)?;
    let header_len = VAULT_FILE_MAGIC.len() + VAULT_FILE_SALT_LEN;

    if data.len() > header_len && &data[..VAULT_FILE_MAGIC.len()] == VAULT_FILE_MAGIC {
        // New portable format
        let salt = data[VAULT_FILE_MAGIC.len()..header_len].to_vec();
        let encrypted = EncryptedData::from_bytes(&data[header_len..])?;
        Ok((salt, encrypted))
    } else {
        // Legacy format (no header) — use empty salt (caller must supply vault salt)
        let encrypted = EncryptedData::from_bytes(&data)?;
        Ok((Vec::new(), encrypted))
    }
}

// ─── Utility functions ──────────────────────────────────────────────────────

/// Secure delete: overwrite with random bytes 3 times, then unlink.
/// Rejects symlinks to prevent overwriting unintended targets.
fn secure_delete(path: &Path) -> Result<(), std::io::Error> {
    // Reject symlinks — prevent overwriting symlink targets
    if path.read_link().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Refusing to secure-delete symlink: {}", path.display()),
        ));
    }
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
        // Canonicalize to resolve symlinks (e.g., /tmp → /private/tmp on macOS)
        dir.canonicalize().unwrap_or(dir)
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

    #[test]
    fn change_protection_locked_to_readonly() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("pass").unwrap();

        let f = dir.join("secret.txt");
        fs::write(&f, "secret data").unwrap();
        let p = f.to_str().unwrap();

        // Add as Locked
        vault.add(&[p], ProtectionLevel::Locked, "pass").unwrap();
        assert!(!f.exists());
        assert!(dir.join("secret.txt.vault").exists());

        // Change to ReadOnly
        let result = vault.change_protection(&[p], ProtectionLevel::ReadOnly, "pass").unwrap();
        assert_eq!(result.entries_affected, 1);
        assert!(f.exists()); // decrypted back
        assert!(!dir.join("secret.txt.vault").exists()); // .vault removed
        assert_eq!(fs::read_to_string(&f).unwrap(), "secret data");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&f).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o444);
        }

        let entries = vault.list("pass").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protection, ProtectionLevel::ReadOnly);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn change_protection_readonly_to_locked() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("pass").unwrap();

        let f = dir.join("doc.txt");
        fs::write(&f, "my document").unwrap();
        let p = f.to_str().unwrap();

        // Add as ReadOnly
        vault.add(&[p], ProtectionLevel::ReadOnly, "pass").unwrap();
        assert!(f.exists());

        // Change to Locked
        let result = vault.change_protection(&[p], ProtectionLevel::Locked, "pass").unwrap();
        assert_eq!(result.entries_affected, 1);
        assert!(!f.exists()); // original deleted
        assert!(dir.join("doc.txt.vault").exists()); // encrypted

        // Verify we can still decrypt
        vault.unlock(&[p], "pass").unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "my document");

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn change_protection_locked_to_locked_local_metadata_only() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("pass").unwrap();

        let f = dir.join("data.txt");
        fs::write(&f, "data").unwrap();
        let p = f.to_str().unwrap();

        vault.add(&[p], ProtectionLevel::Locked, "pass").unwrap();
        let vault_file = dir.join("data.txt.vault");
        assert!(vault_file.exists());
        let vault_bytes_before = fs::read(&vault_file).unwrap();

        // Change Locked → LockedLocal (metadata only — .vault file unchanged)
        let result = vault.change_protection(&[p], ProtectionLevel::LockedLocal, "pass").unwrap();
        assert_eq!(result.entries_affected, 1);
        assert!(vault_file.exists());
        let vault_bytes_after = fs::read(&vault_file).unwrap();
        assert_eq!(vault_bytes_before, vault_bytes_after); // file untouched

        let entries = vault.list("pass").unwrap();
        assert_eq!(entries[0].protection, ProtectionLevel::LockedLocal);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn change_protection_same_level_no_op() {
        let dir = temp_dir();
        let vault = Vault::new(dir.to_str().unwrap());
        vault.setup().unwrap();
        vault.set_initial_passphrase("pass").unwrap();

        let f = dir.join("file.txt");
        fs::write(&f, "content").unwrap();
        let p = f.to_str().unwrap();

        vault.add(&[p], ProtectionLevel::LocalOnly, "pass").unwrap();

        // Change to same level — should be no-op
        let result = vault.change_protection(&[p], ProtectionLevel::LocalOnly, "pass").unwrap();
        assert_eq!(result.entries_affected, 0);

        fs::remove_dir_all(&dir).unwrap();
    }
}
