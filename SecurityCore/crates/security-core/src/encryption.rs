//! AES-256-GCM encryption for sensitive data at rest.
//!
//! Encrypts: whitelist.json, sensitive config fields, alert log previews.
//! Key derivation: SHA-256 of user passphrase (matching ElizaOS pattern).
//! AAD (Additional Authenticated Data) tags ensure integrity and context binding.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;

/// AAD tags for different encryption contexts — prevents ciphertext reuse across contexts.
pub mod aad {
    pub const CONFIG: &[u8] = b"securitycore:config:v1";
    pub const WHITELIST: &[u8] = b"securitycore:whitelist:v1";
    pub const ALERT_LOG: &[u8] = b"securitycore:alertlog:v1";
    pub const GENERAL: &[u8] = b"securitycore:general:v1";
    pub const MODEL_MANIFEST: &[u8] = b"securitycore:models:v1";
    pub const POLICY_AUDIT: &[u8] = b"securitycore:policyaudit:v1";
}

/// Default passphrase — must be overridden in production.
const DEFAULT_PASSPHRASE: &str = "securitycore-default-passphrase-CHANGE-ME";

/// Encrypted payload: 12-byte nonce || ciphertext (includes 16-byte GCM tag).
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Serialize to bytes: nonce || ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserialize from bytes: first 12 bytes = nonce, rest = ciphertext.
    pub fn from_bytes(data: &[u8]) -> Result<Self, EncryptionError> {
        if data.len() < 12 + 16 {
            // Need at least nonce (12) + GCM tag (16)
            return Err(EncryptionError::InvalidData(
                "Data too short for nonce + GCM tag".into(),
            ));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[..12]);
        let ciphertext = data[12..].to_vec();
        Ok(Self { nonce, ciphertext })
    }

    /// Encode to base64 for JSON/TOML storage.
    pub fn to_base64(&self) -> String {
        use std::fmt::Write;
        let bytes = self.to_bytes();
        let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
        for chunk in bytes.chunks(3) {
            for &b in chunk {
                write!(out, "{:02x}", b).unwrap();
            }
        }
        // Use hex encoding for simplicity (no base64 dep needed)
        out
    }

    /// Decode from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, EncryptionError> {
        let bytes = hex_decode(hex)?;
        Self::from_bytes(&bytes)
    }
}

/// Encryption errors.
#[derive(Debug)]
pub enum EncryptionError {
    InvalidData(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    DefaultPassphrase,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            Self::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            Self::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            Self::DefaultPassphrase => write!(
                f,
                "Default passphrase in production — set SECURITYCORE_PASSPHRASE"
            ),
        }
    }
}

impl std::error::Error for EncryptionError {}

/// AES-256-GCM encryption engine.
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for Encryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encryptor")
            .field("cipher", &"Aes256Gcm { ... }")
            .finish()
    }
}

impl Encryptor {
    /// Create from a passphrase. Key = SHA-256(passphrase).
    pub fn new(passphrase: &str) -> Self {
        let key = derive_key(passphrase);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256-GCM key init");
        Self { cipher }
    }

    /// Create from environment variable, falling back to default.
    /// In production mode, returns Err if using the default passphrase.
    pub fn from_env(enforce_production: bool) -> Result<Self, EncryptionError> {
        let passphrase = std::env::var("SECURITYCORE_PASSPHRASE")
            .unwrap_or_else(|_| DEFAULT_PASSPHRASE.to_string());

        if enforce_production && passphrase == DEFAULT_PASSPHRASE {
            return Err(EncryptionError::DefaultPassphrase);
        }

        Ok(Self::new(&passphrase))
    }

    /// Encrypt plaintext with AAD context binding.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData, EncryptionError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|e| EncryptionError::EncryptionFailed(format!("{}", e)))?;

        Ok(EncryptedData {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt ciphertext with AAD context verification.
    pub fn decrypt(
        &self,
        encrypted: &EncryptedData,
        aad: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let payload = aes_gcm::aead::Payload {
            msg: encrypted.ciphertext.as_ref(),
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("{}", e)))
    }

    /// Encrypt a string, return hex-encoded result.
    pub fn encrypt_string(&self, plaintext: &str, aad: &[u8]) -> Result<String, EncryptionError> {
        let encrypted = self.encrypt(plaintext.as_bytes(), aad)?;
        Ok(encrypted.to_base64())
    }

    /// Decrypt a hex-encoded string.
    pub fn decrypt_string(&self, hex: &str, aad: &[u8]) -> Result<String, EncryptionError> {
        let encrypted = EncryptedData::from_hex(hex)?;
        let plaintext = self.decrypt(&encrypted, aad)?;
        String::from_utf8(plaintext)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("Invalid UTF-8: {}", e)))
    }

    /// Encrypt a JSON-serializable value.
    pub fn encrypt_json<T: serde::Serialize>(
        &self,
        value: &T,
        aad: &[u8],
    ) -> Result<String, EncryptionError> {
        let json = serde_json::to_string(value)
            .map_err(|e| EncryptionError::EncryptionFailed(format!("JSON serialize: {}", e)))?;
        self.encrypt_string(&json, aad)
    }

    /// Decrypt to a JSON-deserializable value.
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        hex: &str,
        aad: &[u8],
    ) -> Result<T, EncryptionError> {
        let json = self.decrypt_string(hex, aad)?;
        serde_json::from_str(&json)
            .map_err(|e| EncryptionError::DecryptionFailed(format!("JSON deserialize: {}", e)))
    }
}

/// PBKDF2 iteration count — 100,000 iterations per OWASP recommendation.
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Fixed salt for PBKDF2 key derivation (vault operations add their own per-vault salt on top).
/// This prevents rainbow table attacks on the passphrase-to-key derivation step.
const PBKDF2_SALT: &[u8] = b"securitycore:pbkdf2:v1:salt";

/// Derive a 256-bit key from a passphrase via PBKDF2-HMAC-SHA256 (100k iterations).
/// Replaces single-pass SHA-256 to resist brute-force attacks.
fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        passphrase.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        &mut key,
    ).expect("PBKDF2 key derivation");
    key
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, EncryptionError> {
    if !hex.len().is_multiple_of(2) {
        return Err(EncryptionError::InvalidData("Odd hex length".into()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| EncryptionError::InvalidData("Invalid hex".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let enc = Encryptor::new("test-passphrase-2024");
        let plaintext = b"Hello, AES-256-GCM encryption!";

        let encrypted = enc.encrypt(plaintext, aad::GENERAL).unwrap();
        let decrypted = enc.decrypt(&encrypted, aad::GENERAL).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn string_roundtrip() {
        let enc = Encryptor::new("my-secure-passphrase");
        let original = "Sensitive whitelist data: friend@example.com";

        let hex = enc.encrypt_string(original, aad::WHITELIST).unwrap();
        let decrypted = enc.decrypt_string(&hex, aad::WHITELIST).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn json_roundtrip() {
        let enc = Encryptor::new("json-test-key");

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct TestData {
            name: String,
            count: u32,
        }

        let original = TestData {
            name: "test".to_string(),
            count: 42,
        };

        let hex = enc.encrypt_json(&original, aad::CONFIG).unwrap();
        let decrypted: TestData = enc.decrypt_json(&hex, aad::CONFIG).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let enc1 = Encryptor::new("correct-passphrase");
        let enc2 = Encryptor::new("wrong-passphrase");

        let encrypted = enc1.encrypt(b"secret data", aad::GENERAL).unwrap();
        let result = enc2.decrypt(&encrypted, aad::GENERAL);

        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let enc = Encryptor::new("test-passphrase");

        let encrypted = enc.encrypt(b"secret", aad::CONFIG).unwrap();
        let result = enc.decrypt(&encrypted, aad::WHITELIST); // wrong AAD

        assert!(result.is_err());
    }

    #[test]
    fn different_nonces_produce_different_ciphertext() {
        let enc = Encryptor::new("test-passphrase");
        let plaintext = b"same data";

        let e1 = enc.encrypt(plaintext, aad::GENERAL).unwrap();
        let e2 = enc.encrypt(plaintext, aad::GENERAL).unwrap();

        // Same plaintext, different nonces → different ciphertext
        assert_ne!(e1.ciphertext, e2.ciphertext);
        assert_ne!(e1.nonce, e2.nonce);

        // Both decrypt correctly
        assert_eq!(
            enc.decrypt(&e1, aad::GENERAL).unwrap(),
            enc.decrypt(&e2, aad::GENERAL).unwrap()
        );
    }

    #[test]
    fn serialization_roundtrip() {
        let enc = Encryptor::new("serialize-test");
        let plaintext = b"data to serialize";

        let encrypted = enc.encrypt(plaintext, aad::GENERAL).unwrap();
        let bytes = encrypted.to_bytes();
        let restored = EncryptedData::from_bytes(&bytes).unwrap();

        assert_eq!(encrypted.nonce, restored.nonce);
        assert_eq!(encrypted.ciphertext, restored.ciphertext);

        let decrypted = enc.decrypt(&restored, aad::GENERAL).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn hex_roundtrip() {
        let enc = Encryptor::new("hex-test");
        let original = "hex encoding test data";

        let hex = enc.encrypt_string(original, aad::GENERAL).unwrap();
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        let decrypted = enc.decrypt_string(&hex, aad::GENERAL).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn empty_plaintext() {
        let enc = Encryptor::new("empty-test");

        let encrypted = enc.encrypt(b"", aad::GENERAL).unwrap();
        let decrypted = enc.decrypt(&encrypted, aad::GENERAL).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_plaintext() {
        let enc = Encryptor::new("large-test");
        let plaintext = "A".repeat(1_000_000); // 1 MB

        let encrypted = enc
            .encrypt(plaintext.as_bytes(), aad::ALERT_LOG)
            .unwrap();
        let decrypted = enc.decrypt(&encrypted, aad::ALERT_LOG).unwrap();

        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn default_passphrase_blocked_in_production() {
        // Temporarily set env to default
        std::env::remove_var("SECURITYCORE_PASSPHRASE");
        let result = Encryptor::from_env(true);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::DefaultPassphrase
        ));
    }

    #[test]
    fn from_env_works_with_custom_passphrase() {
        std::env::set_var("SECURITYCORE_PASSPHRASE", "my-custom-key-123");
        let enc = Encryptor::from_env(true).unwrap();
        let encrypted = enc.encrypt(b"works", aad::GENERAL).unwrap();
        let decrypted = enc.decrypt(&encrypted, aad::GENERAL).unwrap();
        assert_eq!(decrypted, b"works");
        std::env::remove_var("SECURITYCORE_PASSPHRASE");
    }
}
