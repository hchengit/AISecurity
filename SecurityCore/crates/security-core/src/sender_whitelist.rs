use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Source of the whitelist entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntrySource {
    #[serde(rename = "user")]
    UserExplicit,
    #[serde(rename = "contacts")]
    ContactsSync,
}

/// A whitelist entry — exact address or @domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub address: String,
    pub source: EntrySource,
    #[serde(rename = "addedAt")]
    pub added_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Scan policy for a sender based on whitelist status.
#[derive(Debug, Clone)]
pub struct ScanPolicy {
    pub is_whitelisted: bool,
}

/// Categories that should ALWAYS fire regardless of whitelist.
pub const ALWAYS_SCAN_CATEGORIES: &[&str] = &[
    "malicious_url",
    "dangerous_attachment",
    "malware_dropper",
    "prompt_injection",
    "crypto_scam",
];

/// Categories suppressed for whitelisted senders.
pub const SUPPRESSED_CATEGORIES: &[&str] = &[
    "social_engineering",
    "authority_impersonation",
];

/// Categories with raised threshold for whitelisted senders.
pub const REDUCED_CATEGORIES: &[&str] = &[
    "phishing",
    "sensitive_data_request",
];

impl ScanPolicy {
    /// Should this threat category fire for this sender?
    pub fn should_alert(&self, category: &str, intent_layers: u8) -> bool {
        // Always-scan categories fire regardless
        if ALWAYS_SCAN_CATEGORIES.contains(&category) {
            return true;
        }

        // Unknown senders — everything fires
        if !self.is_whitelisted {
            return true;
        }

        // Whitelisted: suppress social engineering / authority impersonation
        if SUPPRESSED_CATEGORIES.contains(&category) {
            return false;
        }

        // Whitelisted: raise threshold for reduced categories (need 5+ layers)
        if REDUCED_CATEGORIES.contains(&category) {
            return intent_layers >= 5;
        }

        // All other categories: fire normally
        true
    }
}

/// Freemail domains that cannot be whitelisted at domain level.
pub const FREEMAIL_DOMAINS: &[&str] = &[
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com",
    "protonmail.com", "proton.me", "zoho.com", "mail.com", "gmx.com", "yandex.com",
];

/// In-memory sender whitelist with JSON persistence.
pub struct SenderWhitelist {
    entries: HashMap<String, WhitelistEntry>,
    file_path: String,
}

impl SenderWhitelist {
    /// Create a new whitelist, loading from disk if the file exists.
    pub fn new(security_dir: &str) -> Self {
        let file_path = format!("{}/whitelist.json", security_dir);
        let mut wl = SenderWhitelist {
            entries: HashMap::new(),
            file_path,
        };
        wl.load();
        wl
    }

    /// Create from a specific file path.
    pub fn from_path(file_path: &str) -> Self {
        let mut wl = SenderWhitelist {
            entries: HashMap::new(),
            file_path: file_path.to_string(),
        };
        wl.load();
        wl
    }

    /// Check the scan policy for a sender.
    pub fn policy(&self, sender: &str) -> ScanPolicy {
        let addr = extract_address(sender).to_lowercase();

        // Check exact address match
        if self.entries.contains_key(&addr) {
            return ScanPolicy { is_whitelisted: true };
        }

        // Check domain match
        if let Some(at_idx) = addr.find('@') {
            let domain_key = format!("@{}", &addr[at_idx + 1..]);
            if self.entries.contains_key(&domain_key) {
                return ScanPolicy { is_whitelisted: true };
            }
        }

        ScanPolicy { is_whitelisted: false }
    }

    /// Add a sender to the whitelist. Returns false if blocked (empty or freemail domain).
    pub fn add(
        &mut self,
        sender: &str,
        source: EntrySource,
        note: Option<&str>,
    ) -> bool {
        let addr = extract_address(sender).to_lowercase();
        if addr.is_empty() {
            return false;
        }

        // Block domain-level whitelist for freemail providers
        if let Some(domain) = addr.strip_prefix('@') {
            if FREEMAIL_DOMAINS.contains(&domain) {
                return false;
            }
        }

        let entry = WhitelistEntry {
            address: addr.clone(),
            source,
            added_at: chrono::Utc::now().to_rfc3339(),
            note: note.map(|s| s.to_string()),
        };

        self.entries.insert(addr, entry);
        self.save();
        true
    }

    /// Remove a sender from the whitelist.
    pub fn remove(&mut self, sender: &str) {
        let addr = extract_address(sender).to_lowercase();
        self.entries.remove(&addr);
        self.save();
    }

    /// Get all whitelist entries sorted by added_at descending.
    pub fn all_entries(&self) -> Vec<&WhitelistEntry> {
        let mut entries: Vec<_> = self.entries.values().collect();
        entries.sort_by(|a, b| b.added_at.cmp(&a.added_at));
        entries
    }

    /// Check if a sender is whitelisted.
    pub fn is_whitelisted(&self, sender: &str) -> bool {
        self.policy(sender).is_whitelisted
    }

    // -- Persistence --

    fn load(&mut self) {
        let data = match std::fs::read_to_string(&self.file_path) {
            Ok(d) => d,
            Err(_) => return,
        };
        let arr: Vec<WhitelistEntry> = match serde_json::from_str(&data) {
            Ok(a) => a,
            Err(_) => return,
        };
        for entry in arr {
            self.entries.insert(entry.address.to_lowercase(), entry);
        }
    }

    fn save(&self) {
        let arr: Vec<&WhitelistEntry> = self.entries.values().collect();
        if let Ok(data) = serde_json::to_string_pretty(&arr) {
            let _ = std::fs::write(&self.file_path, data);
        }
    }
}

/// Extract bare email address from "Name <email@example.com>" format.
fn extract_address(sender: &str) -> String {
    if let Some(start) = sender.find('<') {
        if let Some(end) = sender.find('>') {
            if start < end {
                return sender[start + 1..end].to_string();
            }
        }
    }
    sender.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_whitelist() -> SenderWhitelist {
        // Use a non-existent path so no file is loaded
        SenderWhitelist {
            entries: HashMap::new(),
            file_path: "/tmp/test_whitelist_nonexistent.json".to_string(),
        }
    }

    #[test]
    fn unknown_sender_not_whitelisted() {
        let wl = make_whitelist();
        let policy = wl.policy("unknown@evil.com");
        assert!(!policy.is_whitelisted);
    }

    #[test]
    fn add_and_check_exact() {
        let mut wl = make_whitelist();
        assert!(wl.add("friend@example.com", EntrySource::UserExplicit, None));
        assert!(wl.is_whitelisted("friend@example.com"));
        assert!(!wl.is_whitelisted("stranger@example.com"));
    }

    #[test]
    fn add_and_check_domain() {
        let mut wl = make_whitelist();
        assert!(wl.add("@company.com", EntrySource::UserExplicit, Some("Work")));
        assert!(wl.is_whitelisted("anyone@company.com"));
        assert!(!wl.is_whitelisted("other@evil.com"));
    }

    #[test]
    fn block_freemail_domain() {
        let mut wl = make_whitelist();
        assert!(!wl.add("@gmail.com", EntrySource::UserExplicit, None));
        assert!(!wl.is_whitelisted("anyone@gmail.com"));
    }

    #[test]
    fn allow_freemail_exact_address() {
        let mut wl = make_whitelist();
        assert!(wl.add("friend@gmail.com", EntrySource::UserExplicit, None));
        assert!(wl.is_whitelisted("friend@gmail.com"));
        assert!(!wl.is_whitelisted("other@gmail.com"));
    }

    #[test]
    fn extract_from_angle_brackets() {
        let addr = extract_address("John Doe <john@example.com>");
        assert_eq!(addr, "john@example.com");
    }

    #[test]
    fn extract_bare_address() {
        let addr = extract_address("john@example.com");
        assert_eq!(addr, "john@example.com");
    }

    #[test]
    fn remove_entry() {
        let mut wl = make_whitelist();
        wl.add("test@example.com", EntrySource::UserExplicit, None);
        assert!(wl.is_whitelisted("test@example.com"));
        wl.remove("test@example.com");
        assert!(!wl.is_whitelisted("test@example.com"));
    }

    #[test]
    fn policy_always_scan_fires() {
        let policy = ScanPolicy { is_whitelisted: true };
        assert!(policy.should_alert("malicious_url", 0));
        assert!(policy.should_alert("dangerous_attachment", 0));
        assert!(policy.should_alert("crypto_scam", 0));
    }

    #[test]
    fn policy_suppresses_social_engineering() {
        let policy = ScanPolicy { is_whitelisted: true };
        assert!(!policy.should_alert("social_engineering", 3));
        assert!(!policy.should_alert("authority_impersonation", 3));
    }

    #[test]
    fn policy_reduced_needs_five_layers() {
        let policy = ScanPolicy { is_whitelisted: true };
        assert!(!policy.should_alert("phishing", 4));
        assert!(policy.should_alert("phishing", 5));
        assert!(!policy.should_alert("sensitive_data_request", 3));
        assert!(policy.should_alert("sensitive_data_request", 5));
    }

    #[test]
    fn policy_unknown_sender_fires_all() {
        let policy = ScanPolicy { is_whitelisted: false };
        assert!(policy.should_alert("social_engineering", 0));
        assert!(policy.should_alert("phishing", 1));
        assert!(policy.should_alert("authority_impersonation", 0));
    }

    #[test]
    fn case_insensitive() {
        let mut wl = make_whitelist();
        wl.add("Test@Example.COM", EntrySource::UserExplicit, None);
        assert!(wl.is_whitelisted("test@example.com"));
        assert!(wl.is_whitelisted("TEST@EXAMPLE.COM"));
    }
}
