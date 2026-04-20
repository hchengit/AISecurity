//! Model vetting — checks SHA-256 hashes of installed models against two
//! lists:
//!
//!   - **Known-bad**: concrete hashes published by academic papers or
//!     public incident reports (BadNets, Trojan-fine-tune papers, etc.).
//!   - **User allow-list**: hashes the user has explicitly pinned as
//!     trusted. Hashes here short-circuit any known-bad match for the
//!     same file (the user has vouched for them).
//!
//! The lists are stored as flat text files, one `sha256` per line
//! (case-insensitive, optional `#` comments). The known-bad list lives
//! at `<security_dir>/known-bad-models.txt` and can be refreshed from a
//! configured URL; the allow-list is purely local.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

// ═══════════════════════════════════════════════════════════════════
// Config
// ═══════════════════════════════════════════════════════════════════

/// TOML section (`[models]` / `[models.vetting]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ModelVettingConfig {
    pub enabled: bool,
    /// User-pinned trusted hashes (hex, 64 chars).
    pub allow_list: Vec<String>,
    /// Optional URL from which to refresh the known-bad feed.
    /// Blank = offline-only (uses the checked-in `known-bad-models.txt`).
    pub known_bad_feed_url: String,
    pub refresh_interval_hours: u32,
}

impl Default for ModelVettingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_list: Vec::new(),
            known_bad_feed_url: String::new(),
            refresh_interval_hours: 24,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Verdict
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VettingVerdict {
    /// Hash matched the user's allow-list — trusted.
    Trusted,
    /// Hash matched the known-bad list.
    KnownBad,
    /// Hash did not match either list.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelVettingResult {
    pub path: String,
    pub sha256: String,
    pub verdict: VettingVerdict,
    /// Human-readable source of the verdict, e.g.
    /// `"allow_list:user"` or `"known_bad:builtin"`.
    pub source: String,
}

// ═══════════════════════════════════════════════════════════════════
// Loaders
// ═══════════════════════════════════════════════════════════════════

/// Parse a text feed (one hash per line, `#` comments, blanks skipped)
/// into a normalized set of lowercase hex hashes.
pub fn parse_hash_feed(content: &str) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for raw in content.lines() {
        let trimmed = raw.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() { continue; }
        let first = trimmed.split_whitespace().next().unwrap_or("");
        if is_valid_hash(first) {
            set.insert(first.to_lowercase());
        }
    }
    set
}

/// Load the known-bad list from disk. Returns empty set if the file is
/// missing (not an error — user just hasn't installed a feed).
pub fn load_known_bad(security_dir: &str) -> BTreeSet<String> {
    let path = PathBuf::from(security_dir).join("known-bad-models.txt");
    match fs::read_to_string(&path) {
        Ok(content) => parse_hash_feed(&content),
        Err(_) => BTreeSet::new(),
    }
}

/// Save/refresh the known-bad list to disk (atomic). Intended to be
/// called by the threat-feeds pipeline after a network fetch.
pub fn save_known_bad(security_dir: &str, hashes: &BTreeSet<String>) -> Result<(), String> {
    let dir = PathBuf::from(security_dir);
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {}", dir.display(), e))?;
    }
    let path = dir.join("known-bad-models.txt");
    let tmp = dir.join("known-bad-models.txt.tmp");
    let mut body = String::new();
    body.push_str("# Known-bad model SHA-256 hashes (one per line). Managed by AISecurity.\n");
    body.push_str(&format!("# Refreshed at {}\n", chrono::Utc::now().to_rfc3339()));
    for h in hashes {
        body.push_str(h);
        body.push('\n');
    }
    fs::write(&tmp, &body).map_err(|e| format!("write tmp: {}", e))?;
    fs::rename(&tmp, &path).map_err(|e| format!("rename: {}", e))?;
    Ok(())
}

/// Normalize the config's `allow_list` into a set of lowercase hex hashes.
pub fn allow_list_set(config: &ModelVettingConfig) -> BTreeSet<String> {
    config.allow_list.iter()
        .map(|h| h.trim().to_lowercase())
        .filter(|h| is_valid_hash(h))
        .collect()
}

// ═══════════════════════════════════════════════════════════════════
// Core check
// ═══════════════════════════════════════════════════════════════════

/// Vet a single model hash against allow-list + known-bad list.
///
/// Allow-list always wins over known-bad (user has vouched).
pub fn vet_hash(
    path: &str,
    sha256: &str,
    allow_list: &BTreeSet<String>,
    known_bad: &BTreeSet<String>,
) -> ModelVettingResult {
    let norm = sha256.to_lowercase();
    if allow_list.contains(&norm) {
        return ModelVettingResult {
            path: path.to_string(),
            sha256: norm,
            verdict: VettingVerdict::Trusted,
            source: "allow_list:user".into(),
        };
    }
    if known_bad.contains(&norm) {
        return ModelVettingResult {
            path: path.to_string(),
            sha256: norm,
            verdict: VettingVerdict::KnownBad,
            source: "known_bad:feed".into(),
        };
    }
    ModelVettingResult {
        path: path.to_string(),
        sha256: norm,
        verdict: VettingVerdict::Unknown,
        source: "none".into(),
    }
}

/// Vet a batch of (path, hash) pairs. Convenience wrapper.
pub fn vet_batch(
    items: &[(String, String)],
    config: &ModelVettingConfig,
    security_dir: &str,
) -> Vec<ModelVettingResult> {
    if !config.enabled {
        return Vec::new();
    }
    let allow = allow_list_set(config);
    let bad = load_known_bad(security_dir);
    items.iter()
        .map(|(path, hash)| vet_hash(path, hash, &allow, &bad))
        .collect()
}

fn is_valid_hash(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn h(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    #[test]
    fn parse_feed_ignores_comments_and_blanks() {
        let src = format!(
            "# comment\n\n{}\n  # inline ignored\n{}  # trailing\n",
            h('a'), h('b')
        );
        let set = parse_hash_feed(&src);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&h('a')));
        assert!(set.contains(&h('b')));
    }

    #[test]
    fn parse_feed_skips_invalid_hashes() {
        let src = format!("notahash\nshorthash\n{}\n", h('a'));
        let set = parse_hash_feed(&src);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn vet_trusted_via_allow_list() {
        let allow: BTreeSet<_> = [h('a')].iter().cloned().collect();
        let bad: BTreeSet<_> = [h('a')].iter().cloned().collect(); // both contain it
        let r = vet_hash("/m.gguf", &h('a'), &allow, &bad);
        // Allow-list wins.
        assert_eq!(r.verdict, VettingVerdict::Trusted);
        assert!(r.source.contains("allow_list"));
    }

    #[test]
    fn vet_known_bad_detected() {
        let allow = BTreeSet::new();
        let bad: BTreeSet<_> = [h('c')].iter().cloned().collect();
        let r = vet_hash("/m.gguf", &h('c'), &allow, &bad);
        assert_eq!(r.verdict, VettingVerdict::KnownBad);
    }

    #[test]
    fn vet_unknown_when_neither_matches() {
        let allow = BTreeSet::new();
        let bad = BTreeSet::new();
        let r = vet_hash("/m.gguf", &h('d'), &allow, &bad);
        assert_eq!(r.verdict, VettingVerdict::Unknown);
    }

    #[test]
    fn allow_list_set_filters_invalid() {
        let cfg = ModelVettingConfig {
            allow_list: vec![h('a'), "notahash".into(), h('b').to_uppercase()],
            ..ModelVettingConfig::default()
        };
        let s = allow_list_set(&cfg);
        assert_eq!(s.len(), 2);
        // Should be lowercase-normalized.
        assert!(s.contains(&h('b')));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("aisec_vet_rt");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut hashes = BTreeSet::new();
        hashes.insert(h('e'));
        hashes.insert(h('f'));

        save_known_bad(dir.to_str().unwrap(), &hashes).unwrap();
        let loaded = load_known_bad(dir.to_str().unwrap());
        assert_eq!(loaded, hashes);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vet_batch_disabled_returns_empty() {
        let cfg = ModelVettingConfig { enabled: false, ..Default::default() };
        let items = vec![("/m".into(), h('z'))];
        let r = vet_batch(&items, &cfg, "/nonexistent");
        assert!(r.is_empty());
    }
}
