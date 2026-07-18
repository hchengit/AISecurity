//! Real-time threat intelligence feeds — OpenPhish + Spamhaus DBL.
//!
//! Downloads known-bad URL/domain lists, caches in local SQLite, provides fast lookup.
//! All checks are local queries — no user data leaves the machine.
//! Stale cache remains queryable when offline.

use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::{params, Connection};
use std::sync::Mutex;
use std::time::Duration;

use crate::path_resolver::PathResolver;

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

/// Result of checking a URL or domain against threat feeds.
#[derive(Debug, Clone)]
pub struct FeedLookupResult {
    /// -1 = no match, 1-4 = Low..Critical
    pub threat_level: i8,
    /// Which feed matched (e.g., "openphish", "spamhaus_dbl")
    pub feed_name: Option<String>,
    /// The matched indicator (URL or domain)
    pub indicator: Option<String>,
}

impl FeedLookupResult {
    pub fn no_match() -> Self {
        Self { threat_level: -1, feed_name: None, indicator: None }
    }

    pub fn is_match(&self) -> bool {
        self.threat_level > 0
    }
}

/// Feed source definition.
struct FeedMeta {
    name: &'static str,
    url: &'static str,
    indicator_type: &'static str,  // "url" or "domain"
    severity: i8,                   // 1=Low, 2=Medium, 3=High, 4=Critical
    ttl_hours: u32,                 // how long entries stay valid
    comment_prefix: &'static str,   // lines starting with this are skipped
}

/// Feed health stats.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedStats {
    pub feed_name: String,
    pub last_refresh: Option<String>,
    pub last_error: Option<String>,
    pub entry_count: u32,
    pub total_hits: u32,
    pub refresh_count: u32,
    pub error_count: u32,
}

// ═══════════════════════════════════════════════════════════════════
// Feed definitions
// ═══════════════════════════════════════════════════════════════════

static FEEDS: &[FeedMeta] = &[
    FeedMeta {
        name: "openphish",
        url: "https://openphish.com/feed.txt",
        indicator_type: "url",
        severity: 3, // HIGH
        ttl_hours: 720, // 30 days — phishing domains stay dangerous for weeks
        comment_prefix: "#",
    },
    FeedMeta {
        name: "spamhaus_dbl_sample",
        // Free community sample — full DBL requires paid subscription
        url: "https://www.spamhaus.org/drop/drop.txt",
        indicator_type: "domain",
        severity: 3, // HIGH
        ttl_hours: 720, // 30 days — spam infrastructure changes slowly
        comment_prefix: ";",
    },
];

// ═══════════════════════════════════════════════════════════════════
// Database
// ═══════════════════════════════════════════════════════════════════

static DB: Lazy<Mutex<Option<Connection>>> = Lazy::new(|| Mutex::new(None));

const SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS feed_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        feed_name TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        indicator TEXT NOT NULL,
        severity INTEGER NOT NULL DEFAULT 3,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        UNIQUE(feed_name, indicator)
    );
    CREATE INDEX IF NOT EXISTS idx_indicator ON feed_entries(indicator);
    CREATE INDEX IF NOT EXISTS idx_expires ON feed_entries(expires_at);

    CREATE TABLE IF NOT EXISTS feed_stats (
        feed_name TEXT PRIMARY KEY,
        last_refresh TEXT,
        last_error TEXT,
        entry_count INTEGER DEFAULT 0,
        total_hits INTEGER DEFAULT 0,
        refresh_count INTEGER DEFAULT 0,
        error_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS feed_hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        feed_name TEXT NOT NULL,
        indicator TEXT NOT NULL,
        hit_at TEXT NOT NULL,
        context TEXT
    );
"#;

/// Initialize the threat feeds database. Call once at startup.
pub fn init(security_dir: &str) -> Result<(), String> {
    let db_path = format!("{}/threat-feeds.db", security_dir);
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open threat-feeds.db: {}", e))?;
    conn.execute_batch(SCHEMA)
        .map_err(|e| format!("Failed to create schema: {}", e))?;

    // Initialize stats rows for each feed
    for feed in FEEDS {
        conn.execute(
            "INSERT OR IGNORE INTO feed_stats (feed_name) VALUES (?1)",
            params![feed.name],
        ).map_err(|e| format!("Failed to init stats: {}", e))?;
    }

    let mut db = DB.lock().unwrap();
    *db = Some(conn);
    Ok(())
}

/// Initialize with default security directory.
pub fn init_default() -> Result<(), String> {
    let resolver = PathResolver::new();
    init(&resolver.security_dir())
}

// ═══════════════════════════════════════════════════════════════════
// Lookup
// ═══════════════════════════════════════════════════════════════════

/// Shared infrastructure — cloud storage, CDNs, and email click-trackers that host both
/// legitimate and malicious content. A phishing page on one of these (e.g. an openphish URL like
/// `https://s3.us-east-1.amazonaws.com/bucket/phish.html`) reduces to a *host* that thousands of
/// legitimate senders also use, so matching a URL by that host produces massive false positives
/// (TikTok's `post.spmailtechnol.com` tracker, Postmark's `track.pstmrk.it`, any S3 link…). For
/// these hosts we require an EXACT full-URL feed match instead of a host-level one; a dedicated
/// phishing domain, by contrast, is still matched by host.
const SHARED_INFRA_SUFFIXES: &[&str] = &[
    // Object storage on a SHARED, path-addressed endpoint (many tenants → one hostname). NOTE:
    // deliberately does NOT include per-tenant-subdomain platforms (*.web.app, *.pages.dev,
    // *.azurewebsites.net, *.firebaseapp.com, *.r2.dev, *.backblazeb2.com, *.blob.core.windows.net,
    // *.cloudfront.net, *.googleusercontent.com): there each host is a single attacker-owned tenant,
    // so a host-level feed match is precise and SHOULD flag it.
    "amazonaws.com", "storage.googleapis.com",
    // Email service providers' click/open trackers (shared tracking hostnames).
    "spmailtechnol.com", "pstmrk.it", "sendgrid.net", "sparkpostmail.com", "mailgun.org",
    "mcusercontent.com", "list-manage.com", "createsend.com", "rs6.net", "hubspotemail.net",
    "hubspotlinks.com", "klclick.com", "klclick2.com", "mailanyone.net", "sptrans.io",
    "cmail19.com", "cmail20.com", "mailchimpapp.net", "sendibm1.com", "sendibm2.com",
];

/// True if `host` is (or is a subdomain of) a shared-infrastructure suffix.
fn is_shared_infra_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_lowercase();
    SHARED_INFRA_SUFFIXES
        .iter()
        .any(|s| h == *s || h.ends_with(&format!(".{s}")))
}

/// Check a URL against all feeds. Checks exact URL match, then extracts domain and checks that.
pub fn check_url(url_str: &str) -> FeedLookupResult {
    let db = DB.lock().unwrap();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return FeedLookupResult::no_match(),
    };

    let normalized = url_str.trim().to_lowercase();
    let now = Utc::now().to_rfc3339();

    // 1. Exact URL match
    if let Ok(mut stmt) = conn.prepare(
        "SELECT feed_name, indicator, severity FROM feed_entries WHERE indicator = ?1 AND expires_at > ?2 LIMIT 1"
    ) {
        if let Ok((feed, matched, severity)) = stmt.query_row(params![&normalized, &now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i8>(2)?,
            ))
        }) {
            record_hit(conn, &feed, &matched, "url_exact");
            return FeedLookupResult {
                threat_level: severity,
                feed_name: Some(feed),
                indicator: Some(matched),
            };
        }
    }

    // 2. Extract domain from URL and check domain — but NOT for shared-infrastructure hosts
    //    (cloud storage, CDNs, ESP click-trackers). For those, a host-level feed hit is unreliable
    //    (legit and malicious content share the host), so only the exact-URL match above counts.
    if let Ok(parsed) = url::Url::parse(&normalized) {
        if let Some(host) = parsed.host_str() {
            if is_shared_infra_host(host) {
                return FeedLookupResult::no_match();
            }
            return check_domain_with_conn(conn, host, &now);
        }
    }
    // Fallback: try extracting domain with simple split
    if let Some(domain) = extract_domain_simple(&normalized) {
        if is_shared_infra_host(&domain) {
            return FeedLookupResult::no_match();
        }
        return check_domain_with_conn(conn, &domain, &now);
    }

    FeedLookupResult::no_match()
}

/// Check a domain against all feeds. Also checks parent domain (one level up).
pub fn check_domain(domain: &str) -> FeedLookupResult {
    let db = DB.lock().unwrap();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return FeedLookupResult::no_match(),
    };
    let now = Utc::now().to_rfc3339();
    check_domain_with_conn(conn, domain, &now)
}

fn check_domain_with_conn(conn: &Connection, domain: &str, now: &str) -> FeedLookupResult {
    let normalized = domain.trim().to_lowercase();

    // Exact domain match
    if let Some(result) = query_indicator(conn, &normalized, now) {
        return result;
    }

    // Parent domain (one level up): foo.evil.com → evil.com
    if let Some(dot_idx) = normalized.find('.') {
        let parent = &normalized[dot_idx + 1..];
        if parent.contains('.') { // still has a dot → valid domain
            if let Some(result) = query_indicator(conn, parent, now) {
                return result;
            }
        }
    }

    FeedLookupResult::no_match()
}

fn query_indicator(conn: &Connection, indicator: &str, now: &str) -> Option<FeedLookupResult> {
    let mut stmt = conn.prepare(
        "SELECT feed_name, indicator, severity FROM feed_entries WHERE indicator = ?1 AND expires_at > ?2 LIMIT 1"
    ).ok()?;

    let result = stmt.query_row(params![indicator, now], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i8>(2)?,
        ))
    }).ok()?;

    let (feed, matched, severity) = result;
    record_hit(conn, &feed, &matched, "domain");
    Some(FeedLookupResult {
        threat_level: severity,
        feed_name: Some(feed),
        indicator: Some(matched),
    })
}

fn record_hit(conn: &Connection, feed_name: &str, indicator: &str, context: &str) {
    let now = Utc::now().to_rfc3339();
    let _ = conn.execute(
        "INSERT INTO feed_hits (feed_name, indicator, hit_at, context) VALUES (?1, ?2, ?3, ?4)",
        params![feed_name, indicator, &now, context],
    );
    let _ = conn.execute(
        "UPDATE feed_stats SET total_hits = total_hits + 1 WHERE feed_name = ?1",
        params![feed_name],
    );
}

// ═══════════════════════════════════════════════════════════════════
// Refresh
// ═══════════════════════════════════════════════════════════════════

/// Refresh all feeds. Returns total entries inserted/updated, or error.
pub fn refresh_all() -> Result<u32, String> {
    let db = DB.lock().unwrap();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return Err("Database not initialized".into()),
    };

    let mut total = 0u32;
    for feed in FEEDS {
        match refresh_feed(conn, feed) {
            Ok(count) => {
                total += count;
                eprintln!("[threat_feeds] Refreshed {}: {} entries", feed.name, count);
            }
            Err(e) => {
                eprintln!("[threat_feeds] Failed to refresh {}: {}", feed.name, e);
                // Record error but continue to next feed
                let now = Utc::now().to_rfc3339();
                let _ = conn.execute(
                    "UPDATE feed_stats SET last_error = ?1, error_count = error_count + 1 WHERE feed_name = ?2",
                    params![&format!("{}: {}", now, e), feed.name],
                );
            }
        }
    }

    // Expire stale entries
    let expired = expire_stale(conn);
    if expired > 0 {
        eprintln!("[threat_feeds] Expired {} stale entries", expired);
    }

    Ok(total)
}

fn refresh_feed(conn: &Connection, feed: &FeedMeta) -> Result<u32, String> {
    // Download feed with timeout
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let response = client.get(feed.url)
        .send()
        .map_err(|e| format!("Download failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }

    let body = response.text()
        .map_err(|e| format!("Read body failed: {}", e))?;

    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let expires = (now + chrono::Duration::hours(feed.ttl_hours as i64)).to_rfc3339();

    let mut count = 0u32;

    // Parse and insert in transaction
    let tx = conn.execute("BEGIN", []).ok();
    if tx.is_none() {
        return Err("Failed to begin transaction".into());
    }

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(feed.comment_prefix) {
            continue;
        }

        let indicator = match feed.indicator_type {
            "url" => trimmed.to_lowercase(),
            "domain" => {
                // Spamhaus DROP format: "IP/CIDR ; SBLid" — extract just the IP/CIDR
                let domain_part = trimmed.split(';').next().unwrap_or(trimmed).trim();
                domain_part.to_lowercase()
            }
            _ => trimmed.to_lowercase(),
        };

        if indicator.is_empty() { continue; }

        let _ = conn.execute(
            "INSERT INTO feed_entries (feed_name, indicator_type, indicator, severity, first_seen, last_seen, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
             ON CONFLICT(feed_name, indicator) DO UPDATE SET last_seen = ?5, expires_at = ?6",
            params![feed.name, feed.indicator_type, &indicator, feed.severity, &now_str, &expires],
        );
        count += 1;

        // Also extract and store the domain from URL feeds (for domain-level lookups) — but skip
        // shared-infrastructure hosts (S3, CDNs, ESP trackers), where a bare-host indicator would
        // match every legitimate email that links through them. The full-URL indicator above is
        // still stored, so an exact hit on that specific phishing page is preserved.
        if feed.indicator_type == "url" {
            if let Ok(parsed) = url::Url::parse(&indicator) {
                if let Some(host) = parsed.host_str() {
                    let host_lower = host.to_lowercase();
                    if is_shared_infra_host(&host_lower) {
                        continue;
                    }
                    let _ = conn.execute(
                        "INSERT INTO feed_entries (feed_name, indicator_type, indicator, severity, first_seen, last_seen, expires_at)
                         VALUES (?1, 'domain', ?2, ?3, ?4, ?4, ?5)
                         ON CONFLICT(feed_name, indicator) DO UPDATE SET last_seen = ?4, expires_at = ?5",
                        params![feed.name, &host_lower, feed.severity, &now_str, &expires],
                    );
                }
            }
        }
    }

    let _ = conn.execute("COMMIT", []);

    // Update stats
    let _ = conn.execute(
        "UPDATE feed_stats SET last_refresh = ?1, entry_count = ?2, refresh_count = refresh_count + 1 WHERE feed_name = ?3",
        params![&now_str, count, feed.name],
    );

    Ok(count)
}

fn expire_stale(conn: &Connection) -> u32 {
    let now = Utc::now().to_rfc3339();
    conn.execute("DELETE FROM feed_entries WHERE expires_at < ?1", params![&now])
        .unwrap_or(0) as u32
}

// ═══════════════════════════════════════════════════════════════════
// Stats
// ═══════════════════════════════════════════════════════════════════

/// Get health stats for all feeds.
pub fn get_stats() -> Vec<FeedStats> {
    let db = DB.lock().unwrap();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return Vec::new(),
    };

    let mut stmt = match conn.prepare(
        "SELECT feed_name, last_refresh, last_error, entry_count, total_hits, refresh_count, error_count FROM feed_stats"
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    stmt.query_map([], |row| {
        Ok(FeedStats {
            feed_name: row.get(0)?,
            last_refresh: row.get(1)?,
            last_error: row.get(2)?,
            entry_count: row.get::<_, u32>(3).unwrap_or(0),
            total_hits: row.get::<_, u32>(4).unwrap_or(0),
            refresh_count: row.get::<_, u32>(5).unwrap_or(0),
            error_count: row.get::<_, u32>(6).unwrap_or(0),
        })
    }).ok()
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Get total entry count across all feeds.
pub fn total_entries() -> u32 {
    let db = DB.lock().unwrap();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return 0,
    };
    conn.query_row("SELECT COUNT(*) FROM feed_entries", [], |row| row.get(0))
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn extract_domain_simple(text: &str) -> Option<String> {
    // Extract domain from "https://foo.bar.com/path" or "foo.bar.com"
    let without_scheme = text.strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"))
        .unwrap_or(text);
    let host = without_scheme.split('/').next()?;
    let host = host.split(':').next()?; // strip port
    if host.contains('.') { Some(host.to_lowercase()) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // The feed DB is a process-global `static DB`, so tests that (re)init it
    // must run serially — otherwise one test's test_db() swaps the global
    // connection out from under another's insert→lookup. Hold this for the
    // whole test.
    static TEST_GUARD: Mutex<()> = Mutex::new(());

    fn test_db(name: &str) -> (std::sync::MutexGuard<'static, ()>, String) {
        // Tolerate poisoning so a panicking test doesn't cascade-fail the rest.
        let guard = TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("aisec_feeds_{}", name));
        let _ = fs::create_dir_all(&dir);
        // Reset global DB state
        let mut db = DB.lock().unwrap();
        *db = None;
        drop(db);
        init(dir.to_str().unwrap()).unwrap();
        (guard, dir.to_str().unwrap().to_string())
    }

    fn cleanup(dir: &str) {
        let mut db = DB.lock().unwrap();
        *db = None;
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn init_creates_db() {
        let (_guard, dir) = test_db("init");
        let db_path = format!("{}/threat-feeds.db", dir);
        assert!(fs::metadata(&db_path).is_ok());
        cleanup(&dir);
    }

    #[test]
    fn check_url_no_match() {
        let (_guard, dir) = test_db("no_match");
        let result = check_url("https://google.com");
        assert!(!result.is_match());
        assert_eq!(result.threat_level, -1);
        cleanup(&dir);
    }

    #[test]
    fn insert_and_lookup_url() {
        let (_guard, dir) = test_db("lookup_url");
        let db = DB.lock().unwrap();
        let conn = db.as_ref().unwrap();
        let now = Utc::now().to_rfc3339();
        let expires = (Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        conn.execute(
            "INSERT INTO feed_entries (feed_name, indicator_type, indicator, severity, first_seen, last_seen, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params!["openphish", "url", "https://evil-phish.com/login", 3, &now, &expires],
        ).unwrap();
        drop(db);

        let result = check_url("https://evil-phish.com/login");
        assert!(result.is_match());
        assert_eq!(result.threat_level, 3);
        assert_eq!(result.feed_name, Some("openphish".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn insert_and_lookup_domain() {
        let (_guard, dir) = test_db("lookup_domain");
        let db = DB.lock().unwrap();
        let conn = db.as_ref().unwrap();
        let now = Utc::now().to_rfc3339();
        let expires = (Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        conn.execute(
            "INSERT INTO feed_entries (feed_name, indicator_type, indicator, severity, first_seen, last_seen, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params!["spamhaus_dbl_sample", "domain", "evil-spam.com", 3, &now, &expires],
        ).unwrap();
        drop(db);

        let result = check_domain("evil-spam.com");
        assert!(result.is_match());

        // Subdomain should also match via parent lookup
        let result2 = check_domain("mail.evil-spam.com");
        assert!(result2.is_match());

        // Unrelated domain should not match
        let result3 = check_domain("google.com");
        assert!(!result3.is_match());

        cleanup(&dir);
    }

    #[test]
    fn is_shared_infra_host_matches_suffixes() {
        assert!(is_shared_infra_host("s3.us-east-1.amazonaws.com"));
        assert!(is_shared_infra_host("post.spmailtechnol.com"));
        assert!(is_shared_infra_host("track.pstmrk.it"));
        assert!(is_shared_infra_host("AMAZONAWS.COM")); // case-insensitive, bare suffix
        assert!(!is_shared_infra_host("evil-phish.com"));
        assert!(!is_shared_infra_host("notamazonaws.com")); // suffix must be dot-bounded
    }

    #[test]
    fn shared_infra_url_not_matched_by_host() {
        let (_guard, dir) = test_db("shared_infra");
        let db = DB.lock().unwrap();
        let conn = db.as_ref().unwrap();
        let now = Utc::now().to_rfc3339();
        let expires = (Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        // Simulate the stale bare-host indicators the old ingestion produced from openphish URLs,
        // plus a dedicated phishing domain.
        for host in ["s3.us-east-1.amazonaws.com", "post.spmailtechnol.com", "evil-phish.com"] {
            conn.execute(
                "INSERT INTO feed_entries (feed_name, indicator_type, indicator, severity, first_seen, last_seen, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
                params!["openphish", "domain", host, 3, &now, &expires],
            ).unwrap();
        }
        drop(db);

        // Legit mail linking through shared infra must NOT match on the host alone.
        assert!(!check_url("https://s3.us-east-1.amazonaws.com/bucket/legit-image.png").is_match());
        assert!(!check_url("https://post.spmailtechnol.com/click/abc123").is_match());
        // A dedicated phishing domain is still matched by host.
        assert!(check_url("https://evil-phish.com/login").is_match());
        cleanup(&dir);
    }

    #[test]
    fn domain_extraction_from_url() {
        let (_guard, dir) = test_db("domain_extract");
        let db = DB.lock().unwrap();
        let conn = db.as_ref().unwrap();
        let now = Utc::now().to_rfc3339();
        let expires = (Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
        // Insert domain (as if extracted from a URL feed)
        conn.execute(
            "INSERT INTO feed_entries (feed_name, indicator_type, indicator, severity, first_seen, last_seen, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params!["openphish", "domain", "phishing-site.xyz", 3, &now, &expires],
        ).unwrap();
        drop(db);

        // URL check should fall through to domain check
        let result = check_url("https://phishing-site.xyz/steal-creds");
        assert!(result.is_match());
        cleanup(&dir);
    }

    #[test]
    fn expired_entries_dont_match() {
        let (_guard, dir) = test_db("expired");
        let db = DB.lock().unwrap();
        let conn = db.as_ref().unwrap();
        let now = Utc::now().to_rfc3339();
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        conn.execute(
            "INSERT INTO feed_entries (feed_name, indicator_type, indicator, severity, first_seen, last_seen, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params!["openphish", "url", "https://expired-phish.com", 3, &now, &past],
        ).unwrap();
        drop(db);

        let result = check_url("https://expired-phish.com");
        assert!(!result.is_match(), "Expired entry should not match");
        cleanup(&dir);
    }

    #[test]
    fn extract_domain_simple_works() {
        assert_eq!(extract_domain_simple("https://foo.bar.com/path"), Some("foo.bar.com".to_string()));
        assert_eq!(extract_domain_simple("http://evil.xyz:8080/login"), Some("evil.xyz".to_string()));
        assert_eq!(extract_domain_simple("foo.bar.com"), Some("foo.bar.com".to_string()));
        assert_eq!(extract_domain_simple("localhost"), None);
    }

    #[test]
    fn stats_initialized() {
        let (_guard, dir) = test_db("stats");
        let stats = get_stats();
        assert_eq!(stats.len(), 2); // openphish + spamhaus
        assert_eq!(stats[0].refresh_count, 0);
        assert_eq!(stats[0].total_hits, 0);
        cleanup(&dir);
    }
}
