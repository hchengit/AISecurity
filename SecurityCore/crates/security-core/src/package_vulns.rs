//! Package vulnerability feed — OSV-backed lookups for pinned dependencies.
//!
//! Distinct from `threat_feeds.rs` (URL/domain indicators). OSV records are
//! triples of `(ecosystem, name, version)` against a CVE/GHSA advisory, which
//! doesn't fit the URL/domain schema cleanly.
//!
//! # Flow
//!
//! 1. `check_package(eco, name, version)` — cache lookup first; on miss or
//!    stale entry, hit `https://api.osv.dev/v1/query` synchronously (≤30 s
//!    timeout), cache the result, return the highest-severity verdict.
//! 2. `check_package_batch` — single OSV `/v1/querybatch` call for N packages.
//!    Used by DependencyDriftWatcher when a lockfile changes. Rate-friendly.
//!
//! # Cache
//!
//! SQLite table `package_vulnerabilities` lives in `~/.mac-security/package-vulns.db`.
//! Separate DB from `threat-feeds.db` so a corrupted package cache can't take
//! down the URL/domain feeds (and vice versa).
//!
//! `checked_at` + `ttl_hours` decide freshness. Misses (no vuln found) are
//! cached too — stored with `cve=NULL` — so repeated lookups on a clean
//! package don't hit the network.

use chrono::Utc;
use once_cell::sync::Lazy;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const CACHE_TTL_HOURS: i64 = 24;

/// Result of checking a single package against the cache + OSV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageCheckResult {
    /// true iff a known advisory covers this version.
    pub vulnerable: bool,
    /// Highest-severity CVE/GHSA ID we found (or None if clean).
    pub cve: Option<String>,
    /// 1=Low, 2=Medium, 3=High, 4=Critical. -1 if clean.
    pub severity: i8,
    /// Provenance — "osv", "cache", or "error".
    pub source: String,
}

impl PackageCheckResult {
    pub fn clean(source: &str) -> Self {
        Self { vulnerable: false, cve: None, severity: -1, source: source.into() }
    }
    pub fn error(reason: &str) -> Self {
        Self { vulnerable: false, cve: None, severity: -1, source: format!("error:{}", reason) }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Database
// ═══════════════════════════════════════════════════════════════════

static DB: Lazy<Mutex<Option<Connection>>> = Lazy::new(|| Mutex::new(None));

const SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS package_vulnerabilities (
        ecosystem TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        cve TEXT,               -- NULL means "cached miss" (clean)
        severity INTEGER,        -- -1 = clean, 1..4 = Low..Critical
        source TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        PRIMARY KEY (ecosystem, name, version)
    );
    CREATE INDEX IF NOT EXISTS idx_pkg_expires ON package_vulnerabilities(expires_at);
"#;

pub fn init(security_dir: &str) -> Result<(), String> {
    let db_path = format!("{}/package-vulns.db", security_dir);
    let conn = Connection::open(&db_path)
        .map_err(|e| format!("Failed to open package-vulns.db: {}", e))?;
    conn.execute_batch(SCHEMA)
        .map_err(|e| format!("Failed to create schema: {}", e))?;
    let mut db = DB.lock().unwrap();
    *db = Some(conn);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Ecosystem normalization — OSV uses specific casing per ecosystem.
// ═══════════════════════════════════════════════════════════════════

/// Normalize an ecosystem string to OSV's expected form.
/// See https://ossf.github.io/osv-schema/#affectedpackage-field for canonical list.
pub fn normalize_ecosystem(raw: &str) -> &'static str {
    match raw.to_lowercase().as_str() {
        "pypi" | "pip" | "python" => "PyPI",
        "npm" | "node" | "nodejs" => "npm",
        "cargo" | "crates" | "crates.io" | "rust" => "crates.io",
        "go" | "golang" => "Go",
        "rubygems" | "gem" | "ruby" => "RubyGems",
        "maven" | "java" => "Maven",
        "nuget" | "dotnet" | ".net" => "NuGet",
        "packagist" | "composer" | "php" => "Packagist",
        _ => "PyPI", // default — most supply-chain incidents are in pip
    }
}

// ═══════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════

/// Single-package lookup. Cache-first, network on miss.
pub fn check_package(ecosystem: &str, name: &str, version: &str) -> PackageCheckResult {
    let eco = normalize_ecosystem(ecosystem);
    let name_l = name.to_lowercase();
    let ver = version.trim().to_string();

    if let Some(cached) = cache_get(eco, &name_l, &ver) {
        return cached;
    }

    // Cache miss — hit OSV for this one package.
    let fresh = match osv_query_one(eco, &name_l, &ver) {
        Ok(r) => r,
        Err(e) => return PackageCheckResult::error(&e),
    };

    // Persist and return.
    cache_put(eco, &name_l, &ver, &fresh);
    fresh
}

/// Batched lookup — single OSV /querybatch roundtrip for N packages.
/// Returns results in the same order as the input `queries` slice.
pub fn check_package_batch(queries: &[(String, String, String)]) -> Vec<PackageCheckResult> {
    if queries.is_empty() {
        return Vec::new();
    }

    // Serve as much as possible from cache; collect misses for a single
    // network call.
    let mut out: Vec<Option<PackageCheckResult>> = vec![None; queries.len()];
    let mut misses: Vec<usize> = Vec::new();
    for (idx, (eco, name, ver)) in queries.iter().enumerate() {
        let eco_n = normalize_ecosystem(eco);
        let name_l = name.to_lowercase();
        if let Some(cached) = cache_get(eco_n, &name_l, ver) {
            out[idx] = Some(cached);
        } else {
            misses.push(idx);
        }
    }

    if !misses.is_empty() {
        let miss_queries: Vec<(String, String, String)> = misses.iter()
            .map(|&i| {
                let (e, n, v) = &queries[i];
                (normalize_ecosystem(e).to_string(), n.to_lowercase(), v.clone())
            })
            .collect();
        match osv_query_batch(&miss_queries) {
            Ok(results) => {
                for (i, idx) in misses.iter().enumerate() {
                    let result = results.get(i).cloned().unwrap_or_else(|| PackageCheckResult::clean("osv"));
                    let (eco, name, ver) = &miss_queries[i];
                    cache_put(eco, name, ver, &result);
                    out[*idx] = Some(result);
                }
            }
            Err(e) => {
                let err = PackageCheckResult::error(&e);
                for &idx in &misses {
                    out[idx] = Some(err.clone());
                }
            }
        }
    }

    out.into_iter().map(|r| r.unwrap_or_else(|| PackageCheckResult::error("unreachable"))).collect()
}

// ═══════════════════════════════════════════════════════════════════
// Cache
// ═══════════════════════════════════════════════════════════════════

fn cache_get(ecosystem: &str, name: &str, version: &str) -> Option<PackageCheckResult> {
    let db = DB.lock().unwrap();
    let conn = db.as_ref()?;
    let now = Utc::now().to_rfc3339();

    let result = conn.query_row(
        "SELECT cve, severity, source FROM package_vulnerabilities
         WHERE ecosystem = ?1 AND name = ?2 AND version = ?3 AND expires_at > ?4",
        params![ecosystem, name, version, &now],
        |row| {
            let cve: Option<String> = row.get(0)?;
            let severity: i64 = row.get(1)?;
            let source: String = row.get(2)?;
            Ok((cve, severity, source))
        },
    ).ok()?;

    let (cve, severity, source) = result;
    Some(PackageCheckResult {
        vulnerable: cve.is_some(),
        cve,
        severity: severity as i8,
        source: format!("cache:{}", source),
    })
}

fn cache_put(ecosystem: &str, name: &str, version: &str, r: &PackageCheckResult) {
    let db = DB.lock().unwrap();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return,
    };
    let now = Utc::now();
    let now_s = now.to_rfc3339();
    let expires = (now + chrono::Duration::hours(CACHE_TTL_HOURS)).to_rfc3339();

    let _ = conn.execute(
        "INSERT INTO package_vulnerabilities (ecosystem, name, version, cve, severity, source, checked_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(ecosystem, name, version) DO UPDATE SET
           cve = ?4, severity = ?5, source = ?6, checked_at = ?7, expires_at = ?8",
        params![
            ecosystem, name, version,
            r.cve.as_deref(),
            r.severity as i64,
            &r.source,
            &now_s, &expires
        ],
    );
}

// ═══════════════════════════════════════════════════════════════════
// OSV client
// ═══════════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Serialize)]
struct OsvQuery<'a> {
    package: OsvPackage<'a>,
    version: &'a str,
}

#[derive(Serialize)]
struct OsvBatchRequest<'a> {
    queries: Vec<OsvQuery<'a>>,
}

#[derive(Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResult>,
}

#[derive(Deserialize)]
struct OsvBatchResult {
    #[serde(default)]
    vulns: Vec<OsvBatchVuln>,
}

#[derive(Deserialize)]
struct OsvBatchVuln {
    id: String,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    kind: String,
    score: String,
}

fn osv_query_one(ecosystem: &str, name: &str, version: &str) -> Result<PackageCheckResult, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    let body = OsvQuery {
        package: OsvPackage { name, ecosystem },
        version,
    };
    let body_json = serde_json::to_string(&body)
        .map_err(|e| format!("osv serialize: {}", e))?;

    let resp = client
        .post(OSV_QUERY_URL)
        .header("Content-Type", "application/json")
        .body(body_json)
        .send()
        .map_err(|e| format!("osv query: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("osv http {}", resp.status()));
    }

    let resp_text = resp.text()
        .map_err(|e| format!("osv read body: {}", e))?;
    let parsed: OsvQueryResponse = serde_json::from_str(&resp_text)
        .map_err(|e| format!("osv parse: {}", e))?;

    Ok(build_result_from_vulns(&parsed.vulns))
}

fn osv_query_batch(queries: &[(String, String, String)]) -> Result<Vec<PackageCheckResult>, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {}", e))?;

    let osv_queries: Vec<OsvQuery> = queries.iter()
        .map(|(eco, name, ver)| OsvQuery {
            package: OsvPackage { name: name.as_str(), ecosystem: eco.as_str() },
            version: ver.as_str(),
        })
        .collect();

    let body = OsvBatchRequest { queries: osv_queries };
    let body_json = serde_json::to_string(&body)
        .map_err(|e| format!("osv batch serialize: {}", e))?;

    let resp = client
        .post(OSV_BATCH_URL)
        .header("Content-Type", "application/json")
        .body(body_json)
        .send()
        .map_err(|e| format!("osv batch: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("osv batch http {}", resp.status()));
    }

    let resp_text = resp.text()
        .map_err(|e| format!("osv batch read body: {}", e))?;
    let parsed: OsvBatchResponse = serde_json::from_str(&resp_text)
        .map_err(|e| format!("osv batch parse: {}", e))?;

    // /querybatch returns only {id} per vuln — no severity. Any non-empty
    // vulns list means "vulnerable", and we treat it as HIGH by default.
    // The single-package /query is what we hit for precise severity later.
    let out: Vec<PackageCheckResult> = parsed.results.into_iter()
        .map(|r| {
            if r.vulns.is_empty() {
                PackageCheckResult::clean("osv")
            } else {
                let ids: Vec<String> = r.vulns.into_iter().map(|v| v.id).collect();
                PackageCheckResult {
                    vulnerable: true,
                    cve: Some(ids.join(",")),
                    severity: 3, // default HIGH — /querybatch omits severity
                    source: "osv".into(),
                }
            }
        })
        .collect();

    Ok(out)
}

/// Collapse a set of OSV vulns to a single result, picking the highest severity.
fn build_result_from_vulns(vulns: &[OsvVuln]) -> PackageCheckResult {
    if vulns.is_empty() {
        return PackageCheckResult::clean("osv");
    }

    let mut top_sev = 3i8; // default HIGH for "we have an advisory but no CVSS"
    let mut top_id = vulns[0].id.clone();
    for v in vulns {
        // Prefer GHSA IDs over other IDs — more stable + human-readable
        if v.id.starts_with("GHSA-") && !top_id.starts_with("GHSA-") {
            top_id = v.id.clone();
        }
        for s in &v.severity {
            // CVSS score comes in as e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            // or a bare numeric like "9.8". Both forms appear in OSV.
            if let Some(score) = parse_cvss_score(&s.score) {
                let sev = cvss_to_severity(score);
                if sev > top_sev {
                    top_sev = sev;
                    top_id = v.id.clone();
                }
            }
        }
        // Some advisories use database_specific.severity = "HIGH" etc.
        if let Some(ds) = &v.database_specific {
            if let Some(sev_str) = ds.get("severity").and_then(|v| v.as_str()) {
                let sev = match sev_str.to_uppercase().as_str() {
                    "CRITICAL" => 4,
                    "HIGH" => 3,
                    "MODERATE" | "MEDIUM" => 2,
                    "LOW" => 1,
                    _ => top_sev,
                };
                if sev > top_sev {
                    top_sev = sev;
                    top_id = v.id.clone();
                }
            }
        }
    }

    PackageCheckResult {
        vulnerable: true,
        cve: Some(top_id),
        severity: top_sev,
        source: "osv".into(),
    }
}

fn parse_cvss_score(s: &str) -> Option<f32> {
    // "9.8" — direct numeric.
    if let Ok(n) = s.parse::<f32>() {
        return Some(n);
    }
    // "CVSS:3.1/AV:N/..." — no raw score, just the vector. We can't compute
    // the score without the full CVSS algorithm, so return None and let the
    // database_specific fallback or default severity kick in.
    None
}

fn cvss_to_severity(score: f32) -> i8 {
    if score >= 9.0 { 4 }
    else if score >= 7.0 { 3 }
    else if score >= 4.0 { 2 }
    else { 1 }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn isolated_db(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("aisec_pkgvuln_{}", name));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        let mut db = DB.lock().unwrap();
        *db = None;
        drop(db);
        init(dir.to_str().unwrap()).unwrap();
        dir.to_str().unwrap().to_string()
    }

    fn cleanup(dir: &str) {
        let mut db = DB.lock().unwrap();
        *db = None;
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ecosystem_normalization() {
        assert_eq!(normalize_ecosystem("pypi"), "PyPI");
        assert_eq!(normalize_ecosystem("Python"), "PyPI");
        assert_eq!(normalize_ecosystem("npm"), "npm");
        assert_eq!(normalize_ecosystem("Cargo"), "crates.io");
        assert_eq!(normalize_ecosystem("crates.io"), "crates.io");
        assert_eq!(normalize_ecosystem("golang"), "Go");
        assert_eq!(normalize_ecosystem("gem"), "RubyGems");
    }

    #[test]
    fn cache_miss_then_hit() {
        let dir = isolated_db("cachehit");
        // Preload a cache entry manually (bypassing OSV).
        let r = PackageCheckResult {
            vulnerable: true,
            cve: Some("GHSA-xxxx".into()),
            severity: 4,
            source: "osv".into(),
        };
        cache_put("PyPI", "litellm", "1.82.8", &r);

        let got = cache_get("PyPI", "litellm", "1.82.8").unwrap();
        assert!(got.vulnerable);
        assert_eq!(got.severity, 4);
        assert_eq!(got.cve, Some("GHSA-xxxx".into()));
        assert!(got.source.starts_with("cache:"));

        // Miss on different version.
        assert!(cache_get("PyPI", "litellm", "9.9.9").is_none());
        cleanup(&dir);
    }

    #[test]
    fn cache_stores_clean_lookups_too() {
        let dir = isolated_db("cacheclean");
        cache_put("PyPI", "requests", "2.31.0", &PackageCheckResult::clean("osv"));
        let hit = cache_get("PyPI", "requests", "2.31.0").unwrap();
        assert!(!hit.vulnerable);
        assert!(hit.cve.is_none());
        cleanup(&dir);
    }

    #[test]
    fn cvss_thresholds() {
        assert_eq!(cvss_to_severity(9.8), 4);
        assert_eq!(cvss_to_severity(9.0), 4);
        assert_eq!(cvss_to_severity(7.5), 3);
        assert_eq!(cvss_to_severity(5.0), 2);
        assert_eq!(cvss_to_severity(2.0), 1);
    }

    #[test]
    fn build_result_picks_highest_severity() {
        let vulns = vec![
            OsvVuln {
                id: "CVE-lowsev".into(),
                severity: vec![OsvSeverity { kind: "CVSS_V3".into(), score: "5.0".into() }],
                database_specific: None,
            },
            OsvVuln {
                id: "GHSA-critical".into(),
                severity: vec![OsvSeverity { kind: "CVSS_V3".into(), score: "9.5".into() }],
                database_specific: None,
            },
        ];
        let r = build_result_from_vulns(&vulns);
        assert!(r.vulnerable);
        assert_eq!(r.severity, 4);
        assert_eq!(r.cve, Some("GHSA-critical".into()));
    }

    #[test]
    fn build_result_uses_database_specific_severity() {
        let vulns = vec![OsvVuln {
            id: "GHSA-xxxx".into(),
            severity: vec![],
            database_specific: Some(serde_json::json!({ "severity": "CRITICAL" })),
        }];
        let r = build_result_from_vulns(&vulns);
        assert_eq!(r.severity, 4);
    }

    #[test]
    fn build_result_clean_when_no_vulns() {
        let r = build_result_from_vulns(&[]);
        assert!(!r.vulnerable);
        assert_eq!(r.severity, -1);
        assert!(r.cve.is_none());
    }
}
