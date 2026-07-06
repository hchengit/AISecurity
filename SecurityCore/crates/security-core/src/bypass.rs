//! Global bypass switch — the user's "just let the agent do whatever"
//! escape hatch.
//!
//! Checked at the top of every enforcement path (intent-hook, aisec-mcp,
//! local_services HTTP handlers). When active, the path short-circuits
//! to an Allow with a `bypass:*` reason so audit logs still record the
//! event — the user opted out, they didn't vanish.
//!
//! Two sources, either activates bypass:
//!
//!   * **File**    `~/.mac-security/bypass` (or `<MACSEC_SECURITY_DIR>/bypass`)
//!   * **Env var** `AISEC_BYPASS=1` (or any non-empty value other than `0`/`false`/`no`)
//!
//! File wins — it's the "stable" signal (survives across shells, matches
//! the menu-bar UX when that lands). Env var is for per-process overrides.

use std::path::PathBuf;

/// Reason an individual call was bypassed. Serialized into the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BypassReason {
    File(String),
    EnvVar,
}

impl BypassReason {
    pub fn as_audit_str(&self) -> String {
        match self {
            BypassReason::File(path) => format!("bypass:file={}", path),
            BypassReason::EnvVar     => "bypass:env=AISEC_BYPASS".into(),
        }
    }
}

/// Returns `Some(reason)` if bypass is active, `None` otherwise.
///
/// `security_dir` is the user's AISecurity directory — typically
/// `~/.mac-security`. `None` means "compute from the $HOME env var".
pub fn active(security_dir: Option<&str>) -> Option<BypassReason> {
    active_with(security_dir, std::env::var("AISEC_BYPASS").ok().as_deref())
}

/// Like [`active`] but ignores the `AISEC_BYPASS` environment variable —
/// only the on-disk bypass file activates.
///
/// Enforcement components that run *inside the monitored agent's
/// environment* (e.g. the PreToolUse hook) use this: an agent that can set
/// an env var on the hook process must not be able to switch enforcement
/// off with `AISEC_BYPASS=1`. The bypass file requires write access to the
/// security directory, a meaningfully higher bar. Trusted, long-lived
/// components with their own launch environment (the daemon) use [`active`].
pub fn active_file_only(security_dir: Option<&str>) -> Option<BypassReason> {
    active_with(security_dir, None)
}

/// Core of [`active`] with the `AISEC_BYPASS` env value passed in explicitly
/// rather than read from the process environment. This keeps the decision a
/// pure function of its inputs so tests can exercise every branch without
/// mutating process-global env (which would race other tests). Callers in
/// production go through [`active`], which reads the real env var.
fn active_with(security_dir: Option<&str>, env_bypass: Option<&str>) -> Option<BypassReason> {
    if let Some(path) = bypass_file_path(security_dir) {
        if std::path::Path::new(&path).exists() {
            return Some(BypassReason::File(path));
        }
    }
    if env_truthy(env_bypass) {
        return Some(BypassReason::EnvVar);
    }
    None
}

fn bypass_file_path(security_dir: Option<&str>) -> Option<String> {
    let base: String = if let Some(d) = security_dir {
        d.to_string()
    } else if let Ok(d) = std::env::var("MACSEC_SECURITY_DIR") {
        d
    } else if let Ok(home) = std::env::var("HOME") {
        format!("{}/.mac-security", home)
    } else {
        return None;
    };
    Some(format!("{}/bypass", base.trim_end_matches('/')))
}

/// Whether an `AISEC_BYPASS` value counts as "on". Pure — no env access.
fn env_truthy(v: Option<&str>) -> bool {
    match v {
        Some(v) => {
            let v = v.trim().to_lowercase();
            !v.is_empty() && v != "0" && v != "false" && v != "no" && v != "off"
        }
        None => false,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests — exercise `active_with` / `env_truthy` directly so no branch
// depends on process-global env. Each test uses a distinct temp dir, so
// there is no shared state and no serialization is needed.
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn no_sources_no_bypass() {
        let dir = fresh_dir("aisec_bp_none");
        assert!(active_with(Some(dir.to_str().unwrap()), None).is_none());
    }

    #[test]
    fn env_var_activates() {
        let dir = fresh_dir("aisec_bp_env");
        let r = active_with(Some(dir.to_str().unwrap()), Some("1"));
        assert!(matches!(r, Some(BypassReason::EnvVar)));
    }

    #[test]
    fn env_var_falsy_values_ignored() {
        let dir = fresh_dir("aisec_bp_envfalse");
        for v in ["0", "false", "no", "off", "FALSE", ""] {
            assert!(
                active_with(Some(dir.to_str().unwrap()), Some(v)).is_none(),
                "falsy {:?} should not bypass",
                v
            );
        }
    }

    #[test]
    fn file_activates() {
        let dir = fresh_dir("aisec_bp_file");
        std::fs::create_dir_all(&dir).unwrap();
        let fpath = dir.join("bypass");
        std::fs::write(&fpath, "").unwrap();
        let r = active_with(Some(dir.to_str().unwrap()), None);
        match r {
            Some(BypassReason::File(p)) => assert_eq!(p, fpath.to_str().unwrap()),
            other => panic!("expected File, got {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_beats_env() {
        let dir = fresh_dir("aisec_bp_file_beats");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bypass"), "").unwrap();
        // File source is checked first, so it wins even when env says "on".
        let r = active_with(Some(dir.to_str().unwrap()), Some("1"));
        assert!(matches!(r, Some(BypassReason::File(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_only_ignores_env_but_honors_file() {
        let dir = fresh_dir("aisec_bp_fileonly");
        // No file present → not bypassed, regardless of any env value
        // (active_file_only never consults AISEC_BYPASS).
        assert!(active_file_only(Some(dir.to_str().unwrap())).is_none());
        // File present → bypassed via the File source.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bypass"), "").unwrap();
        assert!(matches!(
            active_file_only(Some(dir.to_str().unwrap())),
            Some(BypassReason::File(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_string_formats() {
        assert_eq!(
            BypassReason::File("/x/bypass".into()).as_audit_str(),
            "bypass:file=/x/bypass"
        );
        assert_eq!(
            BypassReason::EnvVar.as_audit_str(),
            "bypass:env=AISEC_BYPASS"
        );
    }
}
