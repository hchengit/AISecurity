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
    if let Some(path) = bypass_file_path(security_dir) {
        if std::path::Path::new(&path).exists() {
            return Some(BypassReason::File(path));
        }
    }
    if env_bypass_on() {
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

fn env_bypass_on() -> bool {
    match std::env::var("AISEC_BYPASS") {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            !v.is_empty() && v != "0" && v != "false" && v != "no" && v != "off"
        }
        Err(_) => false,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests — use a serial Mutex because env vars + filesystem are process-global.
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests mutate process-global state (env + a temp directory). Serialize.
    static GUARD: Mutex<()> = Mutex::new(());

    fn clean_env() {
        std::env::remove_var("AISEC_BYPASS");
        std::env::remove_var("MACSEC_SECURITY_DIR");
    }

    #[test]
    fn no_sources_no_bypass() {
        let _g = GUARD.lock().unwrap();
        clean_env();
        let dir = std::env::temp_dir().join("aisec_bp_none");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(active(Some(dir.to_str().unwrap())).is_none());
    }

    #[test]
    fn env_var_activates() {
        let _g = GUARD.lock().unwrap();
        clean_env();
        std::env::set_var("AISEC_BYPASS", "1");
        let dir = std::env::temp_dir().join("aisec_bp_env");
        let _ = std::fs::remove_dir_all(&dir);
        let r = active(Some(dir.to_str().unwrap()));
        assert!(matches!(r, Some(BypassReason::EnvVar)));
        clean_env();
    }

    #[test]
    fn env_var_falsy_values_ignored() {
        let _g = GUARD.lock().unwrap();
        clean_env();
        let dir = std::env::temp_dir().join("aisec_bp_envfalse");
        let _ = std::fs::remove_dir_all(&dir);
        for v in ["0", "false", "no", "off", "FALSE", ""] {
            std::env::set_var("AISEC_BYPASS", v);
            assert!(active(Some(dir.to_str().unwrap())).is_none(), "falsy {:?} should not bypass", v);
        }
        clean_env();
    }

    #[test]
    fn file_activates() {
        let _g = GUARD.lock().unwrap();
        clean_env();
        let dir = std::env::temp_dir().join("aisec_bp_file");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fpath = dir.join("bypass");
        std::fs::write(&fpath, "").unwrap();
        let r = active(Some(dir.to_str().unwrap()));
        match r {
            Some(BypassReason::File(p)) => assert_eq!(p, fpath.to_str().unwrap()),
            other => panic!("expected File, got {:?}", other),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_beats_env() {
        let _g = GUARD.lock().unwrap();
        clean_env();
        let dir = std::env::temp_dir().join("aisec_bp_file_beats");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bypass"), "").unwrap();
        std::env::set_var("AISEC_BYPASS", "1");
        let r = active(Some(dir.to_str().unwrap()));
        assert!(matches!(r, Some(BypassReason::File(_))));
        clean_env();
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
