use serde::Deserialize;
use std::path::PathBuf;

use crate::path_resolver::PathResolver;

/// Top-level configuration — same TOML format as Phase 1 Swift config.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub general: GeneralConfig,
    pub paths: PathsConfig,
    pub file_watcher: FileWatcherConfig,
    pub email_scanner: EmailScannerConfig,
    pub messages_scanner: MessagesScannerConfig,
    pub scheduled_scan: ScheduledScanConfig,
    pub notifications: NotificationsConfig,
    pub protected_paths: ProtectedPathsConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub mode: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    pub security_dir: String,
    pub mail_dir: String,
    pub messages_db: String,
    pub quarantine_dir: String,
    pub log_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FileWatcherConfig {
    pub enabled: bool,
    pub monitored_directories: Vec<String>,
    pub max_scan_size_bytes: usize,
    pub debounce_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EmailScannerConfig {
    pub enabled: bool,
    pub startup_scan_limit: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MessagesScannerConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScheduledScanConfig {
    pub enabled: bool,
    pub interval_hours: u32,
    pub scan_directories: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotificationsConfig {
    pub enabled: bool,
    pub critical_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProtectedPathsConfig {
    pub paths: Option<Vec<String>>,
}

// -- Defaults --

#[allow(clippy::derivable_impls)]
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            paths: PathsConfig::default(),
            file_watcher: FileWatcherConfig::default(),
            email_scanner: EmailScannerConfig::default(),
            messages_scanner: MessagesScannerConfig::default(),
            scheduled_scan: ScheduledScanConfig::default(),
            notifications: NotificationsConfig::default(),
            protected_paths: ProtectedPathsConfig::default(),
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: "PRODUCTION".to_string(),
        }
    }
}

impl Default for PathsConfig {
    fn default() -> Self {
        let resolver = PathResolver::new();
        Self {
            security_dir: resolver.security_dir().to_string(),
            mail_dir: resolver.mail_dir().to_string(),
            messages_db: resolver.messages_db().to_string(),
            quarantine_dir: resolver.quarantine_dir().to_string(),
            log_dir: resolver.log_dir().to_string(),
        }
    }
}

impl Default for FileWatcherConfig {
    fn default() -> Self {
        let resolver = PathResolver::new();
        Self {
            enabled: true,
            monitored_directories: resolver
                .default_monitored_dirs()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            max_scan_size_bytes: 5_242_880, // 5 MB
            debounce_ms: 300,
        }
    }
}

impl Default for EmailScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            startup_scan_limit: 50,
        }
    }
}

impl Default for MessagesScannerConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for ScheduledScanConfig {
    fn default() -> Self {
        let resolver = PathResolver::new();
        Self {
            enabled: true,
            interval_hours: 6,
            scan_directories: resolver
                .default_monitored_dirs()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            critical_only: true,
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for ProtectedPathsConfig {
    fn default() -> Self {
        Self { paths: None }
    }
}

impl SecurityConfig {
    /// Load config from a TOML file, with env var overrides.
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        let mut config: SecurityConfig =
            toml::from_str(&content).map_err(|e| format!("Failed to parse TOML: {}", e))?;
        config.apply_env_overrides();
        Ok(config)
    }

    /// Load with defaults if file doesn't exist, then apply env overrides.
    pub fn load_or_default(path: &str) -> Self {
        let mut config = if PathBuf::from(path).exists() {
            Self::load(path).unwrap_or_default()
        } else {
            Self::default()
        };
        config.apply_env_overrides();
        config
    }

    /// Apply MACSEC_* environment variable overrides.
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("MACSEC_MODE") {
            self.general.mode = v;
        }
        if let Ok(v) = std::env::var("MACSEC_SECURITY_DIR") {
            self.paths.security_dir = v;
        }
        if let Ok(v) = std::env::var("MACSEC_MAIL_DIR") {
            self.paths.mail_dir = v;
        }
        if let Ok(v) = std::env::var("MACSEC_MESSAGES_DB") {
            self.paths.messages_db = v;
        }
        if let Ok(v) = std::env::var("MACSEC_LOG_DIR") {
            self.paths.log_dir = v;
        }
        if let Ok(v) = std::env::var("MACSEC_QUARANTINE_DIR") {
            self.paths.quarantine_dir = v;
        }
        if let Ok(v) = std::env::var("MACSEC_SCAN_DIRS") {
            self.file_watcher.monitored_directories =
                v.split(':').map(|s| s.to_string()).collect();
        }
    }

    /// Get protected paths — custom if configured, else platform defaults.
    pub fn protected_paths(&self) -> Vec<String> {
        if let Some(ref custom) = self.protected_paths.paths {
            return custom.clone();
        }
        let resolver = PathResolver::new();
        resolver
            .default_protected_paths()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Is mode PRODUCTION?
    pub fn is_production(&self) -> bool {
        self.general.mode.eq_ignore_ascii_case("PRODUCTION")
    }

    /// Is mode TESTING?
    pub fn is_testing(&self) -> bool {
        self.general.mode.eq_ignore_ascii_case("TESTING")
    }

    /// Is mode DEVELOPMENT?
    pub fn is_development(&self) -> bool {
        self.general.mode.eq_ignore_ascii_case("DEVELOPMENT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SecurityConfig::default();
        assert_eq!(config.general.mode, "PRODUCTION");
        assert!(config.file_watcher.enabled);
        assert_eq!(config.file_watcher.max_scan_size_bytes, 5_242_880);
        assert_eq!(config.file_watcher.debounce_ms, 300);
        assert_eq!(config.email_scanner.startup_scan_limit, 50);
        assert_eq!(config.scheduled_scan.interval_hours, 6);
        assert!(config.notifications.critical_only);
    }

    #[test]
    fn parse_toml() {
        let toml = r#"
[general]
mode = "TESTING"

[paths]
security_dir = "/tmp/test-security"
log_dir = "/tmp/test-logs"

[file_watcher]
enabled = false
max_scan_size_bytes = 1048576

[email_scanner]
enabled = false

[notifications]
critical_only = false
"#;
        let config: SecurityConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.general.mode, "TESTING");
        assert_eq!(config.paths.security_dir, "/tmp/test-security");
        assert!(!config.file_watcher.enabled);
        assert_eq!(config.file_watcher.max_scan_size_bytes, 1_048_576);
        assert!(!config.email_scanner.enabled);
        assert!(!config.notifications.critical_only);
    }

    #[test]
    fn mode_checks() {
        let mut config = SecurityConfig::default();
        assert!(config.is_production());
        config.general.mode = "TESTING".to_string();
        assert!(config.is_testing());
        config.general.mode = "DEVELOPMENT".to_string();
        assert!(config.is_development());
    }

    #[test]
    fn protected_paths_default() {
        let config = SecurityConfig::default();
        let paths = config.protected_paths();
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.contains(".ssh")));
        assert!(paths.iter().any(|p| p.contains(".gnupg")));
    }

    #[test]
    fn protected_paths_custom() {
        let mut config = SecurityConfig::default();
        config.protected_paths.paths = Some(vec!["/custom/path".to_string()]);
        let paths = config.protected_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "/custom/path");
    }
}
