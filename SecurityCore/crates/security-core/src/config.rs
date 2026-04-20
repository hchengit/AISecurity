use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::path_resolver::PathResolver;
use crate::severity::SeverityLevel;

// ===========================================================================
// Protection Tier — user-facing security aggressiveness
// ===========================================================================

/// User-selectable protection tier.
///
/// - `Relaxed`: Baseline safety net, minimal interruption. Lets agents work freely.
/// - `Balanced`: Recommended default. Blocks critical threats, asks about medium-risk.
/// - `Strict`: Maximum enforcement. Everything monitored, tight thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtectionTier {
    Relaxed,
    Balanced,
    Strict,
}

impl Default for ProtectionTier {
    fn default() -> Self {
        ProtectionTier::Balanced
    }
}

impl ProtectionTier {
    /// Parse from string (case-insensitive). Returns None for unknown values.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "relaxed" => Some(Self::Relaxed),
            "balanced" => Some(Self::Balanced),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Relaxed => "relaxed",
            Self::Balanced => "balanced",
            Self::Strict => "strict",
        }
    }

    /// Numeric ordering: Relaxed=0, Balanced=1, Strict=2.
    pub fn level(&self) -> u8 {
        match self {
            Self::Relaxed => 0,
            Self::Balanced => 1,
            Self::Strict => 2,
        }
    }
}

// ===========================================================================
// Dangerous Extension Action
// ===========================================================================

/// What to do when a dangerous file extension is detected in email attachments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DangerousExtAction {
    LogOnly,
    FlagNotify,
    AutoQuarantine,
}

// ===========================================================================
// Protected Path Scope
// ===========================================================================

/// How many protected paths to monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedPathScope {
    /// Only ~/.ssh, ~/.gnupg (minimum)
    Core,
    /// Full default set (wallets, .env, Photos, etc.)
    Default,
    /// Full default set + user-configured custom paths
    DefaultPlusCustom,
}

// ===========================================================================
// Effective Security Config — the resolved, flat output
// ===========================================================================

/// Fully resolved security configuration. Produced by `SecurityConfig::resolve_effective()`.
///
/// This is the single source of truth that both Swift (via FFI JSON) and the Linux daemon
/// read from. All tier logic, overrides, floor enforcement, and mode adjustments are
/// already applied — consumers just read fields directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveSecurityConfig {
    // -- Tier identity --
    pub protection_tier: ProtectionTier,

    // -- Quarantine --
    pub auto_quarantine: bool,
    pub auto_quarantine_min_severity: SeverityLevel,

    // -- File watcher --
    pub file_watcher_enabled: bool,
    pub file_watcher_directories: Vec<String>,

    // -- Clipboard --
    pub clipboard_monitoring_enabled: bool,
    pub clipboard_interval_ms: u64,

    // -- Email --
    pub email_scanning_enabled: bool,
    pub email_intent_enabled: bool,
    pub email_intent_threshold: u8,
    pub email_intent_threshold_whitelisted: u8,

    // -- Messages --
    pub messages_scanning_enabled: bool,
    pub messages_scan_interval_ms: u64,

    // -- Scheduled scan --
    pub scheduled_scan_enabled: bool,
    pub scheduled_scan_interval_hours: u32,

    // -- Notifications --
    pub notifications_enabled: bool,
    pub notifications_external_min_severity: SeverityLevel,

    // -- Whitelist policy --
    pub whitelist_bypass_max_severity: SeverityLevel,

    // -- Dangerous extensions --
    pub dangerous_ext_action: DangerousExtAction,

    // -- Protected paths --
    pub protected_path_scope: ProtectedPathScope,

    // -- Floor controls (always enforced) --
    pub always_forbidden_enabled: bool,
    pub vault_rate_limiting_enabled: bool,
    pub self_protection_enabled: bool,
    pub auto_reencrypt_enabled: bool,
    pub auto_reencrypt_timeout_minutes: u32,
    pub startup_scan_enabled: bool,
    pub audit_logging_enabled: bool,
}

impl EffectiveSecurityConfig {
    /// Relaxed tier: quiet safety net, minimal interruption.
    pub fn relaxed_defaults() -> Self {
        let resolver = PathResolver::new();
        Self {
            protection_tier: ProtectionTier::Relaxed,

            auto_quarantine: false,
            auto_quarantine_min_severity: SeverityLevel::Critical,

            file_watcher_enabled: true,
            file_watcher_directories: vec![resolver.downloads_dir().to_string()],

            clipboard_monitoring_enabled: false,
            clipboard_interval_ms: 5000,

            email_scanning_enabled: true,
            email_intent_enabled: false, // pattern-only
            email_intent_threshold: 5,
            email_intent_threshold_whitelisted: 5,

            messages_scanning_enabled: false,
            messages_scan_interval_ms: 60000,

            scheduled_scan_enabled: false,
            scheduled_scan_interval_hours: 12,

            notifications_enabled: true,
            notifications_external_min_severity: SeverityLevel::Critical,

            whitelist_bypass_max_severity: SeverityLevel::High,

            dangerous_ext_action: DangerousExtAction::LogOnly,

            protected_path_scope: ProtectedPathScope::Core,

            // Floor controls — always true
            always_forbidden_enabled: true,
            vault_rate_limiting_enabled: true,
            self_protection_enabled: true,
            auto_reencrypt_enabled: true,
            auto_reencrypt_timeout_minutes: 30,
            startup_scan_enabled: true,
            audit_logging_enabled: true,
        }
    }

    /// Balanced tier: recommended default. Block critical, ask about medium.
    pub fn balanced_defaults() -> Self {
        let resolver = PathResolver::new();
        Self {
            protection_tier: ProtectionTier::Balanced,

            auto_quarantine: true,
            auto_quarantine_min_severity: SeverityLevel::Critical,

            file_watcher_enabled: true,
            file_watcher_directories: resolver
                .default_monitored_dirs()
                .iter()
                .map(|s| s.to_string())
                .collect(),

            clipboard_monitoring_enabled: true,
            clipboard_interval_ms: 5000,

            email_scanning_enabled: true,
            email_intent_enabled: true,
            email_intent_threshold: 3,
            email_intent_threshold_whitelisted: 5,

            messages_scanning_enabled: true,
            messages_scan_interval_ms: 60000,

            scheduled_scan_enabled: true,
            scheduled_scan_interval_hours: 12,

            notifications_enabled: true,
            notifications_external_min_severity: SeverityLevel::High,

            whitelist_bypass_max_severity: SeverityLevel::Medium,

            dangerous_ext_action: DangerousExtAction::FlagNotify,

            protected_path_scope: ProtectedPathScope::Default,

            // Floor controls
            always_forbidden_enabled: true,
            vault_rate_limiting_enabled: true,
            self_protection_enabled: true,
            auto_reencrypt_enabled: true,
            auto_reencrypt_timeout_minutes: 30,
            startup_scan_enabled: true,
            audit_logging_enabled: true,
        }
    }

    /// Strict tier: maximum enforcement, everything monitored.
    pub fn strict_defaults() -> Self {
        let resolver = PathResolver::new();
        let mut dirs: Vec<String> = resolver
            .default_monitored_dirs()
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Add ~/Desktop for strict mode
        dirs.push(resolver.desktop_dir().to_string());

        Self {
            protection_tier: ProtectionTier::Strict,

            auto_quarantine: true,
            auto_quarantine_min_severity: SeverityLevel::High,

            file_watcher_enabled: true,
            file_watcher_directories: dirs,

            clipboard_monitoring_enabled: true,
            clipboard_interval_ms: 2000,

            email_scanning_enabled: true,
            email_intent_enabled: true,
            email_intent_threshold: 2,
            email_intent_threshold_whitelisted: 4,

            messages_scanning_enabled: true,
            messages_scan_interval_ms: 30000,

            scheduled_scan_enabled: true,
            scheduled_scan_interval_hours: 6,

            notifications_enabled: true,
            notifications_external_min_severity: SeverityLevel::Medium,

            whitelist_bypass_max_severity: SeverityLevel::Low,

            dangerous_ext_action: DangerousExtAction::AutoQuarantine,

            protected_path_scope: ProtectedPathScope::DefaultPlusCustom,

            // Floor controls
            always_forbidden_enabled: true,
            vault_rate_limiting_enabled: true,
            self_protection_enabled: true,
            auto_reencrypt_enabled: true,
            auto_reencrypt_timeout_minutes: 30,
            startup_scan_enabled: true,
            audit_logging_enabled: true,
        }
    }

    /// Enforce the security floor — unconditionally force floor controls ON.
    /// This is the final step after tier defaults + overrides. Cannot be bypassed.
    pub fn enforce_floor(&mut self) {
        self.always_forbidden_enabled = true;
        self.vault_rate_limiting_enabled = true;
        self.self_protection_enabled = true;
        self.auto_reencrypt_enabled = true;
        self.startup_scan_enabled = true;
        self.audit_logging_enabled = true;
        // Floor minimum: auto-reencrypt timeout cannot exceed 30 minutes
        if self.auto_reencrypt_timeout_minutes > 30 {
            self.auto_reencrypt_timeout_minutes = 30;
        }
    }

    /// Apply optional user overrides from the [overrides] TOML section.
    /// Floor controls cannot be weakened (silently ignored).
    pub fn apply_overrides(&mut self, overrides: &OverridesConfig) {
        if let Some(v) = overrides.auto_quarantine {
            self.auto_quarantine = v;
        }
        if let Some(v) = overrides.clipboard_monitoring_enabled {
            self.clipboard_monitoring_enabled = v;
        }
        if let Some(v) = overrides.clipboard_interval_ms {
            self.clipboard_interval_ms = v;
        }
        if let Some(v) = overrides.email_intent_enabled {
            self.email_intent_enabled = v;
        }
        if let Some(v) = overrides.email_intent_threshold {
            self.email_intent_threshold = v;
        }
        if let Some(v) = overrides.messages_scanning_enabled {
            self.messages_scanning_enabled = v;
        }
        if let Some(v) = overrides.messages_scan_interval_ms {
            self.messages_scan_interval_ms = v;
        }
        if let Some(v) = overrides.scheduled_scan_enabled {
            self.scheduled_scan_enabled = v;
        }
        if let Some(v) = overrides.scheduled_scan_interval_hours {
            self.scheduled_scan_interval_hours = v;
        }
        // Floor controls: overrides that try to weaken them are silently ignored.
        // enforce_floor() runs AFTER this method, so even if set here, they'll be forced back.
    }
}

// ===========================================================================
// Overrides Config — optional TOML [overrides] section
// ===========================================================================

/// Optional per-control overrides within the selected tier.
/// All fields are Option — only set fields are applied.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OverridesConfig {
    pub auto_quarantine: Option<bool>,
    pub clipboard_monitoring_enabled: Option<bool>,
    pub clipboard_interval_ms: Option<u64>,
    pub email_intent_enabled: Option<bool>,
    pub email_intent_threshold: Option<u8>,
    pub messages_scanning_enabled: Option<bool>,
    pub messages_scan_interval_ms: Option<u64>,
    pub scheduled_scan_enabled: Option<bool>,
    pub scheduled_scan_interval_hours: Option<u32>,
}

// ===========================================================================
// Top-level Configuration — TOML structure
// ===========================================================================

/// Top-level configuration — reads from config.toml with env var overrides.
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
    pub overrides: OverridesConfig,
    pub model_verification: ModelVerificationConfig,
    pub command_policy: crate::command_policy::CommandPolicyConfig,

    // ── Phase 15: NemoClaw-inspired interpositional controls ──
    pub privacy_router: crate::privacy_router::PrivacyRouterConfig,
    pub intent_verifier: crate::intent_verifier::IntentVerifierConfig,
    pub model_vetting: crate::model_vetting::ModelVettingConfig,
    /// Map of agent name → per-agent policy. Serialized under `[agents.*]`.
    #[serde(default)]
    pub agents: std::collections::HashMap<String, crate::agent_policy::AgentPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ModelVerificationConfig {
    pub enabled: bool,
    pub paths: Vec<String>,
    pub ignore_paths: Vec<String>,
    pub verify_interval_hours: u32,
}

impl Default for ModelVerificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: Vec::new(),
            ignore_paths: Vec::new(), // paths to skip tamper alerts for (actively developed models)
            verify_interval_hours: 6,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub mode: String,
    pub protection_tier: ProtectionTier,
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
            overrides: OverridesConfig::default(),
            model_verification: ModelVerificationConfig::default(),
            command_policy: crate::command_policy::CommandPolicyConfig::default(),
            privacy_router: crate::privacy_router::PrivacyRouterConfig::default(),
            intent_verifier: crate::intent_verifier::IntentVerifierConfig::default(),
            model_vetting: crate::model_vetting::ModelVettingConfig::default(),
            agents: std::collections::HashMap::new(),
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: "PRODUCTION".to_string(),
            protection_tier: ProtectionTier::Balanced,
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
        if let Ok(v) = std::env::var("MACSEC_PROTECTION_TIER") {
            if let Some(tier) = ProtectionTier::from_str_loose(&v) {
                self.general.protection_tier = tier;
            }
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

    /// Resolve the effective security configuration.
    ///
    /// Combines: tier defaults → user overrides → floor enforcement → mode adjustments.
    /// The returned EffectiveSecurityConfig is the single source of truth.
    pub fn resolve_effective(&self) -> EffectiveSecurityConfig {
        // 1. Start with tier defaults
        let mut eff = match self.general.protection_tier {
            ProtectionTier::Relaxed => EffectiveSecurityConfig::relaxed_defaults(),
            ProtectionTier::Balanced => EffectiveSecurityConfig::balanced_defaults(),
            ProtectionTier::Strict => EffectiveSecurityConfig::strict_defaults(),
        };

        // 2. Apply optional [overrides] section
        eff.apply_overrides(&self.overrides);

        // 3. Enforce security floor (unconditional, final step)
        eff.enforce_floor();

        // 4. Mode adjustments — deployment context overrides
        // In TESTING or DEVELOPMENT, auto-quarantine is always off
        if !self.is_production() {
            eff.auto_quarantine = false;
        }

        eff
    }
}

/// Atomically update the protection_tier field in a config.toml file.
/// Reads the file, finds/inserts the protection_tier line, writes atomically.
pub fn set_protection_tier_in_file(config_path: &str, tier: ProtectionTier) -> Result<(), String> {
    let content = std::fs::read_to_string(config_path)
        .unwrap_or_else(|_| "[general]\n".to_string());

    let tier_line = format!("protection_tier = \"{}\"", tier.as_str());
    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut found = false;
    let mut in_general = false;
    let mut general_end_idx = None;

    for (i, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[general]" {
            in_general = true;
            general_end_idx = Some(i + 1);
            continue;
        }
        if in_general {
            if trimmed.starts_with('[') {
                // Hit next section — insert before it if not found
                break;
            }
            if trimmed.starts_with("protection_tier") {
                *line = tier_line.clone();
                found = true;
                break;
            }
            general_end_idx = Some(i + 1);
        }
    }

    if !found {
        if let Some(idx) = general_end_idx {
            lines.insert(idx, tier_line);
        } else {
            // No [general] section at all — add one
            lines.insert(0, "[general]".to_string());
            lines.insert(1, tier_line);
        }
    }

    let new_content = lines.join("\n") + "\n";

    // Atomic write: write to tmp then rename
    let tmp_path = format!("{}.tmp", config_path);
    std::fs::write(&tmp_path, &new_content)
        .map_err(|e| format!("Failed to write tmp config: {}", e))?;
    std::fs::rename(&tmp_path, config_path)
        .map_err(|e| format!("Failed to rename config: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SecurityConfig::default();
        assert_eq!(config.general.mode, "PRODUCTION");
        assert_eq!(config.general.protection_tier, ProtectionTier::Balanced);
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
    fn parse_toml_with_protection_tier() {
        let toml = r#"
[general]
mode = "PRODUCTION"
protection_tier = "strict"
"#;
        let config: SecurityConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.general.protection_tier, ProtectionTier::Strict);
    }

    #[test]
    fn parse_toml_without_protection_tier_defaults_to_balanced() {
        let toml = r#"
[general]
mode = "PRODUCTION"
"#;
        let config: SecurityConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.general.protection_tier, ProtectionTier::Balanced);
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

    // -- Protection Tier tests --

    #[test]
    fn tier_from_str_loose() {
        assert_eq!(ProtectionTier::from_str_loose("relaxed"), Some(ProtectionTier::Relaxed));
        assert_eq!(ProtectionTier::from_str_loose("BALANCED"), Some(ProtectionTier::Balanced));
        assert_eq!(ProtectionTier::from_str_loose("Strict"), Some(ProtectionTier::Strict));
        assert_eq!(ProtectionTier::from_str_loose("unknown"), None);
    }

    #[test]
    fn tier_level_ordering() {
        assert!(ProtectionTier::Relaxed.level() < ProtectionTier::Balanced.level());
        assert!(ProtectionTier::Balanced.level() < ProtectionTier::Strict.level());
    }

    // -- Effective Config tests --

    #[test]
    fn relaxed_tier_defaults() {
        let eff = EffectiveSecurityConfig::relaxed_defaults();
        assert_eq!(eff.protection_tier, ProtectionTier::Relaxed);
        assert!(!eff.auto_quarantine);
        assert!(!eff.clipboard_monitoring_enabled);
        assert!(!eff.email_intent_enabled);
        assert!(!eff.messages_scanning_enabled);
        assert!(!eff.scheduled_scan_enabled);
        // Floor controls always true
        assert!(eff.always_forbidden_enabled);
        assert!(eff.vault_rate_limiting_enabled);
        assert!(eff.self_protection_enabled);
        assert!(eff.auto_reencrypt_enabled);
        assert!(eff.startup_scan_enabled);
        assert!(eff.audit_logging_enabled);
        // File watcher still on (Downloads only)
        assert!(eff.file_watcher_enabled);
        assert_eq!(eff.file_watcher_directories.len(), 1);
    }

    #[test]
    fn balanced_tier_defaults() {
        let eff = EffectiveSecurityConfig::balanced_defaults();
        assert_eq!(eff.protection_tier, ProtectionTier::Balanced);
        assert!(eff.auto_quarantine);
        assert_eq!(eff.auto_quarantine_min_severity, SeverityLevel::Critical);
        assert!(eff.clipboard_monitoring_enabled);
        assert_eq!(eff.clipboard_interval_ms, 5000);
        assert!(eff.email_intent_enabled);
        assert_eq!(eff.email_intent_threshold, 3);
        assert_eq!(eff.email_intent_threshold_whitelisted, 5);
        assert!(eff.messages_scanning_enabled);
        assert!(eff.scheduled_scan_enabled);
        assert_eq!(eff.scheduled_scan_interval_hours, 12);
    }

    #[test]
    fn strict_tier_defaults() {
        let eff = EffectiveSecurityConfig::strict_defaults();
        assert_eq!(eff.protection_tier, ProtectionTier::Strict);
        assert!(eff.auto_quarantine);
        assert_eq!(eff.auto_quarantine_min_severity, SeverityLevel::High);
        assert!(eff.clipboard_monitoring_enabled);
        assert_eq!(eff.clipboard_interval_ms, 2000);
        assert_eq!(eff.email_intent_threshold, 2);
        assert_eq!(eff.email_intent_threshold_whitelisted, 4);
        assert_eq!(eff.messages_scan_interval_ms, 30000);
        assert_eq!(eff.scheduled_scan_interval_hours, 6);
        assert_eq!(eff.dangerous_ext_action, DangerousExtAction::AutoQuarantine);
    }

    #[test]
    fn floor_cannot_be_weakened() {
        let mut eff = EffectiveSecurityConfig::relaxed_defaults();
        // Try to weaken floor controls
        eff.always_forbidden_enabled = false;
        eff.vault_rate_limiting_enabled = false;
        eff.self_protection_enabled = false;
        eff.auto_reencrypt_enabled = false;
        eff.startup_scan_enabled = false;
        eff.audit_logging_enabled = false;
        eff.auto_reencrypt_timeout_minutes = 120; // try to extend timeout

        // Enforce floor
        eff.enforce_floor();

        // All floor controls forced back to true
        assert!(eff.always_forbidden_enabled);
        assert!(eff.vault_rate_limiting_enabled);
        assert!(eff.self_protection_enabled);
        assert!(eff.auto_reencrypt_enabled);
        assert!(eff.startup_scan_enabled);
        assert!(eff.audit_logging_enabled);
        assert_eq!(eff.auto_reencrypt_timeout_minutes, 30);
    }

    #[test]
    fn resolve_effective_balanced() {
        let config = SecurityConfig::default();
        let eff = config.resolve_effective();
        assert_eq!(eff.protection_tier, ProtectionTier::Balanced);
        assert!(eff.auto_quarantine); // PRODUCTION mode, Balanced tier
        assert!(eff.clipboard_monitoring_enabled);
        assert!(eff.email_intent_enabled);
    }

    #[test]
    fn resolve_effective_testing_mode_disables_quarantine() {
        let mut config = SecurityConfig::default();
        config.general.mode = "TESTING".to_string();
        config.general.protection_tier = ProtectionTier::Strict;
        let eff = config.resolve_effective();
        // Strict tier wants quarantine, but TESTING mode overrides
        assert!(!eff.auto_quarantine);
    }

    #[test]
    fn resolve_effective_with_overrides() {
        let mut config = SecurityConfig::default();
        config.general.protection_tier = ProtectionTier::Balanced;
        config.overrides.clipboard_monitoring_enabled = Some(false);
        config.overrides.scheduled_scan_interval_hours = Some(24);
        let eff = config.resolve_effective();
        assert!(!eff.clipboard_monitoring_enabled); // overridden
        assert_eq!(eff.scheduled_scan_interval_hours, 24); // overridden
        // Floor controls still enforced
        assert!(eff.always_forbidden_enabled);
    }

    #[test]
    fn effective_config_json_roundtrip() {
        let eff = EffectiveSecurityConfig::balanced_defaults();
        let json = serde_json::to_string(&eff).unwrap();
        let back: EffectiveSecurityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protection_tier, eff.protection_tier);
        assert_eq!(back.auto_quarantine, eff.auto_quarantine);
        assert_eq!(back.email_intent_threshold, eff.email_intent_threshold);
        assert_eq!(back.clipboard_interval_ms, eff.clipboard_interval_ms);
    }

    #[test]
    fn protection_tier_serde() {
        let json = "\"relaxed\"";
        let tier: ProtectionTier = serde_json::from_str(json).unwrap();
        assert_eq!(tier, ProtectionTier::Relaxed);

        let back = serde_json::to_string(&tier).unwrap();
        assert_eq!(back, "\"relaxed\"");
    }

    #[test]
    fn set_protection_tier_in_file_works() {
        let dir = std::env::temp_dir().join("aisec_test_tier");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        std::fs::write(&path, "[general]\nmode = \"PRODUCTION\"\nprotection_tier = \"balanced\"\n").unwrap();

        set_protection_tier_in_file(path.to_str().unwrap(), ProtectionTier::Strict).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("protection_tier = \"strict\""));
        assert!(content.contains("mode = \"PRODUCTION\""));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_protection_tier_in_file_inserts_if_missing() {
        let dir = std::env::temp_dir().join("aisec_test_tier2");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        std::fs::write(&path, "[general]\nmode = \"PRODUCTION\"\n").unwrap();

        set_protection_tier_in_file(path.to_str().unwrap(), ProtectionTier::Relaxed).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("protection_tier = \"relaxed\""));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
