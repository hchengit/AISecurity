import Foundation
import TOMLKit

/// Security operating mode — deployment context (set by developer/deployer).
enum SecurityMode: String, Codable, Sendable {
    case production  = "PRODUCTION"   // Maximum security — all alerts, auto-quarantine
    case testing     = "TESTING"      // Alert but do NOT quarantine
    case development = "DEVELOPMENT"  // Logging only
}

/// User-facing protection tier — monitoring aggressiveness (set by end user).
/// Orthogonal to SecurityMode: mode = deployment context, tier = user preference.
enum ProtectionTier: String, Codable, Sendable, CaseIterable {
    case relaxed  = "relaxed"    // Baseline safety net, minimal interruption
    case balanced = "balanced"   // Recommended default — block critical, ask about medium
    case strict   = "strict"     // Maximum enforcement, everything monitored

    /// Map from Rust FFI value (0/1/2).
    static func from(rawValue: Int) -> ProtectionTier {
        switch rawValue {
        case 0:  return .relaxed
        case 2:  return .strict
        default: return .balanced
        }
    }

    /// Numeric value to pass to Rust FFI.
    var rustValue: Int {
        switch self {
        case .relaxed:  return 0
        case .balanced: return 1
        case .strict:   return 2
        }
    }

    /// Int-based tag for NSMenuItem (needed since raw type is now String).
    var menuTag: Int { rustValue }

    var displayName: String {
        switch self {
        case .relaxed:  return "Relaxed"
        case .balanced: return "Balanced"
        case .strict:   return "Strict"
        }
    }

    var description: String {
        switch self {
        case .relaxed:  return "Baseline monitoring"
        case .balanced: return "Recommended"
        case .strict:   return "Maximum enforcement"
        }
    }

    var menuBarIcon: String {
        switch self {
        case .relaxed:  return "shield"
        case .balanced: return "shield.lefthalf.filled"
        case .strict:   return "lock.shield"
        }
    }

    /// Whether this tier is less restrictive than another.
    func isDowngradeFrom(_ other: ProtectionTier) -> Bool {
        rustValue < other.rustValue
    }
}

/// Fully resolved security configuration from Rust.
/// Produced by `SecurityCoreBridge.getEffectiveConfig()`.
/// All tier logic, overrides, and floor enforcement are already applied.
struct EffectiveSecurityConfig: Codable, Sendable {
    // Tier identity
    let protectionTier: ProtectionTier

    // Quarantine
    let autoQuarantine: Bool
    let autoQuarantineMinSeverity: String  // "CRITICAL", "HIGH", etc.

    // File watcher
    let fileWatcherEnabled: Bool
    let fileWatcherDirectories: [String]

    // Clipboard
    let clipboardMonitoringEnabled: Bool
    let clipboardIntervalMs: UInt64

    // Email
    let emailScanningEnabled: Bool
    let emailIntentEnabled: Bool
    let emailIntentThreshold: UInt8
    let emailIntentThresholdWhitelisted: UInt8

    // Messages
    let messagesScanningEnabled: Bool
    let messagesScanIntervalMs: UInt64

    // Scheduled scan
    let scheduledScanEnabled: Bool
    let scheduledScanIntervalHours: UInt32

    // Notifications
    let notificationsEnabled: Bool
    let notificationsExternalMinSeverity: String

    // Whitelist
    let whitelistBypassMaxSeverity: String

    // Dangerous extensions
    let dangerousExtAction: String  // "log_only", "flag_notify", "auto_quarantine"

    // Protected paths
    let protectedPathScope: String  // "core", "default", "default_plus_custom"

    // Floor controls (always true)
    let alwaysForbiddenEnabled: Bool
    let vaultRateLimitingEnabled: Bool
    let selfProtectionEnabled: Bool
    let autoReencryptEnabled: Bool
    let autoReencryptTimeoutMinutes: UInt32
    let startupScanEnabled: Bool
    let auditLoggingEnabled: Bool

    // JSON key mapping: Rust uses snake_case, Swift uses camelCase
    enum CodingKeys: String, CodingKey {
        case protectionTier = "protection_tier"
        case autoQuarantine = "auto_quarantine"
        case autoQuarantineMinSeverity = "auto_quarantine_min_severity"
        case fileWatcherEnabled = "file_watcher_enabled"
        case fileWatcherDirectories = "file_watcher_directories"
        case clipboardMonitoringEnabled = "clipboard_monitoring_enabled"
        case clipboardIntervalMs = "clipboard_interval_ms"
        case emailScanningEnabled = "email_scanning_enabled"
        case emailIntentEnabled = "email_intent_enabled"
        case emailIntentThreshold = "email_intent_threshold"
        case emailIntentThresholdWhitelisted = "email_intent_threshold_whitelisted"
        case messagesScanningEnabled = "messages_scanning_enabled"
        case messagesScanIntervalMs = "messages_scan_interval_ms"
        case scheduledScanEnabled = "scheduled_scan_enabled"
        case scheduledScanIntervalHours = "scheduled_scan_interval_hours"
        case notificationsEnabled = "notifications_enabled"
        case notificationsExternalMinSeverity = "notifications_external_min_severity"
        case whitelistBypassMaxSeverity = "whitelist_bypass_max_severity"
        case dangerousExtAction = "dangerous_ext_action"
        case protectedPathScope = "protected_path_scope"
        case alwaysForbiddenEnabled = "always_forbidden_enabled"
        case vaultRateLimitingEnabled = "vault_rate_limiting_enabled"
        case selfProtectionEnabled = "self_protection_enabled"
        case autoReencryptEnabled = "auto_reencrypt_enabled"
        case autoReencryptTimeoutMinutes = "auto_reencrypt_timeout_minutes"
        case startupScanEnabled = "startup_scan_enabled"
        case auditLoggingEnabled = "audit_logging_enabled"
    }
}

/// Central configuration — reads from config.toml with env var overrides.
///
/// Override priority: environment variable > config.toml > built-in default
/// Config file location: ~/.mac-security/config.toml (or MACSEC_SECURITY_DIR/config.toml)
struct SecurityConfig: Sendable {
    static let shared = SecurityConfig()

    let mode: SecurityMode
    let protectionTier: ProtectionTier
    let home: String
    let securityDir: String
    let configFilePath: String
    let paths: PathResolver

    // ── File Watcher ────────────────────────────────────────────────
    struct FileWatcherConfig: Sendable {
        let enabled: Bool
        let monitoredDirectories: [String]
        let maxScanSizeBytes: Int
        let debounceMs: Int
    }
    let fileWatcher: FileWatcherConfig

    // ── External File Sanitizer ─────────────────────────────────────
    struct ExternalFileSanitizerConfig: Sendable {
        let enabled: Bool
        let autoQuarantine: Bool
        let quarantineDir: String
        let scanDownloadsOnStart: Bool
    }
    let externalFileSanitizer: ExternalFileSanitizerConfig

    // ── Prompt Injection Guard ──────────────────────────────────────
    struct PromptInjectionGuardConfig: Sendable {
        let enabled: Bool
        let clipboardMonitorIntervalMs: Int
    }
    let promptInjectionGuard: PromptInjectionGuardConfig

    // ── Sensitive Data Detector ─────────────────────────────────────
    struct SensitiveDataDetectorConfig: Sendable {
        let enabled: Bool
        let criticalCategories: [String]
        let alertSeverity: SeverityLevel
    }
    let sensitiveDataDetector: SensitiveDataDetectorConfig

    // ── Email Scanner ───────────────────────────────────────────────
    struct EmailScannerConfig: Sendable {
        let enabled: Bool
        let mailDir: String
        let alertCategories: [String]
        let startupScanLimit: Int
    }
    let emailScanner: EmailScannerConfig

    // ── Always Forbidden ────────────────────────────────────────────
    struct AlwaysForbiddenConfig: Sendable {
        let walletKeyAccess: Bool
        let creditCardTransmission: Bool
        let ssnTransmission: Bool
        let driversLicenseUpload: Bool
        let photosLibraryUpload: Bool
        let keychainDump: Bool
        let envFileUpload: Bool
        let privatePemKeyUpload: Bool
        let turboTaxUpload: Bool
    }
    let alwaysForbidden: AlwaysForbiddenConfig

    // ── Audit ───────────────────────────────────────────────────────
    struct AuditConfig: Sendable {
        let logDir: String
        let logBlockedOperations: Bool
        let logAlerts: Bool
        let maxLogAgeDays: Int
    }
    let audit: AuditConfig

    // ── Notifications ───────────────────────────────────────────────
    struct NotificationsConfig: Sendable {
        let enabled: Bool
        let criticalOnly: Bool
    }
    let notifications: NotificationsConfig

    // ── Scheduled Scan ──────────────────────────────────────────────
    struct ScheduledScanConfig: Sendable {
        let enabled: Bool
        let intervalHours: Int
        let scanDirectories: [String]
    }
    let scheduledScan: ScheduledScanConfig

    // ── Messages Scanner ────────────────────────────────────────────
    struct MessagesScannerConfig: Sendable {
        let enabled: Bool
        let messagesDb: String
    }
    let messagesScanner: MessagesScannerConfig

    // ── Python .pth Watcher (Phase 16 A) ────────────────────────────
    struct PythonPthWatcherConfig: Sendable {
        let enabled: Bool
    }
    let pythonPthWatcher: PythonPthWatcherConfig

    // ── Dependency Drift Watcher (Phase 16 B) ───────────────────────
    struct DependencyDriftConfig: Sendable {
        let enabled: Bool
        let projectRoots: [String]
        let maxDepth: Int
    }
    let dependencyDrift: DependencyDriftConfig

    // ── Persistence Path Watcher (Phase 16 D) ───────────────────────
    struct PersistencePathsConfig: Sendable {
        let enabled: Bool
    }
    let persistencePaths: PersistencePathsConfig

    // ── Helpers ─────────────────────────────────────────────────────
    var isProduction: Bool  { mode == .production }
    var isTesting: Bool     { mode == .testing }
    var isDevelopment: Bool  { mode == .development }
    var shouldQuarantine: Bool { externalFileSanitizer.autoQuarantine }

    // ── TOML Helpers ────────────────────────────────────────────────

    /// Load config.toml from the security directory, if it exists.
    private static func loadTOML() -> TOMLTable? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Determine security dir (env > default) to find config.toml
        let secDir: String
        if let env = ProcessInfo.processInfo.environment["MACSEC_SECURITY_DIR"], !env.isEmpty {
            secDir = env.hasPrefix("~/") ? (home as NSString).appendingPathComponent(String(env.dropFirst(2))) : env
        } else {
            secDir = (home as NSString).appendingPathComponent(".mac-security")
        }

        let configPath = (secDir as NSString).appendingPathComponent("config.toml")
        guard FileManager.default.fileExists(atPath: configPath),
              let contents = try? String(contentsOfFile: configPath, encoding: .utf8) else {
            return nil
        }

        // Verify config file ownership and permissions (security hardening)
        Self.verifyConfigIntegrity(secDir: secDir, configPath: configPath)

        return try? TOMLTable(string: contents)
    }

    /// Safely read a string from a TOML table path like ["paths", "mail_dir"].
    private static func tomlString(_ table: TOMLTable?, _ section: String, _ key: String) -> String? {
        guard let table = table,
              let sec = table[section] as? TOMLTable,
              let val = sec[key] else { return nil }
        return "\(val)"
    }

    /// Safely read an int from a TOML table.
    private static func tomlInt(_ table: TOMLTable?, _ section: String, _ key: String) -> Int? {
        guard let table = table,
              let sec = table[section] as? TOMLTable,
              let val = sec[key] as? TOMLInt else { return nil }
        return val.int
    }

    /// Safely read a bool from a TOML table.
    private static func tomlBool(_ table: TOMLTable?, _ section: String, _ key: String) -> Bool? {
        guard let table = table,
              let sec = table[section] as? TOMLTable,
              let val = sec[key] as? Bool else { return nil }
        return val
    }

    /// Safely read a string array from a TOML table.
    private static func tomlStringArray(_ table: TOMLTable?, _ section: String, _ key: String) -> [String]? {
        guard let table = table,
              let sec = table[section] as? TOMLTable,
              let arr = sec[key] as? TOMLArray else { return nil }
        var result: [String] = []
        for i in 0..<arr.count {
            if let s = arr[i] as? String {
                result.append(s)
            } else {
                result.append("\(arr[i])")
            }
        }
        return result.isEmpty ? nil : result
    }

    // ── Config Integrity Check ──────────────────────────────────────

    /// Verify config file ownership and permissions to detect tampering.
    /// Alerts if config is writable by group/other or owned by another user.
    private static func verifyConfigIntegrity(secDir: String, configPath: String) {
        let fm = FileManager.default

        // Check security directory permissions
        for path in [secDir, configPath] {
            guard let attrs = try? fm.attributesOfItem(atPath: path) else { continue }

            // Verify owner is current user
            if let ownerID = attrs[.ownerAccountID] as? NSNumber {
                let currentUID = getuid()
                if ownerID.uint32Value != currentUID {
                    NSLog("[AISecurity] WARNING: %@ owned by uid %d, expected %d — possible tampering",
                          path, ownerID.uint32Value, currentUID)
                }
            }

            // Check permissions — should be 0700 (dir) or 0600 (file)
            if let posix = attrs[.posixPermissions] as? NSNumber {
                let mode = posix.uint16Value
                let groupOtherBits = mode & 0o077
                if groupOtherBits != 0 {
                    NSLog("[AISecurity] WARNING: %@ is accessible by group/other (mode %o) — hardening to owner-only", path, mode)
                    // Auto-harden: strip group/other permissions
                    let isDir = (attrs[.type] as? FileAttributeType) == .typeDirectory
                    let safeMode: UInt16 = isDir ? 0o700 : 0o600
                    try? fm.setAttributes([.posixPermissions: NSNumber(value: safeMode)], ofItemAtPath: path)
                }
            }
        }

        // Verify notification config permissions too
        let notifConfigPath = (secDir as NSString).appendingPathComponent("notification-config.json")
        if fm.fileExists(atPath: notifConfigPath) {
            if let attrs = try? fm.attributesOfItem(atPath: notifConfigPath),
               let posix = attrs[.posixPermissions] as? NSNumber {
                let mode = posix.uint16Value
                if mode & 0o077 != 0 {
                    NSLog("[AISecurity] WARNING: notification-config.json is accessible by group/other — hardening")
                    try? fm.setAttributes([.posixPermissions: NSNumber(value: UInt16(0o600))], ofItemAtPath: notifConfigPath)
                }
            }
        }
    }

    // ── Init with TOML + env var support ────────────────────────────
    init() {
        let toml = Self.loadTOML()

        // Mode: env > toml > default
        let envMode = ProcessInfo.processInfo.environment["MACSEC_MODE"]
            ?? ProcessInfo.processInfo.environment["MAC_SECURITY_MODE"]  // backwards compat
        let tomlMode = Self.tomlString(toml, "general", "mode")
        self.mode = SecurityMode(rawValue: envMode ?? tomlMode ?? "PRODUCTION") ?? .production

        // Protection Tier: env > toml > default (balanced)
        let envTier = ProcessInfo.processInfo.environment["MACSEC_PROTECTION_TIER"]
        let tomlTier = Self.tomlString(toml, "general", "protection_tier")
        let tierStr = envTier ?? tomlTier ?? "balanced"
        switch tierStr.lowercased() {
        case "relaxed":  self.protectionTier = .relaxed
        case "strict":   self.protectionTier = .strict
        default:         self.protectionTier = .balanced
        }

        // PathResolver handles all path resolution with env > toml > default
        let resolver = PathResolver(
            configSecurityDir: Self.tomlString(toml, "paths", "security_dir"),
            configMailDir: Self.tomlString(toml, "paths", "mail_dir"),
            configMessagesDb: Self.tomlString(toml, "paths", "messages_db"),
            configQuarantineDir: Self.tomlString(toml, "paths", "quarantine_dir"),
            configLogDir: Self.tomlString(toml, "paths", "log_dir"),
            configMonitoredDirs: Self.tomlStringArray(toml, "file_watcher", "monitored_directories"),
            configScheduledScanDirs: Self.tomlStringArray(toml, "scheduled_scan", "scan_directories"),
            configProtectedPaths: Self.tomlStringArray(toml, "protected_paths", "paths")
        )
        self.paths = resolver
        self.home = resolver.home
        self.securityDir = resolver.securityDir
        self.configFilePath = (resolver.securityDir as NSString).appendingPathComponent("config.toml")

        // ── File Watcher ────────────────────────────────────────────
        self.fileWatcher = FileWatcherConfig(
            enabled: Self.tomlBool(toml, "file_watcher", "enabled") ?? true,
            monitoredDirectories: resolver.monitoredDirectories,
            maxScanSizeBytes: Self.tomlInt(toml, "file_watcher", "max_scan_size_bytes") ?? 5 * 1024 * 1024,
            debounceMs: Self.tomlInt(toml, "file_watcher", "debounce_ms") ?? 300
        )

        // ── External File Sanitizer ─────────────────────────────────
        self.externalFileSanitizer = ExternalFileSanitizerConfig(
            enabled: Self.tomlBool(toml, "external_file_sanitizer", "enabled") ?? true,
            autoQuarantine: mode == .production,
            quarantineDir: resolver.quarantineDir,
            scanDownloadsOnStart: Self.tomlBool(toml, "external_file_sanitizer", "scan_downloads_on_start") ?? true
        )

        // ── Prompt Injection Guard ──────────────────────────────────
        self.promptInjectionGuard = PromptInjectionGuardConfig(
            enabled: Self.tomlBool(toml, "prompt_injection_guard", "enabled") ?? true,
            clipboardMonitorIntervalMs: Self.tomlInt(toml, "prompt_injection_guard", "clipboard_monitor_interval_ms") ?? 2000
        )

        // ── Sensitive Data Detector ─────────────────────────────────
        self.sensitiveDataDetector = SensitiveDataDetectorConfig(
            enabled: Self.tomlBool(toml, "sensitive_data_detector", "enabled") ?? true,
            criticalCategories: Self.tomlStringArray(toml, "sensitive_data_detector", "critical_categories")
                ?? ["crypto", "financial", "credential", "pii"],
            alertSeverity: .high
        )

        // ── Email Scanner ───────────────────────────────────────────
        self.emailScanner = EmailScannerConfig(
            enabled: Self.tomlBool(toml, "email_scanner", "enabled") ?? true,
            mailDir: resolver.mailDir,
            alertCategories: [
                "phishing", "social_engineering", "authority_impersonation",
                "sensitive_data_request", "malicious_url", "dangerous_attachment",
                "crypto_scam", "malware_dropper", "prompt_injection"
            ],
            startupScanLimit: Self.tomlInt(toml, "email_scanner", "startup_scan_limit") ?? 50
        )

        // ── Messages Scanner ────────────────────────────────────────
        self.messagesScanner = MessagesScannerConfig(
            enabled: Self.tomlBool(toml, "messages_scanner", "enabled") ?? true,
            messagesDb: resolver.messagesDb
        )

        // ── Always Forbidden ────────────────────────────────────────
        self.alwaysForbidden = AlwaysForbiddenConfig(
            walletKeyAccess: Self.tomlBool(toml, "always_forbidden", "wallet_key_access") ?? true,
            creditCardTransmission: Self.tomlBool(toml, "always_forbidden", "credit_card_transmission") ?? true,
            ssnTransmission: Self.tomlBool(toml, "always_forbidden", "ssn_transmission") ?? true,
            driversLicenseUpload: Self.tomlBool(toml, "always_forbidden", "drivers_license_upload") ?? true,
            photosLibraryUpload: Self.tomlBool(toml, "always_forbidden", "photos_library_upload") ?? true,
            keychainDump: Self.tomlBool(toml, "always_forbidden", "keychain_dump") ?? true,
            envFileUpload: Self.tomlBool(toml, "always_forbidden", "env_file_upload") ?? true,
            privatePemKeyUpload: Self.tomlBool(toml, "always_forbidden", "private_pem_key_upload") ?? true,
            turboTaxUpload: Self.tomlBool(toml, "always_forbidden", "turbotax_upload") ?? true
        )

        // ── Audit ───────────────────────────────────────────────────
        self.audit = AuditConfig(
            logDir: resolver.logDir,
            logBlockedOperations: Self.tomlBool(toml, "audit", "log_blocked_operations") ?? true,
            logAlerts: Self.tomlBool(toml, "audit", "log_alerts") ?? true,
            maxLogAgeDays: Self.tomlInt(toml, "audit", "max_log_age_days") ?? 90
        )

        // ── Notifications ───────────────────────────────────────────
        self.notifications = NotificationsConfig(
            enabled: Self.tomlBool(toml, "notifications", "enabled") ?? true,
            criticalOnly: Self.tomlBool(toml, "notifications", "critical_only") ?? (mode == .production)
        )

        // ── Scheduled Scan ──────────────────────────────────────────
        self.scheduledScan = ScheduledScanConfig(
            enabled: Self.tomlBool(toml, "scheduled_scan", "enabled") ?? true,
            intervalHours: Self.tomlInt(toml, "scheduled_scan", "interval_hours") ?? 6,
            scanDirectories: resolver.scheduledScanDirectories
        )

        // ── Phase 16 sections ───────────────────────────────────────

        self.pythonPthWatcher = PythonPthWatcherConfig(
            enabled: Self.tomlBool(toml, "python_pth_watcher", "enabled") ?? true
        )

        // dependency_drift.project_roots is also reused by persistence_paths
        // for `.git/hooks` discovery — one list to maintain.
        let projectRoots = Self.tomlStringArray(toml, "dependency_drift", "project_roots") ?? []
        self.dependencyDrift = DependencyDriftConfig(
            enabled: Self.tomlBool(toml, "dependency_drift", "enabled") ?? true,
            projectRoots: projectRoots,
            maxDepth: Self.tomlInt(toml, "dependency_drift", "max_depth") ?? 3
        )

        self.persistencePaths = PersistencePathsConfig(
            enabled: Self.tomlBool(toml, "persistence_paths", "enabled") ?? true
        )
    }
}
