import Foundation
import TOMLKit

/// Security operating mode — mirrors SecurityMode in security.config.js
enum SecurityMode: String, Codable, Sendable {
    case production  = "PRODUCTION"   // Maximum security — all alerts, auto-quarantine
    case testing     = "TESTING"      // Alert but do NOT quarantine
    case development = "DEVELOPMENT"  // Logging only
}

/// Central configuration — reads from config.toml with env var overrides.
///
/// Override priority: environment variable > config.toml > built-in default
/// Config file location: ~/.mac-security/config.toml (or MACSEC_SECURITY_DIR/config.toml)
struct SecurityConfig: Sendable {
    static let shared = SecurityConfig()

    let mode: SecurityMode
    let home: String
    let securityDir: String
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
        return Int(val)
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

    // ── Init with TOML + env var support ────────────────────────────
    init() {
        let toml = Self.loadTOML()

        // Mode: env > toml > default
        let envMode = ProcessInfo.processInfo.environment["MACSEC_MODE"]
            ?? ProcessInfo.processInfo.environment["MAC_SECURITY_MODE"]  // backwards compat
        let tomlMode = Self.tomlString(toml, "general", "mode")
        self.mode = SecurityMode(rawValue: envMode ?? tomlMode ?? "PRODUCTION") ?? .production

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
    }
}
