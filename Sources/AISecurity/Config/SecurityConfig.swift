import Foundation

/// Security operating mode — mirrors SecurityMode in security.config.js
enum SecurityMode: String, Codable, Sendable {
    case production  = "PRODUCTION"   // Maximum security — all alerts, auto-quarantine
    case testing     = "TESTING"      // Alert but do NOT quarantine
    case development = "DEVELOPMENT"  // Logging only
}

/// Central configuration — mirrors config/security.config.js
struct SecurityConfig: Sendable {
    static let shared = SecurityConfig()

    let mode: SecurityMode
    let home: String
    let securityDir: String

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

    // ── Helpers ─────────────────────────────────────────────────────
    var isProduction: Bool  { mode == .production }
    var isTesting: Bool     { mode == .testing }
    var isDevelopment: Bool  { mode == .development }
    var shouldQuarantine: Bool { externalFileSanitizer.autoQuarantine }

    // ── Init with defaults ──────────────────────────────────────────
    init() {
        let envMode = ProcessInfo.processInfo.environment["MAC_SECURITY_MODE"] ?? "PRODUCTION"
        self.mode = SecurityMode(rawValue: envMode) ?? .production
        self.home = FileManager.default.homeDirectoryForCurrentUser.path
        self.securityDir = (home as NSString).appendingPathComponent(".mac-security")

        self.fileWatcher = FileWatcherConfig(
            enabled: true,
            monitoredDirectories: [
                (home as NSString).appendingPathComponent("Downloads"),
                (home as NSString).appendingPathComponent("Desktop"),
                (home as NSString).appendingPathComponent("Documents"),
            ],
            maxScanSizeBytes: 5 * 1024 * 1024,
            debounceMs: 300
        )

        self.externalFileSanitizer = ExternalFileSanitizerConfig(
            enabled: true,
            autoQuarantine: mode == .production,
            quarantineDir: (securityDir as NSString).appendingPathComponent("quarantine"),
            scanDownloadsOnStart: true
        )

        self.promptInjectionGuard = PromptInjectionGuardConfig(
            enabled: true,
            clipboardMonitorIntervalMs: 2000
        )

        self.sensitiveDataDetector = SensitiveDataDetectorConfig(
            enabled: true,
            criticalCategories: ["crypto", "financial", "credential", "pii"],
            alertSeverity: .high
        )

        self.emailScanner = EmailScannerConfig(
            enabled: true,
            mailDir: (home as NSString).appendingPathComponent("Library/Mail"),
            alertCategories: [
                "phishing", "social_engineering", "authority_impersonation",
                "sensitive_data_request", "malicious_url", "dangerous_attachment",
                "crypto_scam", "malware_dropper", "prompt_injection"
            ],
            startupScanLimit: 50
        )

        self.alwaysForbidden = AlwaysForbiddenConfig(
            walletKeyAccess: true,
            creditCardTransmission: true,
            ssnTransmission: true,
            driversLicenseUpload: true,
            photosLibraryUpload: true,
            keychainDump: true,
            envFileUpload: true,
            privatePemKeyUpload: true,
            turboTaxUpload: true
        )

        self.audit = AuditConfig(
            logDir: (securityDir as NSString).appendingPathComponent("logs"),
            logBlockedOperations: true,
            logAlerts: true,
            maxLogAgeDays: 90
        )

        self.notifications = NotificationsConfig(
            enabled: true,
            criticalOnly: mode == .production
        )

        self.scheduledScan = ScheduledScanConfig(
            enabled: true,
            intervalHours: 6,
            scanDirectories: [
                (home as NSString).appendingPathComponent("Downloads"),
                (home as NSString).appendingPathComponent("Desktop"),
                (home as NSString).appendingPathComponent("Documents"),
            ]
        )
    }
}
