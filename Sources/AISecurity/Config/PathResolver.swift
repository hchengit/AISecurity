import Foundation

/// Resolves all file system paths used by AISecurity.
/// Supports ~ expansion, config.toml overrides, and environment variable overrides.
/// Priority: environment variable > config.toml value > built-in default.
struct PathResolver: Sendable {

    let home: String
    let securityDir: String
    let mailDir: String
    let messagesDb: String
    let quarantineDir: String
    let logDir: String
    let monitoredDirectories: [String]
    let scheduledScanDirectories: [String]
    let protectedPaths: [String]

    // MARK: - Default protected paths (macOS)

    private static func defaultProtectedPaths(home: String) -> [String] {
        return [
            "\(home)/Pictures/Photos Library.photoslibrary",
            "\(home)/Pictures",
            "\(home)/Library/Application Support/com.apple.photoanalysisd",
            "\(home)/Library/Application Support/Photos",
            "\(home)/Library/Application Support/Sparrow",
            "\(home)/.sparrow",
            "\(home)/.bitcoin",
            "\(home)/.lnd",
            "\(home)/Library/Application Support/Bitwarden",
            "\(home)/Library/Application Support/Aura",
            "\(home)/Library/Keychains",
            "\(home)/Library/Mail",
            "\(home)/Library/Messages",
            "\(home)/Library/Group Containers/group.com.apple.notes",
            "\(home)/Library/Calendars",
            "\(home)/Library/Application Support/AddressBook",
            "\(home)/Library/Containers/com.apple.AddressBook",
            "\(home)/Library/Reminders",
            "\(home)/Library/Group Containers/group.com.apple.reminders",
            "\(home)/.ssh",
            "\(home)/.gnupg",
            "\(home)/Library/Safari",
            "\(home)/Documents/Tax Returns",
            "\(home)/Documents/TurboTax",
        ]
    }

    // MARK: - Init

    /// Initialize with optional TOML config values.
    /// Pass `nil` for any value to use defaults.
    init(
        configSecurityDir: String? = nil,
        configMailDir: String? = nil,
        configMessagesDb: String? = nil,
        configQuarantineDir: String? = nil,
        configLogDir: String? = nil,
        configMonitoredDirs: [String]? = nil,
        configScheduledScanDirs: [String]? = nil,
        configProtectedPaths: [String]? = nil
    ) {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        self.home = home

        // Helper: resolve ~ in a path, then check env override
        func resolve(_ path: String) -> String {
            if path.hasPrefix("~/") || path == "~" {
                return (home as NSString).appendingPathComponent(String(path.dropFirst(2)))
            }
            return path
        }

        func envOrConfig(_ envKey: String, config: String?, fallback: String) -> String {
            if let env = ProcessInfo.processInfo.environment[envKey], !env.isEmpty {
                return resolve(env)
            }
            if let cfg = config {
                return resolve(cfg)
            }
            return resolve(fallback)
        }

        func envOrConfigPaths(_ envKey: String, config: [String]?, fallback: [String]) -> [String] {
            if let env = ProcessInfo.processInfo.environment[envKey], !env.isEmpty {
                return env.split(separator: ":").map { resolve(String($0)) }
            }
            if let cfg = config {
                return cfg.map { resolve($0) }
            }
            return fallback.map { resolve($0) }
        }

        self.securityDir = envOrConfig("MACSEC_SECURITY_DIR", config: configSecurityDir, fallback: "~/.mac-security")
        self.mailDir = envOrConfig("MACSEC_MAIL_DIR", config: configMailDir, fallback: "~/Library/Mail")
        self.messagesDb = envOrConfig("MACSEC_MESSAGES_DB", config: configMessagesDb, fallback: "~/Library/Messages/chat.db")
        self.logDir = envOrConfig("MACSEC_LOG_DIR", config: configLogDir, fallback: "~/.mac-security/logs")
        self.quarantineDir = envOrConfig("MACSEC_QUARANTINE_DIR", config: configQuarantineDir, fallback: "~/.mac-security/quarantine")

        let defaultDirs = ["~/Downloads", "~/Desktop", "~/Documents"]
        self.monitoredDirectories = envOrConfigPaths("MACSEC_SCAN_DIRS", config: configMonitoredDirs, fallback: defaultDirs)
        self.scheduledScanDirectories = envOrConfigPaths("MACSEC_SCAN_DIRS", config: configScheduledScanDirs, fallback: defaultDirs)

        if let custom = configProtectedPaths {
            self.protectedPaths = custom.map { resolve($0) }
        } else {
            self.protectedPaths = Self.defaultProtectedPaths(home: home)
        }
    }
}
