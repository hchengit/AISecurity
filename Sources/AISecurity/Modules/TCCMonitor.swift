import Foundation
import SQLite3

/// Monitors macOS TCC (Transparency, Consent, and Control) database for permission changes.
///
/// Watches ~/Library/Application Support/com.apple.TCC/TCC.db for:
/// - New Full Disk Access grants
/// - New Accessibility access grants
/// - New Screen Recording grants
/// - New Camera/Microphone grants
/// - New Automation (AppleScript) grants
///
/// Alerts when any app gets new sensitive permissions, especially AI agent processes.
final class TCCMonitor: @unchecked Sendable {

    private let logger: SecurityLogger
    private var pollTimer: DispatchSourceTimer?
    private(set) var isRunning = false

    /// Previous snapshot of granted permissions: [service+client → grant info]
    private var previousGrants: [String: GrantInfo] = [:]

    /// TCC database path
    private let tccDbPath: String

    /// Services we monitor (the dangerous ones)
    private static let monitoredServices: Set<String> = [
        "kTCCServiceAccessibility",             // Accessibility (can control other apps!)
        "kTCCServiceScreenCapture",             // Screen recording
        "kTCCServiceSystemPolicyAllFiles",      // Full Disk Access
        "kTCCServiceCamera",                    // Camera
        "kTCCServiceMicrophone",                // Microphone
        "kTCCServiceAppleEvents",               // AppleScript / Automation
        "kTCCServicePostEvent",                 // Input monitoring
        "kTCCServiceListenEvent",               // Input monitoring (listen)
        "kTCCServiceSystemPolicyDesktopFolder", // Desktop access
        "kTCCServiceSystemPolicyDocumentsFolder", // Documents access
        "kTCCServiceSystemPolicyDownloadsFolder", // Downloads access
    ]

    struct GrantInfo: Equatable {
        let service: String
        let client: String      // bundle ID or path
        let allowed: Bool
        let lastModified: Int64
    }

    init(logger: SecurityLogger) {
        self.logger = logger
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        self.tccDbPath = (home as NSString).appendingPathComponent(
            "Library/Application Support/com.apple.TCC/TCC.db"
        )
    }

    // MARK: - Start / Stop

    func start() {
        guard !isRunning else { return }

        // Check if TCC.db is readable
        guard FileManager.default.fileExists(atPath: tccDbPath) else {
            logger.info("\u{1F6E1} TCC Monitor: database not found at \(tccDbPath) — skipping")
            return
        }

        isRunning = true

        // Take initial snapshot
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.takeSnapshot(initial: true)
        }

        // Poll every 60 seconds for changes
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            self?.takeSnapshot(initial: false)
        }
        timer.resume()
        pollTimer = timer

        logger.info("\u{1F6E1} TCC Monitor started (watching \(Self.monitoredServices.count) permission types)")
    }

    func stop() {
        pollTimer?.cancel()
        pollTimer = nil
        isRunning = false
        logger.info("\u{1F6E1} TCC Monitor stopped")
    }

    // MARK: - TCC Snapshot

    private func takeSnapshot(initial: Bool) {
        let grants = queryTCCGrants()

        if initial {
            // First snapshot — just record, don't alert
            previousGrants = grants
            logger.info("\u{1F6E1} TCC baseline: \(grants.count) permission grants recorded")
            return
        }

        // Compare with previous snapshot
        for (key, grant) in grants {
            if let previous = previousGrants[key] {
                // Known grant — check if it changed
                if previous.allowed != grant.allowed {
                    if grant.allowed {
                        alertNewGrant(grant)
                    } else {
                        logger.info("\u{1F6E1} Permission revoked: \(friendlyServiceName(grant.service)) for \(grant.client)")
                    }
                }
            } else if grant.allowed {
                // New grant not in previous snapshot
                alertNewGrant(grant)
            }
        }

        previousGrants = grants
    }

    private func alertNewGrant(_ grant: GrantInfo) {
        let serviceName = friendlyServiceName(grant.service)
        let severity: SeverityLevel

        // Accessibility and FDA are highest risk
        switch grant.service {
        case "kTCCServiceAccessibility", "kTCCServiceSystemPolicyAllFiles":
            severity = .critical
        case "kTCCServiceScreenCapture", "kTCCServiceCamera", "kTCCServiceMicrophone":
            severity = .high
        default:
            severity = .medium
        }

        let message = "\u{1F6E1} New permission granted: \(serviceName) → \(grant.client)"
        logger.alert(SecurityAlert(
            type: "TCC_PERMISSION_GRANT",
            severity: severity,
            message: message,
            filePath: tccDbPath
        ))
        logger.info(message)
    }

    // MARK: - TCC Database Query

    private func queryTCCGrants() -> [String: GrantInfo] {
        var grants: [String: GrantInfo] = [:]
        var db: OpaquePointer?

        // Open read-only
        let rc = sqlite3_open_v2(tccDbPath, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil)
        guard rc == SQLITE_OK, db != nil else {
            // TCC.db might not be readable without FDA — that's OK, just skip
            return grants
        }
        defer { sqlite3_close(db) }

        // Query for granted permissions
        let sql = "SELECT service, client, auth_value, last_modified FROM access WHERE auth_value = 2"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return grants }
        defer { sqlite3_finalize(stmt) }

        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let servicePtr = sqlite3_column_text(stmt, 0),
                  let clientPtr = sqlite3_column_text(stmt, 1) else { continue }

            let service = String(cString: servicePtr)
            let client = String(cString: clientPtr)
            let lastModified = sqlite3_column_int64(stmt, 3)

            // Only track services we care about
            guard Self.monitoredServices.contains(service) else { continue }

            let key = "\(service):\(client)"
            grants[key] = GrantInfo(
                service: service,
                client: client,
                allowed: true,
                lastModified: lastModified
            )
        }

        return grants
    }

    // MARK: - Helpers

    private func friendlyServiceName(_ service: String) -> String {
        switch service {
        case "kTCCServiceAccessibility": return "Accessibility"
        case "kTCCServiceScreenCapture": return "Screen Recording"
        case "kTCCServiceSystemPolicyAllFiles": return "Full Disk Access"
        case "kTCCServiceCamera": return "Camera"
        case "kTCCServiceMicrophone": return "Microphone"
        case "kTCCServiceAppleEvents": return "Automation"
        case "kTCCServicePostEvent": return "Input Monitoring"
        case "kTCCServiceListenEvent": return "Input Listening"
        case "kTCCServiceSystemPolicyDesktopFolder": return "Desktop Folder"
        case "kTCCServiceSystemPolicyDocumentsFolder": return "Documents Folder"
        case "kTCCServiceSystemPolicyDownloadsFolder": return "Downloads Folder"
        default: return service
        }
    }
}
