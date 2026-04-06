import Foundation

/// Structured audit trail for all vault operations, file moves, deletions, and threat detections.
/// JSON Lines format with 30-day retention and 10MB rotation.
final class VaultAuditLog {

    static let shared = VaultAuditLog()

    // MARK: - Types

    enum EventType: String, Codable {
        case fileAdded = "FILE_ADDED"
        case fileRemoved = "FILE_REMOVED"
        case fileMoved = "FILE_MOVED"
        case fileDeleted = "FILE_DELETED"
        case protectionChanged = "PROTECTION_CHANGED"
        case fileUnlocked = "FILE_UNLOCKED"
        case fileLocked = "FILE_LOCKED"
        case fileModified = "FILE_MODIFIED"
        case unauthorizedAccess = "UNAUTHORIZED_ACCESS"
        case passphraseChanged = "PASSPHRASE_CHANGED"
        case emailScanned = "EMAIL_SCANNED"
        case messageScanned = "MESSAGE_SCANNED"
        case threatDetected = "THREAT_DETECTED"
    }

    struct AuditEntry: Codable {
        let timestamp: String
        let event: String
        let path: String
        let detail: String
    }

    // MARK: - Config

    private let logDir: String
    private let currentFile: String
    private let maxFileSize: UInt64 = 10 * 1024 * 1024  // 10 MB
    private let retentionDays: Int = 30
    private let queue = DispatchQueue(label: "com.aisecurity.vault.audit", qos: .utility)
    private let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    // MARK: - Init

    private init() {
        let secDir = SecurityConfig.shared.securityDir
        logDir = (secDir as NSString).appendingPathComponent("logs")
        currentFile = (logDir as NSString).appendingPathComponent("vault-audit.jsonl")

        // Ensure log directory exists
        let fm = FileManager.default
        if !fm.fileExists(atPath: logDir) {
            try? fm.createDirectory(atPath: logDir, withIntermediateDirectories: true)
        }

        // Cleanup old rotations on startup
        queue.async { [weak self] in self?.cleanupOldLogs() }
    }

    // MARK: - Write

    /// Log a vault event. Thread-safe, non-blocking.
    func log(_ event: EventType, path: String, detail: String) {
        queue.async { [weak self] in
            guard let self else { return }

            let entry = AuditEntry(
                timestamp: self.isoFormatter.string(from: Date()),
                event: event.rawValue,
                path: path,
                detail: detail
            )

            guard let data = try? JSONEncoder().encode(entry),
                  var line = String(data: data, encoding: .utf8) else { return }
            line += "\n"

            // Rotate if needed
            self.rotateIfNeeded()

            // Append line
            if FileManager.default.fileExists(atPath: self.currentFile) {
                if let handle = FileHandle(forWritingAtPath: self.currentFile) {
                    handle.seekToEndOfFile()
                    handle.write(Data(line.utf8))
                    handle.closeFile()
                }
            } else {
                try? Data(line.utf8).write(to: URL(fileURLWithPath: self.currentFile))
                // Set 0600 permissions
                try? FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: self.currentFile
                )
            }
        }
    }

    // MARK: - Read

    /// Read recent audit entries. Called from main thread for UI; does file I/O on caller's thread.
    func getEntries(since: Date? = nil, limit: Int = 500) -> [AuditEntry] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: currentFile),
              let data = fm.contents(atPath: currentFile),
              let content = String(data: data, encoding: .utf8) else { return [] }

        let decoder = JSONDecoder()
        var entries: [AuditEntry] = []

        let lines = content.components(separatedBy: "\n")
        for line in lines.reversed() {
            guard !line.isEmpty else { continue }
            guard let lineData = line.data(using: .utf8),
                  let entry = try? decoder.decode(AuditEntry.self, from: lineData) else { continue }

            if let since, let entryDate = isoFormatter.date(from: entry.timestamp), entryDate < since {
                break  // entries are chronological; once we pass the cutoff, stop
            }

            entries.append(entry)
            if entries.count >= limit { break }
        }

        return entries.reversed()  // return in chronological order
    }

    // MARK: - Rotation

    private func rotateIfNeeded() {
        let fm = FileManager.default
        guard fm.fileExists(atPath: currentFile),
              let attrs = try? fm.attributesOfItem(atPath: currentFile),
              let size = attrs[.size] as? UInt64,
              size >= maxFileSize else { return }

        let dateStr = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
            .prefix(19)
        let rotatedName = "vault-audit.\(dateStr).jsonl"
        let rotatedPath = (logDir as NSString).appendingPathComponent(String(rotatedName))

        try? fm.moveItem(atPath: currentFile, toPath: rotatedPath)
    }

    private func cleanupOldLogs() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(atPath: logDir) else { return }

        let cutoff = Date().addingTimeInterval(-Double(retentionDays) * 86400)

        for file in files where file.hasPrefix("vault-audit.") && file != "vault-audit.jsonl" {
            let fullPath = (logDir as NSString).appendingPathComponent(file)
            if let attrs = try? fm.attributesOfItem(atPath: fullPath),
               let created = attrs[.creationDate] as? Date,
               created < cutoff {
                try? fm.removeItem(atPath: fullPath)
            }
        }
    }
}
