import Foundation
import UserNotifications

/// Structured security logger — writes JSON lines to ~/.mac-security/logs/
/// and sends native macOS notifications for CRITICAL alerts.
/// Replaces modules/security-logger.js
final class SecurityLogger: @unchecked Sendable {
    private let logDir: String
    private let logFile: String
    private let alertFile: String
    private let maxLogSize: UInt64 = 5 * 1024 * 1024 // 5 MB
    private let queue = DispatchQueue(label: "com.aisecurity.logger", qos: .utility)
    private let encoder = JSONEncoder()

    private var notificationsReady = false

    init(config: SecurityConfig = .shared) {
        self.logDir = config.audit.logDir
        self.logFile = (logDir as NSString).appendingPathComponent("security.log")
        self.alertFile = (logDir as NSString).appendingPathComponent("alerts.log")
        ensureLogDir()
        encoder.outputFormatting = .sortedKeys
        // Do NOT touch UNUserNotificationCenter here — it deadlocks SwiftUI's @StateObject init.
    }

    /// Call this once the app is fully launched (e.g. from daemon.start()).
    func setupNotifications() {
        guard !notificationsReady, Bundle.main.bundleIdentifier != nil else { return }
        notificationsReady = true
        requestNotificationPermission()
    }

    // MARK: - Public API

    func info(_ message: String, data: [String: String] = [:]) {
        let entry = LogEntry(level: "INFO", message: message, data: data)
        print("[INFO]  \(entry.timestamp) \(message)")
        write(to: logFile, entry: entry)
    }

    func warn(_ message: String, data: [String: String] = [:]) {
        let entry = LogEntry(level: "WARN", message: message, data: data)
        print("[WARN]  \(entry.timestamp) \(message)", to: &StderrOutputStream.shared)
        write(to: logFile, entry: entry)
    }

    func alert(_ securityAlert: SecurityAlert) {
        let display = securityAlert.message
        print("[ALERT] \(securityAlert.timestamp) \u{1F6A8} \(display)", to: &StderrOutputStream.shared)
        writeAlert(securityAlert)
        notify(message: display, severity: securityAlert.severity)
        // Send to external channels (Telegram, Discord, Email) based on severity
        NotificationManager.shared.send(securityAlert)
    }

    func getRecentAlerts(limit: Int = 50) -> [SecurityAlert] {
        guard FileManager.default.fileExists(atPath: alertFile),
              let data = FileManager.default.contents(atPath: alertFile),
              let content = String(data: data, encoding: .utf8) else { return [] }

        let decoder = JSONDecoder()
        return content
            .split(separator: "\n")
            .compactMap { line -> SecurityAlert? in
                guard let lineData = line.data(using: .utf8) else { return nil }
                return try? decoder.decode(SecurityAlert.self, from: lineData)
            }
            .suffix(limit)
            .reversed()
    }

    // MARK: - Private

    private func ensureLogDir() {
        try? FileManager.default.createDirectory(
            atPath: logDir, withIntermediateDirectories: true)
    }

    private func write(to file: String, entry: LogEntry) {
        queue.async { [weak self] in
            guard let self else { return }
            rotateIfNeeded(file)
            guard let data = try? self.encoder.encode(entry),
                  var line = String(data: data, encoding: .utf8) else { return }
            line += "\n"
            appendToFile(file, content: line)
        }
    }

    private func writeAlert(_ alert: SecurityAlert) {
        queue.async { [weak self] in
            guard let self else { return }
            rotateIfNeeded(logFile)
            rotateIfNeeded(alertFile)
            guard let data = try? self.encoder.encode(alert),
                  var line = String(data: data, encoding: .utf8) else { return }
            line += "\n"
            appendToFile(logFile, content: line)
            appendToFile(alertFile, content: line)
        }
    }

    private func appendToFile(_ path: String, content: String) {
        if !FileManager.default.fileExists(atPath: path) {
            FileManager.default.createFile(atPath: path, contents: nil)
        }
        guard let handle = FileHandle(forWritingAtPath: path) else { return }
        defer { handle.closeFile() }
        handle.seekToEndOfFile()
        if let data = content.data(using: .utf8) {
            handle.write(data)
        }
    }

    private func rotateIfNeeded(_ file: String) {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: file),
              let size = attrs[.size] as? UInt64,
              size > maxLogSize else { return }
        let rotated = file + ".1"
        try? FileManager.default.removeItem(atPath: rotated)
        try? FileManager.default.moveItem(atPath: file, toPath: rotated)
    }

    private func notify(message: String, severity: SeverityLevel) {
        // UNUserNotificationCenter.current() crashes with SIGABRT if the
        // bundle identifier is nil (e.g. binary launched outside .app context).
        guard notificationsReady, severity == .critical,
              Bundle.main.bundleIdentifier != nil else { return }

        let content = UNMutableNotificationContent()
        content.title = "\u{1F6A8} AISecurity CRITICAL"
        content.subtitle = "Click shield in menu bar to review"
        content.body = String(message.prefix(160))
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    private func requestNotificationPermission() {
        guard Bundle.main.bundleIdentifier != nil else { return }
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { _, _ in }
    }
}

// MARK: - Log Entry

private struct LogEntry: Codable {
    let level: String
    let timestamp: String
    let message: String
    let data: [String: String]

    init(level: String, message: String, data: [String: String] = [:]) {
        self.level = level
        self.timestamp = ISO8601DateFormatter().string(from: Date())
        self.message = message
        self.data = data
    }
}

// MARK: - Stderr helper

private struct StderrOutputStream: TextOutputStream {
    static var shared = StderrOutputStream()
    mutating func write(_ string: String) {
        FileHandle.standardError.write(Data(string.utf8))
    }
}
