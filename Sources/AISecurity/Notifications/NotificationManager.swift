import Foundation

/// Routes security alerts to external notification channels based on severity.
/// Includes rate limiting (per-type cooldown) and per-file dedup to prevent spam.
final class NotificationManager {

    static let shared = NotificationManager()
    private let config = NotificationConfig.shared
    private let lock = NSLock()

    // MARK: - Rate Limiting

    /// Minimum seconds between external notifications of the same alert type.
    private let typeCooldownSeconds: TimeInterval = 60  // 1 minute per type

    /// Minimum seconds between external notifications for the same file path.
    private let fileCooldownSeconds: TimeInterval = 3600  // 1 hour per file

    /// Maximum external notifications per rolling window before throttling.
    private let maxPerWindow = 10
    private let windowSeconds: TimeInterval = 300  // 5-minute window

    /// Last send time per alert type.
    private var lastSendByType: [String: Date] = [:]

    /// Last send time per file path.
    private var lastSendByFile: [String: Date] = [:]

    /// Timestamps of all recent sends (for global rate limiting).
    private var recentSends: [Date] = []

    /// Count of suppressed notifications (for logging).
    private(set) var suppressedCount = 0

    private init() {}

    /// Alert types worth sending externally. Routine OS detections stay local-only.
    private let externalAlertTypes: Set<String> = [
        "VAULT_FILE_ACCESS",
        "EXTERNAL_FILE_THREAT",
        "SENSITIVE_DATA_IN_FILE",
        "SENSITIVE_DATA_IN_CLIPBOARD",
        "SCHEDULED_SCAN_THREATS"
    ]

    /// Send an alert to all enabled channels appropriate for its severity.
    /// Only sends security-relevant alerts externally — routine OS detections stay local.
    /// Rate-limited: per-type cooldown, per-file dedup, global throttle.
    func send(_ alert: SecurityAlert) {
        guard externalAlertTypes.contains(alert.type) else { return }

        // Check rate limits
        lock.lock()
        let now = Date()

        // 1. Per-type cooldown
        if let lastType = lastSendByType[alert.type],
           now.timeIntervalSince(lastType) < typeCooldownSeconds {
            suppressedCount += 1
            lock.unlock()
            return
        }

        // 2. Per-file cooldown (if alert has a file path)
        if let filePath = alert.filePath,
           let lastFile = lastSendByFile[filePath],
           now.timeIntervalSince(lastFile) < fileCooldownSeconds {
            suppressedCount += 1
            lock.unlock()
            return
        }

        // 3. Global rate limit — max N sends per rolling window
        recentSends = recentSends.filter { now.timeIntervalSince($0) < windowSeconds }
        if recentSends.count >= maxPerWindow {
            suppressedCount += 1
            lock.unlock()
            return
        }

        // Record this send
        lastSendByType[alert.type] = now
        if let filePath = alert.filePath {
            lastSendByFile[filePath] = now
        }
        recentSends.append(now)

        // Prune old entries periodically
        if lastSendByFile.count > 200 {
            lastSendByFile = lastSendByFile.filter { now.timeIntervalSince($0.value) < fileCooldownSeconds }
        }
        if lastSendByType.count > 50 {
            lastSendByType = lastSendByType.filter { now.timeIntervalSince($0.value) < typeCooldownSeconds }
        }

        lock.unlock()

        // Send to channels
        let channels = channelsForSeverity(alert.severity)

        if channels.contains(.telegram) && config.telegram.enabled && config.isTelegramConfigured {
            TelegramChannel.send(alert, config: config.telegram) { ok, err in
                if !ok { print("[Notification] Telegram failed: \(err ?? "unknown")") }
            }
        }

        if channels.contains(.discord) && config.discord.enabled && config.isDiscordConfigured {
            DiscordChannel.send(alert, config: config.discord) { ok, err in
                if !ok { print("[Notification] Discord failed: \(err ?? "unknown")") }
            }
        }

        if channels.contains(.email) && config.email.enabled && config.isEmailConfigured {
            EmailChannel.send(alert, config: config.email) { ok, err in
                if !ok { print("[Notification] Email failed: \(err ?? "unknown")") }
            }
        }
    }

    // MARK: - Severity Routing

    private enum Channel { case telegram, discord, email }

    private func channelsForSeverity(_ severity: SeverityLevel) -> Set<Channel> {
        switch severity {
        case .critical: return [.telegram, .discord, .email]
        case .high:     return [.telegram, .discord]
        case .medium:   return []  // local only
        case .low:      return []  // local only
        }
    }
}
