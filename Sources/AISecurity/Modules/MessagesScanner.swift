import Foundation
import SQLite3

/// Apple Messages / iMessage scanner — queries ~/Library/Messages/chat.db via sqlite3.
/// Pattern matching now backed by Rust security-core via FFI.
/// SQLite access, timer, state persistence, and whitelist logic stay in Swift.
final class MessagesScanner: @unchecked Sendable {

    typealias AlertHandler = @Sendable (SecurityAlert) -> Void

    // MARK: - Properties

    private let logger: SecurityLogger
    private let intentParser = ThreatIntentParser()
    private let whitelist: SenderWhitelist
    private let scanInterval: TimeInterval
    private let autoDeleteCritical: Bool
    private var timer: DispatchSourceTimer?
    private var lastSeenRowId: Int
    private(set) var isRunning = false
    private(set) var messagesScanned = 0
    private(set) var threatsFound = 0
    private(set) var byCategory: [String: Int] = [:]
    var onAlert: AlertHandler?

    private let config = SecurityConfig.shared
    private var chatDbPath: String { config.messagesScanner.messagesDb }
    private var stateFilePath: String {
        (config.securityDir as NSString).appendingPathComponent("messages-last-scan.json")
    }

    // MARK: - Init

    init(logger: SecurityLogger, whitelist: SenderWhitelist? = nil, scanIntervalMs: Int = 60000, autoDeleteCritical: Bool = false) {
        self.logger = logger
        self.whitelist = whitelist ?? SenderWhitelist(securityDir: SecurityConfig.shared.securityDir)
        self.scanInterval = Double(scanIntervalMs) / 1000.0
        self.autoDeleteCritical = autoDeleteCritical
        self.lastSeenRowId = 0

        // Load saved state
        self.lastSeenRowId = Self.loadLastSeenRowId(from: stateFilePath)
    }

    // MARK: - Start / Stop

    func start() {
        guard !isRunning else { return }
        guard FileManager.default.fileExists(atPath: chatDbPath) else {
            logger.warn("\u{1F4F1} Messages chat.db not found — Messages scanning skipped", data: ["path": chatDbPath])
            return
        }

        isRunning = true

        // Immediate first scan
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.scan()
        }

        // Periodic scan
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        t.schedule(deadline: .now() + scanInterval, repeating: scanInterval)
        t.setEventHandler { [weak self] in self?.scan() }
        t.resume()
        timer = t

        logger.info("\u{1F4F1} Messages Scanner started", data: [
            "chatDb": chatDbPath,
            "interval": "every \(Int(scanInterval))s",
            "autoDeleteCritical": "\(autoDeleteCritical)"
        ])
    }

    func stop() {
        timer?.cancel()
        timer = nil
        isRunning = false
        logger.info("\u{1F4F1} Messages Scanner stopped")
    }

    // MARK: - Scan

    private func scan() {
        do {
            let messages = try fetchNewMessages()
            guard !messages.isEmpty else { return }

            logger.info("\u{1F4F1} Scanning \(messages.count) new message(s)...")

            for msg in messages {
                guard let text = msg["text"] as? String, !text.trimmingCharacters(in: .whitespaces).isEmpty else { continue }
                messagesScanned += 1

                let rawThreats = analyzeMessage(text)
                let intent = intentParser.parse(text, channel: .sms)

                var threats = rawThreats.filter { t in
                    ["malicious_url", "crypto_scam"].contains(t.category) || intent.layersFired >= 2
                }

                if intent.isThreat && threats.isEmpty {
                    threats.append((type: "intent_detected", label: "Intent: \(intent.label)",
                                    severity: intent.severity ?? .medium, category: "intent_detected"))
                }

                // Apply whitelist policy
                let sender = msg["sender"] as? String ?? "Unknown"
                let senderPolicy = whitelist.policy(for: sender)
                if senderPolicy.isWhitelisted {
                    threats = threats.filter { t in
                        senderPolicy.shouldAlert(category: t.category, intentLayers: intent.layersFired)
                    }
                }

                if !threats.isEmpty {
                    threatsFound += 1
                    var topThreat = threats.sorted { severityRank($0.severity) > severityRank($1.severity) }.first!

                    if let intentSev = intent.severity, severityRank(intentSev) > severityRank(topThreat.severity) {
                        topThreat.severity = intentSev
                    }

                    for t in threats {
                        byCategory[t.category, default: 0] += 1
                    }

                    let preview = String(text.prefix(100)).replacingOccurrences(of: "\n", with: " ")

                    let alert = SecurityAlert(
                        type: "MESSAGE_THREAT_DETECTED",
                        severity: topThreat.severity,
                        message: "\u{1F4F1} Suspicious message from \(sender): \(topThreat.label)",
                        threats: threats.map { ThreatDetail(label: $0.label, category: $0.category, severity: $0.severity) },
                        preview: preview,
                        sender: sender
                    )
                    logger.alert(alert)
                    onAlert?(alert)
                    VaultAuditLog.shared.log(.threatDetected, path: "",
                        detail: "message threat from \(sender): \(topThreat.label)")
                }
            }

            // Advance checkpoint
            if let maxRowId = messages.compactMap({ $0["rowid"] as? Int }).max() {
                saveLastSeenRowId(maxRowId)
            }

        } catch {
            if !error.localizedDescription.contains("locked") && !error.localizedDescription.contains("busy") {
                logger.warn("Messages scan error: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Fetch Messages via SQLite C API (stays in Swift — inherits FDA)

    private func fetchNewMessages() throws -> [[String: Any]] {
        var db: OpaquePointer?
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX
        let rc = sqlite3_open_v2(chatDbPath, &db, flags, nil)
        guard rc == SQLITE_OK, let db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            sqlite3_close(db)
            throw NSError(domain: "MessagesScanner", code: Int(rc),
                          userInfo: [NSLocalizedDescriptionKey: "sqlite3 open failed: \(msg)"])
        }
        defer { sqlite3_close(db) }

        let query = """
        SELECT m.rowid, m.text, m.date, m.is_from_me, m.service, h.id AS sender \
        FROM message m LEFT JOIN handle h ON m.handle_id = h.rowid \
        WHERE m.is_from_me = 0 AND m.text IS NOT NULL AND m.text != '' \
        AND m.rowid > ?1 ORDER BY m.rowid ASC LIMIT 200;
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, query, -1, &stmt, nil) == SQLITE_OK, let stmt else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw NSError(domain: "MessagesScanner", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "prepare failed: \(msg)"])
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_int64(stmt, 1, Int64(lastSeenRowId))

        var results: [[String: Any]] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            var row: [String: Any] = [:]
            row["rowid"] = Int(sqlite3_column_int64(stmt, 0))
            if let cStr = sqlite3_column_text(stmt, 1) {
                row["text"] = String(cString: cStr)
            }
            row["date"] = Int(sqlite3_column_int64(stmt, 2))
            row["is_from_me"] = Int(sqlite3_column_int(stmt, 3))
            if let cStr = sqlite3_column_text(stmt, 4) {
                row["service"] = String(cString: cStr)
            }
            if let cStr = sqlite3_column_text(stmt, 5) {
                row["sender"] = String(cString: cStr)
            }
            results.append(row)
        }
        return results
    }

    // MARK: - Analyze (delegates to Rust FFI)

    private func analyzeMessage(_ text: String) -> [(type: String, label: String, severity: SeverityLevel, category: String)] {
        let rustThreats = SecurityCoreBridge.analyzeMessage(text)
        return rustThreats.map { t in
            (type: t.type, label: t.label, severity: t.severity, category: t.category)
        }
    }

    // MARK: - State Persistence

    private static func loadLastSeenRowId(from path: String) -> Int {
        guard FileManager.default.fileExists(atPath: path),
              let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return 0 }
        return json["lastSeenRowId"] as? Int ?? 0
    }

    private func saveLastSeenRowId(_ rowId: Int) {
        let json: [String: Any] = [
            "lastSeenRowId": rowId,
            "updatedAt": ISO8601DateFormatter().string(from: Date())
        ]
        if let data = try? JSONSerialization.data(withJSONObject: json) {
            try? data.write(to: URL(fileURLWithPath: stateFilePath))
        }
        lastSeenRowId = rowId
    }

    // MARK: - Helpers

    private func severityRank(_ s: SeverityLevel) -> Int { s.rank }

    func getStats() -> [String: Any] {
        ["messagesScanned": messagesScanned, "threatsFound": threatsFound, "isRunning": isRunning]
    }
}
