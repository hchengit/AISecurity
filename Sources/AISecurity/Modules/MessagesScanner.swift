import Foundation
import SQLite3

/// Apple Messages / iMessage scanner — queries ~/Library/Messages/chat.db via sqlite3.
/// Replaces modules/messages-scanner.js — all patterns and logic ported 1:1.
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

    private let home = FileManager.default.homeDirectoryForCurrentUser.path
    private var chatDbPath: String { (home as NSString).appendingPathComponent("Library/Messages/chat.db") }
    private var stateFilePath: String {
        (home as NSString).appendingPathComponent(".mac-security/messages-last-scan.json")
    }

    // MARK: - Threat Patterns

    private struct PatternGroup {
        let patterns: [NSRegularExpression]
        let label: String
        let severity: SeverityLevel
        let category: String
    }

    private let threatPatterns: [(String, PatternGroup)]
    private let knownPhishingDomains: [String]

    // MARK: - Init

    init(logger: SecurityLogger, whitelist: SenderWhitelist? = nil, scanIntervalMs: Int = 60000, autoDeleteCritical: Bool = false) {
        self.logger = logger
        self.whitelist = whitelist ?? SenderWhitelist(securityDir: SecurityConfig.shared.securityDir)
        self.scanInterval = Double(scanIntervalMs) / 1000.0
        self.autoDeleteCritical = autoDeleteCritical
        self.lastSeenRowId = 0

        func compile(_ pats: [String]) -> [NSRegularExpression] {
            pats.compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
        }

        var groups: [(String, PatternGroup)] = []

        groups.append(("smishingBank", PatternGroup(
            patterns: compile([
                #"your\s+(?:bank\s+)?account\s+(?:has\s+been\s+)?(?:suspended|locked|flagged|compromised)"#,
                #"unusual\s+(?:activity|transaction|login)\s+(?:detected|noticed)\s+on\s+your\s+account"#,
                #"verify\s+your\s+(?:bank|account|card|identity)\s+(?:now|immediately|urgently)"#,
                #"(?:chase|wells\s+fargo|bank\s+of\s+america|citibank|us\s+bank|capital\s+one)\s+(?:alert|notice|security)"#,
                #"your\s+(?:debit|credit)\s+card\s+(?:has\s+been\s+)?(?:suspended|blocked|frozen)"#,
            ]),
            label: "Bank / Financial Smishing", severity: .critical, category: "smishing_bank"
        )))

        groups.append(("smishingApple", PatternGroup(
            patterns: compile([
                #"(?:apple|icloud|apple\s+id)\s+(?:account\s+)?(?:suspended|locked|compromised|disabled)"#,
                #"your\s+apple\s+id\s+(?:has\s+been\s+)?(?:used|signed\s+in|accessed)\s+(?:in|from)\s+"#,
                #"appleid\.apple\.com(?!\.apple\.com)"#,
                #"verify\s+your\s+apple\s+(?:id|account|payment)"#,
            ]),
            label: "Apple ID / iCloud Smishing", severity: .critical, category: "smishing_apple"
        )))

        groups.append(("smishingDelivery", PatternGroup(
            patterns: compile([
                #"(?:fedex|ups|usps|dhl|amazon)\s+(?:package|delivery|shipment)\s+(?:held|failed|pending|delayed)"#,
                #"your\s+(?:package|parcel|delivery)\s+(?:could\s+not\s+be\s+delivered|is\s+pending|requires\s+action)"#,
                #"(?:reschedule|confirm|update)\s+your\s+(?:delivery|shipment|package)\s+(?:address|info)"#,
            ]),
            label: "Fake Delivery / Shipping Smishing", severity: .high, category: "smishing_delivery"
        )))

        groups.append(("smishingIRS", PatternGroup(
            patterns: compile([
                #"(?:irs|internal\s+revenue)\s+(?:notice|alert|warning|action\s+required)"#,
                #"tax\s+(?:refund|return|penalty|audit)\s+(?:pending|held|notice)"#,
                #"(?:social\s+security|ssa|medicare)\s+(?:number\s+)?(?:suspended|compromised|flagged)"#,
                #"warrant\s+(?:issued|filed)\s+for\s+(?:your\s+)?(?:arrest|non[-\s]?payment)"#,
            ]),
            label: "Government / IRS Impersonation", severity: .critical, category: "smishing_irs"
        )))

        groups.append(("maliciousUrls", PatternGroup(
            patterns: compile([
                #"https?://(?:bit\.ly|tinyurl\.com|t\.co|ow\.ly|short\.io|cutt\.ly|is\.gd|rebrand\.ly)/\S+"#,
                #"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/\S*"#,
                #"https?://[a-z0-9\-]+\.(?:xyz|tk|ml|ga|cf|gq|pw|top|click|loan|win|date|party|review|work)/\S*"#,
                #"https?://\S+\.(?:dmg|exe|sh|apk|pkg|msi|bat|ps1)\b"#,
                #"https?://[a-z0-9]*(?:paypa1|arnazon|g00gle|micros0ft|app1e|app1e-id|icloud-verify|apple-security)[a-z0-9]*\."#,
            ]),
            label: "Malicious / Suspicious URL in Message", severity: .critical, category: "malicious_url"
        )))

        groups.append(("cryptoScam", PatternGroup(
            patterns: compile([
                #"(?:send|transfer|pay)\s+(?:bitcoin|btc|ethereum|eth|usdt|crypto)\s+(?:to|worth|\$)"#,
                #"(?:i\s+have\s+)?(?:hacked|compromised|recorded)\s+your\s+(?:phone|device|computer|camera)"#,
                #"pay\s+(?:\$[\d,]+|[\d,]+\s+(?:btc|usd))\s+(?:or|within|to\s+prevent)"#,
                #"(?:investment|trading)\s+(?:opportunity|platform|returns?)\s+(?:guaranteed|risk[-\s]free)"#,
                #"double\s+your\s+(?:bitcoin|crypto|money|investment)\s+in\s+"#,
            ]),
            label: "Crypto Scam / Sextortion in Message", severity: .critical, category: "crypto_scam"
        )))

        groups.append(("otpTheft", PatternGroup(
            patterns: compile([
                #"(?:share|send|provide|give|type|enter|read\s+out)\s+(?:your\s+)?(?:otp|one[-\s]time\s+(?:password|code)|verification\s+code)\s+(?:to|with)\s+(?:us|our|an?\s+agent|support)"#,
                #"(?:never\s+share|do\s+not\s+share|don'?t\s+share)\s+(?:your\s+)?(?:otp|code|pin)\s+with\s+(?:anyone|our\s+(?:team|agent|staff))"#,
                #"our\s+(?:agent|representative|support|team)\s+(?:will\s+)?(?:ask|never\s+ask)\s+(?:you\s+)?for\s+(?:your\s+)?(?:otp|code|pin|password)"#,
            ]),
            label: "OTP / Verification Code Theft Attempt", severity: .high, category: "otp_theft"
        )))

        groups.append(("prizeScam", PatternGroup(
            patterns: compile([
                #"(?:congratulations|you\s+(?:have\s+)?won|you've\s+been\s+selected)\s+(?:a\s+)?(?:prize|reward|gift\s+card|cash)"#,
                #"claim\s+your\s+(?:free\s+)?(?:prize|reward|gift|iphone|macbook|cash)\s+(?:now|today|here)"#,
                #"(?:winner|selected|chosen)\s+(?:for|to\s+receive)\s+(?:a\s+)?(?:\$[\d,]+|gift|prize)"#,
            ]),
            label: "Prize / Lottery Scam", severity: .high, category: "prize_scam"
        )))

        groups.append(("urgencyTactics", PatternGroup(
            patterns: compile([
                #"(?:act|respond|reply|click)\s+(?:now|immediately|within\s+\d+\s+hours?)\s+(?:or|to\s+avoid)"#,
                #"(?:final|last|urgent)\s+(?:warning|notice|reminder|chance)\s+(?:before|to)"#,
                #"your\s+(?:account|service|number|line)\s+will\s+be\s+(?:terminated|cancelled|suspended)\s+(?:in\s+\d+|unless)"#,
            ]),
            label: "Urgency / Fear Tactic", severity: .medium, category: "urgency_tactic"
        )))

        self.threatPatterns = groups

        self.knownPhishingDomains = [
            "apple-id-verify", "icloud-locked", "account-verify", "secure-login",
            "apple-support-", "chase-secure", "paypal-secure", "amazon-security",
            "irs-refund", "usps-tracking-", "fedex-delivery-", "ups-alert-"
        ]

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

    // MARK: - Fetch Messages via SQLite C API (runs in-process, inherits FDA)

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

    // MARK: - Analyze

    private func analyzeMessage(_ text: String) -> [(type: String, label: String, severity: SeverityLevel, category: String)] {
        var threats: [(type: String, label: String, severity: SeverityLevel, category: String)] = []
        let nsText = text as NSString
        let range = NSRange(location: 0, length: nsText.length)

        for (key, group) in threatPatterns {
            for pattern in group.patterns {
                if pattern.firstMatch(in: text, range: range) != nil {
                    threats.append((type: key, label: group.label, severity: group.severity, category: group.category))
                    break
                }
            }
        }

        let lower = text.lowercased()
        for domain in knownPhishingDomains {
            if lower.contains(domain) {
                threats.append((type: "known_phishing_domain", label: "Known phishing domain: \(domain)",
                                severity: .critical, category: "malicious_url"))
                break
            }
        }

        return threats
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
