import Foundation

/// Apple Mail email scanner — monitors ~/Library/Mail/ for new .emlx files.
/// Pattern matching now backed by Rust security-core via FFI.
/// .emlx parsing, file watching, attachment checks, and whitelist logic stay in Swift.
final class EmailScanner: @unchecked Sendable {

    typealias AlertHandler = @Sendable (SecurityAlert) -> Void

    // MARK: - Properties

    private let logger: SecurityLogger
    private let intentParser = ThreatIntentParser()
    private let config = SecurityConfig.shared
    private var source: DispatchSourceFileSystemObject?
    private var fileDescriptor: Int32 = -1
    private var pollTimer: DispatchSourceTimer?
    private var scannedFiles: [String: TimeInterval] = [:] // path → mtime
    private let stateFile: String
    private(set) var isRunning = false
    private(set) var emailsScanned = 0
    private(set) var threatsFound = 0
    private(set) var byCategory: [String: Int] = [:]
    private var lastResetDay: Int = 0  // day-of-year for daily counter reset
    var onAlert: AlertHandler?

    // MARK: - Attachment checks (stay in Swift — operate on parsed email structure)

    private let dangerousExtensions: Set<String>
    private let suspiciousAttachmentNames: [NSRegularExpression]

    // MARK: - Trusted domains

    private let trustedDomains: Set<String> = [
        "americanexpress.com", "welcome.americanexpress.com",
        "turbotax.intuit.com", "intuit.com",
        "dell.com", "americas.comm.dell.com",
        "chase.com", "jpmorgan.com",
        "wellsfargo.com", "bankofamerica.com",
        "apple.com", "id.apple.com",
        "amazon.com", "amazon-ppe.com",
        "paypal.com",
        "google.com", "accounts.google.com",
        "microsoft.com", "microsoftonline.com",
        "substack.com",
        "followmyhealth.com",
        "coinbureau.com",
        "gemini.com", "news.gemini.com",
    ]

    // MARK: - Init

    private let whitelist: SenderWhitelist

    init(logger: SecurityLogger, whitelist: SenderWhitelist? = nil) {
        self.logger = logger
        self.whitelist = whitelist ?? SenderWhitelist(securityDir: SecurityConfig.shared.securityDir)
        self.stateFile = (SecurityConfig.shared.securityDir as NSString)
            .appendingPathComponent("email-scanned-state.json")
        // Load previously scanned files so we don't re-alert on restart
        if let data = FileManager.default.contents(atPath: stateFile),
           let dict = try? JSONDecoder().decode([String: TimeInterval].self, from: data) {
            self.scannedFiles = dict
        }

        self.dangerousExtensions = [
            ".exe", ".dmg", ".sh", ".bash", ".zsh", ".bat", ".cmd",
            ".vbs", ".ps1", ".msi", ".pkg", ".run", ".jar", ".deb",
            ".docm", ".xlsm", ".pptm", ".xlam",
            ".js", ".py", ".rb", ".pl", ".php",
            ".iso", ".img",
        ]

        self.suspiciousAttachmentNames = [
            #"^invoice[-_\s]"#, #"^payment[-_\s]"#, #"^receipt[-_\s]"#,
            #"^order[-_\s]"#, #"^statement[-_\s]"#, #"^document[-_\s]"#,
            #"^attachment[-_\s]"#, #"refund"#, #"^notice[-_\s]"#,
        ].compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
    }

    // MARK: - Start / Stop

    func start() {
        guard !isRunning else { return }
        let mailDir = config.emailScanner.mailDir
        guard FileManager.default.fileExists(atPath: mailDir) else {
            logger.warn("Apple Mail directory not found — email scanning skipped", data: ["path": mailDir])
            return
        }

        isRunning = true

        // Watch for file system changes
        let fd = open(mailDir, O_EVTONLY)
        if fd >= 0 {
            fileDescriptor = fd
            let src = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd, eventMask: [.write, .rename],
                queue: DispatchQueue.global(qos: .utility)
            )
            src.setEventHandler { [weak self] in
                self?.pollRecentEmails(windowMs: 70000)
            }
            src.setCancelHandler { close(fd) }
            src.resume()
            source = src
        }

        // Poll fallback every 60s
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            self?.pollRecentEmails(windowMs: 70000)
        }
        timer.resume()
        pollTimer = timer

        // Startup scan of last 7 days
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.pollRecentEmails(windowMs: 7 * 24 * 60 * 60 * 1000)
        }

        logger.info("\u{1F4E7} Email Scanner started", data: ["mailDir": mailDir, "mode": fd >= 0 ? "watch+poll" : "poll-only"])
    }

    func stop() {
        source?.cancel()
        source = nil
        pollTimer?.cancel()
        pollTimer = nil
        if fileDescriptor >= 0 { close(fileDescriptor); fileDescriptor = -1 }
        isRunning = false
        logger.info("\u{1F4E7} Email Scanner stopped")
    }

    // MARK: - State Persistence

    private func persistScannedFiles() {
        if let data = try? JSONEncoder().encode(scannedFiles) {
            try? data.write(to: URL(fileURLWithPath: stateFile))
        }
    }

    // MARK: - Poll

    private func pollRecentEmails(windowMs: Int) {
        let cutoff = Date().timeIntervalSince1970 - Double(windowMs) / 1000.0 - 5.0
        let emlxFiles = findEmlxFiles(in: config.emailScanner.mailDir, limit: 2000)

        if emlxFiles.isEmpty {
            logger.warn("\u{1F4E7} Email poll: 0 .emlx files found — FDA may not be active")
            return
        }

        // Reset daily counter at midnight
        let today = Calendar.current.ordinality(of: .day, in: .year, for: Date()) ?? 0
        if today != lastResetDay {
            emailsScanned = 0
            threatsFound = 0
            lastResetDay = today
        }

        var newCount = 0
        for filePath in emlxFiles {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: filePath),
                  let mdate = attrs[.modificationDate] as? Date else { continue }
            let mtime = mdate.timeIntervalSince1970
            guard mtime >= cutoff else { continue }
            guard scannedFiles[filePath] != mtime else { continue }
            scannedFiles[filePath] = mtime
            scanEmail(filePath)
            newCount += 1
        }

        if newCount > 0 {
            logger.info("\u{1F4E7} Poll scanned \(newCount) new/updated email(s)")
            persistScannedFiles()
        }
    }

    // MARK: - Scan Email

    private func scanEmail(_ filePath: String) {
        guard FileManager.default.fileExists(atPath: filePath),
              let email = parseEmlx(filePath) else { return }

        emailsScanned += 1

        var threats: [(type: String, label: String, severity: SeverityLevel, category: String)] = []
        var warnings: [(label: String, detail: String)] = []

        let from = email.headers["from"] ?? ""
        let subject = email.headers["subject"] ?? ""
        let to = email.headers["to"] ?? ""
        let replyTo = email.headers["reply-to"] ?? ""
        let fullText = "\(from)\n\(subject)\n\(to)\n\(replyTo)\n\(email.body)"

        // Run threat patterns via Rust FFI
        let rustThreats = SecurityCoreBridge.analyzeEmail(fullText)
        for t in rustThreats {
            threats.append((type: t.type, label: t.label, severity: t.severity, category: t.category))
            byCategory[t.category, default: 0] += 1
        }

        // Check attachment names (stays in Swift — operates on parsed email structure)
        for attachName in email.attachmentNames {
            let ext = (attachName as NSString).pathExtension.lowercased()
            let dotExt = ext.isEmpty ? "" : ".\(ext)"

            if dangerousExtensions.contains(dotExt) {
                threats.append((type: "dangerous_attachment_ext", label: "Dangerous attachment: \(attachName)", severity: .critical, category: "dangerous_attachment"))
            }

            let bnRange = NSRange(location: 0, length: (attachName as NSString).length)
            for pattern in suspiciousAttachmentNames {
                if pattern.firstMatch(in: attachName, range: bnRange) != nil &&
                   [".zip", ".rar", ".7z"].contains(dotExt) {
                    warnings.append((label: "Suspicious compressed attachment: \(attachName)",
                                     detail: "Compressed file with suspicious name"))
                }
            }
        }

        // Reply-To mismatch
        if !replyTo.isEmpty && !from.isEmpty {
            let fromDomain = extractDomain(from)
            let replyDomain = extractDomain(replyTo)
            if let fd = fromDomain, let rd = replyDomain, fd != rd {
                warnings.append((label: "Reply-To domain mismatch", detail: "From: \(fd) → Reply-To: \(rd)"))
            }
        }

        // 7-Layer Intent Validation (now via Rust through ThreatIntentParser)
        let intent = intentParser.parse(fullText, channel: .email)
        let senderDomain = extractSenderDomain(from)
        let isTrusted = senderDomain.map { sd in
            trustedDomains.contains(where: { sd == $0 || sd.hasSuffix("." + $0) })
        } ?? false

        let layerThreshold = isTrusted ? 5 : 3

        let bypassCategories: Set<String> = ["dangerous_attachment", "malicious_url", "prompt_injection", "malware_dropper", "crypto_scam"]

        var confirmedThreats = threats.filter { t in
            bypassCategories.contains(t.category) || intent.layersFired >= layerThreshold
        }

        if intent.isThreat && confirmedThreats.isEmpty && intent.layersFired >= layerThreshold {
            confirmedThreats.append((
                type: "intent_detected",
                label: "Intent: \(intent.label)",
                severity: intent.severity ?? .medium,
                category: "intent_detected"
            ))
        }

        // Apply whitelist policy
        let senderPolicy = whitelist.policy(for: from)
        if senderPolicy.isWhitelisted {
            confirmedThreats = confirmedThreats.filter { t in
                senderPolicy.shouldAlert(category: t.category, intentLayers: intent.layersFired)
            }
        }

        // Report
        if !confirmedThreats.isEmpty {
            threatsFound += 1

            let patternSeverity: SeverityLevel = confirmedThreats.contains(where: { $0.severity == .critical }) ? .critical : .high
            let finalSeverity = max(intent.severity ?? .low, patternSeverity)

            let alert = SecurityAlert(
                type: "EMAIL_THREAT_DETECTED",
                severity: finalSeverity,
                message: "\u{1F4E7} \(from.isEmpty ? "unknown" : from) — \(confirmedThreats.map(\.label).joined(separator: ", ")) [\(intent.confidence)]",
                filePath: filePath,
                from: from,
                to: to,
                subject: subject,
                threats: confirmedThreats.map { ThreatDetail(label: $0.label, category: $0.category, severity: $0.severity) }
            )
            logger.alert(alert)
            onAlert?(alert)
        } else if !warnings.isEmpty {
            logger.warn("\u{26A0}\u{FE0F} Suspicious email from \(from.isEmpty ? "unknown" : from): \(subject)")
        } else {
            let sender = from.isEmpty ? "unknown" : from
            let subj = subject.isEmpty ? "(no subject)" : subject
            logger.info("\u{2705} Email clean: \(sender) — \(subj)")
        }
    }

    // MARK: - .emlx Parser (stays in Swift — file I/O)

    private struct ParsedEmail {
        var headers: [String: String] = [:]
        var body: String = ""
        var attachmentNames: [String] = []
    }

    private func parseEmlx(_ filePath: String) -> ParsedEmail? {
        guard let data = FileManager.default.contents(atPath: filePath),
              var raw = String(data: data, encoding: .utf8) else { return nil }

        // .emlx files start with a byte count on the first line — skip it
        if let firstNewline = raw.firstIndex(of: "\n") {
            let firstLine = String(raw[raw.startIndex..<firstNewline]).trimmingCharacters(in: .whitespaces)
            if firstLine.allSatisfy(\.isNumber) {
                raw = String(raw[raw.index(after: firstNewline)...])
            }
        }

        var email = ParsedEmail()

        // Split headers and body
        let headerEnd = raw.range(of: "\n\n") ?? raw.range(of: "\r\n\r\n")
        let headerSection: String
        let bodySection: String

        if let end = headerEnd {
            headerSection = String(raw[raw.startIndex..<end.lowerBound])
            bodySection = String(raw[end.upperBound...])
        } else {
            headerSection = raw
            bodySection = ""
        }

        // Unfold multi-line headers
        let unfolded = headerSection.replacingOccurrences(
            of: #"\r?\n[ \t]+"#, with: " ", options: .regularExpression)

        for line in unfolded.split(separator: "\n", omittingEmptySubsequences: false) {
            if let colonIdx = line.firstIndex(of: ":") {
                let key = String(line[line.startIndex..<colonIdx]).trimmingCharacters(in: .whitespaces).lowercased()
                let val = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
                email.headers[key] = val
            }
        }

        email.body = bodySection

        // Extract attachment filenames
        let attachPattern = try? NSRegularExpression(
            pattern: #"Content-Disposition:.*?filename[*]?=["']?([^"';\r\n]+)"#,
            options: .caseInsensitive)
        if let ap = attachPattern {
            let nsRaw = raw as NSString
            let matches = ap.matches(in: raw, range: NSRange(location: 0, length: nsRaw.length))
            for match in matches {
                if match.numberOfRanges > 1 {
                    let name = nsRaw.substring(with: match.range(at: 1))
                        .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                    email.attachmentNames.append(name)
                }
            }
        }

        return email
    }

    // MARK: - Helpers

    private func findEmlxFiles(in dir: String, limit: Int) -> [String] {
        var files: [String] = []
        let fm = FileManager.default

        func walk(_ d: String) {
            guard files.count < limit else { return }
            guard let entries = try? fm.contentsOfDirectory(atPath: d) else { return }
            for entry in entries {
                guard files.count < limit else { return }
                let full = (d as NSString).appendingPathComponent(entry)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: full, isDirectory: &isDir) else { continue }
                if isDir.boolValue {
                    walk(full)
                } else if entry.hasSuffix(".emlx") {
                    files.append(full)
                }
            }
        }

        walk(dir)
        return files
    }

    private func extractDomain(_ emailStr: String) -> String? {
        let pattern = try? NSRegularExpression(pattern: #"@([a-z0-9.\-]+)"#, options: .caseInsensitive)
        let nsStr = emailStr as NSString
        guard let match = pattern?.firstMatch(in: emailStr, range: NSRange(location: 0, length: nsStr.length)),
              match.numberOfRanges > 1 else { return nil }
        return nsStr.substring(with: match.range(at: 1)).lowercased()
    }

    private func extractSenderDomain(_ from: String) -> String? {
        let pattern1 = try? NSRegularExpression(pattern: #"<[^@]+@([^>]+)>"#)
        let pattern2 = try? NSRegularExpression(pattern: #"@([^\s>]+)"#)
        let nsFrom = from as NSString
        let range = NSRange(location: 0, length: nsFrom.length)

        for pat in [pattern1, pattern2].compactMap({ $0 }) {
            if let match = pat.firstMatch(in: from, range: range), match.numberOfRanges > 1 {
                return nsFrom.substring(with: match.range(at: 1)).lowercased()
            }
        }
        return nil
    }

    func getStats() -> [String: Any] {
        ["emailsScanned": emailsScanned, "threatsFound": threatsFound, "isRunning": isRunning]
    }
}
