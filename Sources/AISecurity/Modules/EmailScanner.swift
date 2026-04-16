import Foundation

/// Apple Mail email scanner — monitors ~/Library/Mail/ for new .emlx files.
/// Pattern matching now backed by Rust security-core via FFI.
/// .emlx parsing, file watching, attachment checks, and whitelist logic stay in Swift.
///
/// Scanning strategy:
/// - Only scans Inbox and custom folders (skips Deleted, Junk, Sent, Drafts)
/// - Tracks unique emails scanned (not rescan count)
/// - Deduplicates via file path (same file modified = update, not new count)
/// - Polls every 60s for emails from the last 10 minutes
/// - Startup: scans last 30 days (or ALL on first launch)
final class EmailScanner: @unchecked Sendable {

    typealias AlertHandler = @Sendable (SecurityAlert) -> Void

    // MARK: - Properties

    private let logger: SecurityLogger
    private let intentParser = ThreatIntentParser()
    private let config = SecurityConfig.shared
    private var source: DispatchSourceFileSystemObject?
    private var fileDescriptor: Int32 = -1
    private var pollTimer: DispatchSourceTimer?
    private var scannedFiles: [String: TimeInterval] = [:] // path → mtime (last scanned)
    private let stateFile: String
    private(set) var isRunning = false
    /// Unique emails scanned (each email counted once, rescans don't inflate)
    private(set) var emailsScanned = 0
    private(set) var threatsFound = 0
    private(set) var byCategory: [String: Int] = [:]
    var onAlert: AlertHandler?

    /// Whether Full Disk Access appears to be missing (cannot traverse Mail directory).
    private(set) var fdaRequired = false
    /// Human-readable status for menu bar display.
    private(set) var scannerStatus: String = "Starting..."

    /// Callback for status updates (so daemon can refresh menu even without threats).
    var onStatusUpdate: ((_ scanned: Int, _ threats: Int, _ status: String) -> Void)?

    // MARK: - Mailbox filtering

    /// Mailbox name prefixes to SKIP (lowercased, compared against .mbox dir names).
    /// Covers Apple Mail, Gmail, Exchange/Outlook, and generic IMAP names.
    /// Only Inbox and custom user folders are scanned.
    private let skippedMailboxPrefixes: [String] = [
        "deleted", "trash", "bin",           // deleted/trash
        "junk", "spam",                       // junk/spam
        "sent", "outbox",                     // sent mail
        "drafts", "draft",                    // drafts
        "archive", "all mail",                // archive
        "[gmail]",                            // Gmail container (has Sent/Trash/Spam inside)
        "sync issues",                        // Exchange sync artifacts
        "notes",                              // Apple Notes sync folder
    ]

    // MARK: - Attachment checks (stay in Swift — operate on parsed email structure)

    private let dangerousExtensions: Set<String>
    private let suspiciousAttachmentNames: [NSRegularExpression]

    // Trusted domains list replaced by dynamic SenderHistory tracking.
    // Sender trust is now earned through clean email history, not a static list.

    // MARK: - Init

    private let whitelist: SenderWhitelist
    private let senderHistory: SenderHistory

    init(logger: SecurityLogger, whitelist: SenderWhitelist? = nil, senderHistory: SenderHistory? = nil) {
        self.logger = logger
        self.whitelist = whitelist ?? SenderWhitelist(securityDir: SecurityConfig.shared.securityDir)
        self.senderHistory = senderHistory ?? SenderHistory(securityDir: SecurityConfig.shared.securityDir)
        self.stateFile = (SecurityConfig.shared.securityDir as NSString)
            .appendingPathComponent("email-scanned-state.json")
        // Load previously scanned files so we don't re-alert on restart
        if let data = FileManager.default.contents(atPath: stateFile),
           var dict = try? JSONDecoder().decode([String: TimeInterval].self, from: data) {
            // Prune entries older than 90 days to prevent unbounded memory growth
            let ninetyDaysAgo = Date().timeIntervalSince1970 - (90 * 24 * 60 * 60)
            let beforeCount = dict.count
            dict = dict.filter { $0.value >= ninetyDaysAgo }
            if dict.count < beforeCount {
                logger.info("\u{1F4E7} Pruned \(beforeCount - dict.count) old email scan entries (>90 days)")
            }
            // Also prune entries from skipped mailboxes (cleanup from before filtering was added)
            let beforeMailboxPrune = dict.count
            let prefixes = skippedMailboxPrefixes
            dict = dict.filter { path, _ in !Self.isSkippedMailbox(path: path, prefixes: prefixes) }
            if dict.count < beforeMailboxPrune {
                logger.info("\u{1F4E7} Pruned \(beforeMailboxPrune - dict.count) entries from skipped mailboxes (Deleted/Junk/Sent)")
            }
            self.scannedFiles = dict
            // emailsScanned starts at 0 on every launch — counts today's scans only.
            // The scannedFiles dict still tracks all files so we don't rescan them,
            // but the visible counter ("Emails scanned today") resets fresh.
            self.emailsScanned = 0
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
            scannerStatus = "Inactive — Mail directory not found"
            return
        }

        isRunning = true

        // FDA diagnostic check
        let fdaCheck = checkMailAccess(mailDir: mailDir)
        logger.info("\u{1F4E7} Email FDA check", data: [
            "canOpen": "\(fdaCheck.canOpen)",
            "canTraverse": "\(fdaCheck.canTraverse)",
            "emlxCount": "\(fdaCheck.emlxCount)"
        ])
        if fdaCheck.canTraverse && fdaCheck.emlxCount > 0 {
            scannerStatus = "Active — \(fdaCheck.emlxCount) inbox emails found"
        } else if !fdaCheck.canTraverse {
            fdaRequired = true
            scannerStatus = "Inactive — FDA required"
            logger.warn("\u{1F4E7} Email scanning: Full Disk Access may not be granted — cannot traverse \(mailDir)")
        } else {
            scannerStatus = "Active — waiting for new emails"
        }

        // Watch for file system changes
        let fd = open(mailDir, O_EVTONLY)
        if fd >= 0 {
            fileDescriptor = fd
            let src = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd, eventMask: [.write, .rename],
                queue: DispatchQueue.global(qos: .utility)
            )
            src.setEventHandler { [weak self] in
                self?.pollRecentEmails(windowMs: 600_000) // 10 minutes
            }
            src.setCancelHandler { close(fd) }
            src.resume()
            source = src
        }

        // Poll every 60s — scan emails from last 10 minutes (generous overlap)
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            self?.pollRecentEmails(windowMs: 600_000) // 10 minutes
        }
        timer.resume()
        pollTimer = timer

        // Startup scan: delayed 30s to let Apple Mail sync new emails after wake/boot.
        // First launch → scan ALL, subsequent → scan last 30 days.
        let isFirstLaunch = scannedFiles.isEmpty
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + (isFirstLaunch ? 0 : 30)) { [weak self] in
            guard let self else { return }
            if isFirstLaunch {
                self.logger.info("\u{1F4E7} First launch: scanning all emails...")
                self.pollRecentEmails(windowMs: 0) // 0 = scan all
            } else {
                self.logger.info("\u{1F4E7} Startup scan (delayed 30s for Mail sync)...")
                self.pollRecentEmails(windowMs: 30 * 24 * 60 * 60 * 1000) // 30 days
            }
        }

        logger.info("\u{1F4E7} Email Scanner started (skipping: Deleted, Junk, Sent, Drafts)", data: ["mailDir": mailDir, "mode": fd >= 0 ? "watch+poll" : "poll-only"])
    }

    /// Diagnostic check: can we actually read the Mail directory tree?
    private func checkMailAccess(mailDir: String) -> (canOpen: Bool, canTraverse: Bool, emlxCount: Int) {
        let fm = FileManager.default
        let canOpen = fm.fileExists(atPath: mailDir)
        var canTraverse = false
        var emlxCount = 0

        if canOpen {
            do {
                let topLevel = try fm.contentsOfDirectory(atPath: mailDir)
                canTraverse = !topLevel.isEmpty

                // Probe versioned subdirectories (V9/, V10/, V11/, etc.)
                for item in topLevel where item.hasPrefix("V") {
                    let subdir = (mailDir as NSString).appendingPathComponent(item)
                    do {
                        let sub = try fm.contentsOfDirectory(atPath: subdir)
                        emlxCount += sub.filter { $0.hasSuffix(".emlx") }.count
                        for subItem in sub {
                            let deeper = (subdir as NSString).appendingPathComponent(subItem)
                            var isDir: ObjCBool = false
                            if fm.fileExists(atPath: deeper, isDirectory: &isDir), isDir.boolValue {
                                if let deepEntries = try? fm.contentsOfDirectory(atPath: deeper) {
                                    emlxCount += deepEntries.filter { $0.hasSuffix(".emlx") }.count
                                }
                            }
                        }
                    } catch {
                        logger.warn("\u{1F4E7} Email FDA: cannot read \(subdir): \(error.localizedDescription)")
                    }
                }
            } catch {
                logger.warn("\u{1F4E7} Email FDA: cannot list \(mailDir): \(error.localizedDescription)")
            }
        }

        return (canOpen, canTraverse, emlxCount)
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

    // MARK: - Mailbox Filtering

    /// Check if a file path is inside a skipped mailbox (Deleted, Junk, Sent, Drafts).
    private static func isSkippedMailbox(path: String, prefixes: [String]) -> Bool {
        // Extract all .mbox directory names from the path
        let lower = path.lowercased()
        let components = lower.components(separatedBy: "/")
        for comp in components where comp.hasSuffix(".mbox") {
            let mboxName = String(comp.dropLast(".mbox".count))
            for prefix in prefixes {
                if mboxName.hasPrefix(prefix) {
                    return true
                }
            }
        }
        return false
    }

    // MARK: - State Persistence

    private func persistScannedFiles() {
        if let data = try? JSONEncoder().encode(scannedFiles) {
            try? data.write(to: URL(fileURLWithPath: stateFile))
        }
    }

    // MARK: - Poll

    private func pollRecentEmails(windowMs: Int) {
        // windowMs == 0 means scan ALL emails (first launch)
        let cutoff: TimeInterval = windowMs > 0
            ? Date().timeIntervalSince1970 - Double(windowMs) / 1000.0 - 5.0
            : 0
        let limit = windowMs == 0 ? 50000 : 10000
        let emlxFiles = findEmlxFiles(in: config.emailScanner.mailDir, limit: limit)

        if emlxFiles.isEmpty {
            if !fdaRequired {
                fdaRequired = true
                scannerStatus = "Inactive — FDA required (0 .emlx files found)"
                notifyStatus()
            }
            logger.warn("\u{1F4E7} Email poll: 0 .emlx files found — FDA may not be active")
            return
        }

        // FDA is working if we found files
        if fdaRequired {
            fdaRequired = false
        }

        var newCount = 0
        var rescanCount = 0
        for filePath in emlxFiles {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: filePath),
                  let mdate = attrs[.modificationDate] as? Date else { continue }
            let mtime = mdate.timeIntervalSince1970
            guard mtime >= cutoff else { continue }

            let existingMtime = scannedFiles[filePath]
            if existingMtime == nil {
                // Brand new email — never seen before
                scannedFiles[filePath] = mtime
                scanEmail(filePath)
                emailsScanned += 1
                newCount += 1
            } else if existingMtime != mtime {
                // File modified (e.g. marked read/unread) — rescan for threats but don't inflate count
                scannedFiles[filePath] = mtime
                scanEmail(filePath)
                rescanCount += 1
            }
            // If existingMtime == mtime: skip entirely (already scanned, unchanged)
        }

        if newCount > 0 || rescanCount > 0 {
            var logMsg = "\u{1F4E7} Poll: \(newCount) new"
            if rescanCount > 0 { logMsg += ", \(rescanCount) updated" }
            logMsg += " — unique: \(emailsScanned), threats: \(threatsFound), domains: \(senderHistory.domainCount)"
            logger.info(logMsg)
            persistScannedFiles()
            senderHistory.persistIfDirty()
        } else if windowMs == 0 || windowMs > 600000 {
            logger.info("\u{1F4E7} Scan complete: \(emlxFiles.count) emails checked, \(emailsScanned) unique scanned, \(threatsFound) threats")
        }

        // Update status for UI — always, so the menu reflects current state
        let now = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .short)
        if newCount > 0 {
            scannerStatus = "Active — \(emailsScanned) scanned, \(newCount) new (\(now))"
        } else {
            scannerStatus = "Active — \(emailsScanned) scanned, up to date (\(now))"
        }
        notifyStatus()
    }

    /// Push status to daemon so menu bar updates even when no threats fire.
    private func notifyStatus() {
        onStatusUpdate?(emailsScanned, threatsFound, scannerStatus)
    }

    // MARK: - Scan Email

    private func scanEmail(_ filePath: String) {
        guard FileManager.default.fileExists(atPath: filePath),
              let email = parseEmlx(filePath) else { return }

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

        // ── Threat feed lookups (Phase 14) ──────────────────────────
        // Check sender domain against cached threat intelligence feeds
        let senderDomain = extractSenderDomain(from) ?? ""
        if !senderDomain.isEmpty {
            let domainCheck = SecurityCoreBridge.feedCheckDomain(senderDomain)
            if domainCheck.isMatch {
                threats.append((
                    type: "threat_feed_domain",
                    label: "Threat feed: sender domain \(senderDomain) on \(domainCheck.feedName ?? "feed")",
                    severity: .critical,
                    category: "threat_feed_domain"
                ))
            }
        }

        // Check URLs in email body against cached feeds
        let urlPattern = try? NSRegularExpression(pattern: #"https?://[^\s<>"']{5,}"#)
        if let urlPat = urlPattern {
            let bodyNS = email.body as NSString
            let urlMatches = urlPat.matches(in: email.body, range: NSRange(location: 0, length: bodyNS.length))
            for match in urlMatches.prefix(20) { // check up to 20 URLs per email
                let urlStr = bodyNS.substring(with: match.range)
                let urlCheck = SecurityCoreBridge.feedCheckUrl(urlStr)
                if urlCheck.isMatch {
                    threats.append((
                        type: "threat_feed_url",
                        label: "Threat feed: URL on \(urlCheck.feedName ?? "feed"): \(urlCheck.indicator ?? urlStr)",
                        severity: .critical,
                        category: "threat_feed_url"
                    ))
                    break // one feed match per email is sufficient
                }
            }
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

        // ── Intent Analysis (Rust) ──────────────────────────────────
        let intent = intentParser.parse(fullText, channel: .email)

        // Hard bypass: ALWAYS alert regardless of sender trust or auth.
        // These indicate actual weaponized content, not just keyword matches.
        let hardBypassCategories: Set<String> = [
            "dangerous_attachment", "malware_dropper", "prompt_injection",
            "threat_feed_url", "threat_feed_domain"  // always alert on feed matches
        ]

        // Soft bypass: alert for unknown/suspicious senders, suppress for trusted.
        // Crypto newsletters legitimately discuss bitcoin; banks mention SSN/CC in context.
        let softBypassCategories: Set<String> = [
            "sensitive_data_request", "crypto_scam", "malicious_url"
        ]

        // Pattern threats confirmed if: hard bypass, soft bypass, or intent fires
        var confirmedThreats = threats.filter { t in
            hardBypassCategories.contains(t.category) ||
            softBypassCategories.contains(t.category) ||
            intent.isThreat
        }

        // Intent-only synthetic threat (no pattern match, but intent score high)
        if intent.isThreat && confirmedThreats.isEmpty {
            confirmedThreats.append((
                type: "intent_detected",
                label: "Intent: \(intent.label) [\(intent.score)%]",
                severity: intent.severity ?? .medium,
                category: "intent_detected"
            ))
        }

        // ── Sender History + Auth — contextual trust ────────────────
        // senderDomain already extracted above for feed check
        let trust = senderHistory.trustLevel(for: senderDomain)
        let auth = email.auth

        // Trusted sender (10+ clean emails, <5% threat rate):
        // Only flag hard bypass (dangerous attachments, malware, prompt injection).
        // Soft bypass (crypto_scam, sensitive_data, malicious_url) suppressed for trusted.
        if trust == .trusted {
            confirmedThreats = confirmedThreats.filter { t in
                hardBypassCategories.contains(t.category)
            }
        }

        // Fully authenticated (SPF+DKIM+DMARC pass):
        // Suppress intent-only threats from authenticated senders
        if auth.allPass && !confirmedThreats.isEmpty {
            confirmedThreats = confirmedThreats.filter { t in
                hardBypassCategories.contains(t.category) ||
                softBypassCategories.contains(t.category) ||
                t.category != "intent_detected"
            }
        }

        // First-contact heuristic: unknown sender + urgency + credential request = boost
        if trust == .unknown && !confirmedThreats.isEmpty {
            // Unknown sender with threats — keep them all, this is suspicious
        } else if trust == .unknown && intent.layers.l1 && intent.layers.l6 {
            // First contact + credential harvest + urgency — flag even below threshold
            confirmedThreats.append((
                type: "first_contact_risk",
                label: "First-contact sender with credential request + urgency",
                severity: .high,
                category: "intent_detected"
            ))
        }

        // Apply whitelist policy (final pass)
        let senderPolicy = whitelist.policy(for: from)
        if senderPolicy.isWhitelisted {
            confirmedThreats = confirmedThreats.filter { t in
                senderPolicy.shouldAlert(category: t.category, intentLayers: intent.score)
            }
        }

        // ── Record sender history ───────────────────────────────────
        let hadThreat = !confirmedThreats.isEmpty
        if !senderDomain.isEmpty {
            senderHistory.recordScan(domain: senderDomain, hadThreat: hadThreat)
        }

        // ── Report ──────────────────────────────────────────────────
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
        }
        // Clean emails: no log (reduces log noise significantly)
    }

    // MARK: - .emlx Parser (stays in Swift — file I/O)

    enum AuthStatus { case pass, fail, softfail, none }

    struct AuthResult {
        var spf: AuthStatus = .none
        var dkim: AuthStatus = .none
        var dmarc: AuthStatus = .none

        var allPass: Bool { spf == .pass && dkim == .pass && dmarc == .pass }
        var anyFail: Bool { spf == .fail || dkim == .fail || dmarc == .fail }
    }

    private struct ParsedEmail {
        var headers: [String: String] = [:]
        var body: String = ""
        var attachmentNames: [String] = []
        var auth: AuthResult = AuthResult()
    }

    /// Parse Authentication-Results header for SPF/DKIM/DMARC status.
    private func parseAuthResults(_ headerValue: String?) -> AuthResult {
        guard let header = headerValue?.lowercased() else { return AuthResult() }
        var result = AuthResult()

        // SPF
        if header.contains("spf=pass") {
            result.spf = .pass
        } else if header.contains("spf=fail") || header.contains("spf=hardfail") {
            result.spf = .fail
        } else if header.contains("spf=softfail") {
            result.spf = .softfail
        }

        // DKIM
        if header.contains("dkim=pass") {
            result.dkim = .pass
        } else if header.contains("dkim=fail") {
            result.dkim = .fail
        }

        // DMARC
        if header.contains("dmarc=pass") {
            result.dmarc = .pass
        } else if header.contains("dmarc=fail") {
            result.dmarc = .fail
        }

        return result
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

        // Parse authentication results (SPF/DKIM/DMARC)
        email.auth = parseAuthResults(email.headers["authentication-results"])

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

            // Skip mailboxes we don't care about (Deleted, Junk, Sent, Drafts, etc.)
            let dirName = (d as NSString).lastPathComponent.lowercased()
            if dirName.hasSuffix(".mbox") {
                let mboxName = String(dirName.dropLast(".mbox".count))
                for prefix in skippedMailboxPrefixes {
                    if mboxName.hasPrefix(prefix) { return }
                }
            }

            do {
                let entries = try fm.contentsOfDirectory(atPath: d)
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
            } catch {
                logger.warn("\u{1F4E7} Cannot read directory \(d): \(error.localizedDescription)")
                if d == dir {
                    fdaRequired = true
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
