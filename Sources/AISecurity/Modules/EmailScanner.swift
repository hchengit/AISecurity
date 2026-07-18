import Foundation

/// Apple Mail email scanner — monitors ~/Library/Mail/ for new .emlx files.
/// Pattern matching now backed by Rust security-core via FFI.
/// .emlx parsing, file watching, attachment checks, and whitelist logic stay in Swift.
///
/// Scanning strategy:
/// - Scans Inbox, custom folders, and (by config, default on) Junk/Spam, Trash, Archive.
///   Junk/Spam is the highest live-threat surface: spam filters divert threats without
///   neutralizing them, and users rummage junk with defenses down. See MailboxRole.
/// - Skips outbound/duplicate folders: Sent, Drafts, Notes, Sync Issues, and Gmail
///   "All Mail" (a copy of the whole mailbox — scanning it double-counts everything).
/// - Mailbox context feeds detection: a message in a flagged folder (Junk/Spam/Trash)
///   does NOT get sender-trust / SPF-DKIM suppression, and never banks "clean" credit
///   into sender-history, so spam volume can't poison inbox scoring.
/// - Rescue path: a never-before-seen file is always scanned regardless of age, so a
///   message moved Junk→Inbox ("Not Junk") is re-checked at the moment before the user
///   opens it, and the existing junk backlog is swept once on first expanded launch.
/// - Tracks unique emails scanned (not rescan count)
/// - Deduplicates via file path (same file modified = update, not new count)
/// - Polls every 60s for emails from the last 10 minutes
/// - Startup: scans last 30 days (or ALL on first launch); backlog finds alert
///   critical-only (weaponized content pops; lesser matches are logged, not notified)
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
    /// Serializes every poll (startup sweep, file-watch, 60s timer) so they can't run
    /// concurrently — this both guards `scannedFiles`/counters against races and ensures the
    /// startup backlog sweep finishes before any live poll processes the same files (so the
    /// backlog can't be re-scanned as live and defeat the critical-only notification policy).
    private let scanQueue = DispatchQueue(label: "com.aisecurity.email.scan")
    /// Set once the first startup backlog sweep completes. Until then every poll is treated as
    /// backlog, so a file-watch event that fires mid-sweep can't notify on the junk backlog.
    private var backfillDone = false
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

    /// Role of a mailbox, derived from its `.mbox` leaf name. Covers Apple Mail, Gmail
    /// (IMAP labels), Exchange/Outlook, and generic IMAP naming.
    enum MailboxRole {
        case inbox          // always scanned
        case junk           // Junk / Spam / Bulk — flagged folder, highest threat density
        case trash          // Trash / Deleted / Bin — flagged folder (people fish things out)
        case archive        // Archive — distinct retained mail
        case allMail        // Gmail "All Mail" — a copy of the whole mailbox (dedup target)
        case sentOrDraft    // Sent / Drafts / Outbox — outbound, out of inbound model
        case container      // Gmail "[Gmail]" wrapper — holds child mailboxes, descend into it
        case labelView      // Gmail Important/Starred — label views that duplicate real mail
        case noise          // Notes / Sync Issues — not mail, skip
        case custom         // user folder — scanned like Inbox

        /// Flagged by the provider as suspicious/discarded: suppress no threats, bank no trust.
        var isFlagged: Bool { self == .junk || self == .trash }

        /// Newly added coverage (vs. the historical Inbox-only scan). Used to scope the
        /// backlog notification-suppression to these folders, so Inbox alerting — which
        /// predates this change — keeps notifying normally on the startup sweep.
        var isExpandedCoverage: Bool {
            self == .junk || self == .trash || self == .archive || self == .allMail
        }
    }

    /// Classify a mailbox from its `.mbox` leaf name (without the `.mbox` suffix).
    static func mailboxRole(leaf: String) -> MailboxRole {
        let n = leaf.lowercased()
        if n == "[gmail]" || n == "[google mail]" { return .container }
        if n.hasPrefix("inbox") { return .inbox }
        if n.hasPrefix("junk") || n.hasPrefix("spam") || n.hasPrefix("bulk") { return .junk }
        if n.hasPrefix("trash") || n.hasPrefix("deleted") || n.hasPrefix("bin") { return .trash }
        if n.hasPrefix("all mail") { return .allMail }
        if n.hasPrefix("archive") { return .archive }
        if n.hasPrefix("sent") || n.hasPrefix("outbox") || n.hasPrefix("draft") { return .sentOrDraft }
        // Important/Starred are only Gmail label views (duplicating real mail) when they sit
        // *inside* the [Gmail] container — that context is applied by the walker. As a bare
        // leaf name they may be a real user folder ("Important Clients"), so classify .custom.
        if n == "important" || n == "starred" { return .labelView }
        if n.hasPrefix("notes") || n.hasPrefix("sync issues") { return .noise }
        return .custom  // unknown folder → scan (fail toward coverage)
    }

    /// Role of the mailbox a message file lives in = the deepest `.mbox` ancestor in its path.
    static func mailboxRole(forPath path: String) -> MailboxRole {
        let comps = path.components(separatedBy: "/")
        for comp in comps.reversed() where comp.hasSuffix(".mbox") {
            return mailboxRole(leaf: String(comp.dropLast(".mbox".count)))
        }
        return .custom
    }

    /// True if ANY mailbox in the path is Junk/Spam/Trash — so a message filed into a
    /// subfolder of Junk (e.g. `Junk.mbox/Quarantine.mbox/…`) is still treated as flagged,
    /// not waved through because its deepest folder happens to be unrecognized.
    static func isInFlaggedSubtree(forPath path: String) -> Bool {
        for comp in path.components(separatedBy: "/") where comp.hasSuffix(".mbox") {
            if mailboxRole(leaf: String(comp.dropLast(".mbox".count))).isFlagged { return true }
        }
        return false
    }

    /// True if ANY mailbox in the path is newly-covered (Junk/Trash/Archive/All Mail) — so a
    /// message in a subfolder of one of those still gets the critical-only backlog treatment
    /// (a subfolder's own name may classify as .custom and escape a deepest-role-only check).
    static func isInExpandedCoverageSubtree(forPath path: String) -> Bool {
        for comp in path.components(separatedBy: "/") where comp.hasSuffix(".mbox") {
            if mailboxRole(leaf: String(comp.dropLast(".mbox".count))).isExpandedCoverage { return true }
        }
        return false
    }

    /// Should the walker skip this mailbox subtree entirely, given config coverage?
    private func skipSubtree(role: MailboxRole) -> Bool {
        switch role {
        case .inbox, .custom, .container: return false
        case .junk:        return !config.emailScanner.scanJunk
        case .trash:       return !config.emailScanner.scanTrash
        case .archive:     return !config.emailScanner.scanArchive
        case .allMail:     return !config.emailScanner.scanAllMail
        case .sentOrDraft: return !config.emailScanner.scanSentDrafts
        case .labelView:   return true   // Gmail Important/Starred duplicate real mail
        case .noise:       return true
        }
    }

    /// Walk priority (lower = visited first) so the file-count cap can't starve Junk
    /// behind a large Inbox. Honors the endorsed order: Junk → Trash → Inbox → custom → Archive.
    private static func walkPriority(role: MailboxRole) -> Int {
        switch role {
        case .junk: return 0
        case .trash: return 1
        case .inbox: return 2
        case .custom, .container: return 3
        case .archive, .allMail: return 4
        case .sentOrDraft, .labelView, .noise: return 5
        }
    }

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
            // Prune entries from mailboxes we no longer scan under current config
            // (e.g. Sent/Drafts/All Mail). Keeps the state file in sync with coverage.
            let beforeMailboxPrune = dict.count
            let cfg = SecurityConfig.shared.emailScanner
            dict = dict.filter { path, _ in
                switch Self.mailboxRole(forPath: path) {
                case .inbox, .custom, .container: return true
                case .junk:        return cfg.scanJunk
                case .trash:       return cfg.scanTrash
                case .archive:     return cfg.scanArchive
                case .allMail:     return cfg.scanAllMail
                case .sentOrDraft: return cfg.scanSentDrafts
                case .labelView, .noise: return false
                }
            }
            if dict.count < beforeMailboxPrune {
                logger.info("\u{1F4E7} Pruned \(beforeMailboxPrune - dict.count) entries from unscanned mailboxes")
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
                guard let self else { return }
                self.scanQueue.async { self.pollRecentEmails(windowMs: 600_000) } // live poll
            }
            src.setCancelHandler { close(fd) }
            src.resume()
            source = src
        }

        // Poll every 60s — scan emails from last 10 minutes (generous overlap)
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.scanQueue.async { self.pollRecentEmails(windowMs: 600_000) } // live poll
        }
        timer.resume()
        pollTimer = timer

        // Startup scan: delayed 30s to let Apple Mail sync new emails after wake/boot.
        // First launch → scan ALL, subsequent → scan last 30 days. Marked as backlog so
        // pre-existing junk/trash finds alert critical-only (no notification burst). Runs on
        // scanQueue ahead of live polls so those files are already seen when live polls run.
        let isFirstLaunch = scannedFiles.isEmpty
        scheduleBacklogSweep(isFirstLaunch: isFirstLaunch, attempt: 0)

        let cfg = config.emailScanner
        let covered = ["Inbox",
                       cfg.scanJunk ? "Junk/Spam" : nil,
                       cfg.scanTrash ? "Trash" : nil,
                       cfg.scanArchive ? "Archive" : nil,
                       cfg.scanAllMail ? "All Mail" : nil,
                       cfg.scanSentDrafts ? "Sent/Drafts" : nil].compactMap { $0 }.joined(separator: ", ")
        logger.info("\u{1F4E7} Email Scanner started (scanning: \(covered))", data: ["mailDir": mailDir, "mode": fd >= 0 ? "watch+poll" : "poll-only"])
    }

    /// Run the one-shot startup backlog sweep, re-arming itself if it couldn't run yet because
    /// Full Disk Access wasn't granted. This is what flips `backfillDone`; without the re-arm a
    /// cold start before FDA (or before Mail has synced) would leave `backfillDone` false forever
    /// and permanently suppress live junk/trash notifications. Bounded so it can't loop endlessly.
    private func scheduleBacklogSweep(isFirstLaunch: Bool, attempt: Int) {
        // First pass immediate; then re-arm on a short cadence. Each pass scans up to `limit`
        // never-seen files as backlog; `backfillDone` flips only once a pass finds NO unseen
        // files left (the whole backlog is drained — see pollRecentEmails). Re-arm is UNBOUNDED
        // (while running & not done): a mailbox larger than one pass's cap needs several passes to
        // drain, and if Full Disk Access is granted late we must keep trying until it succeeds —
        // otherwise leftover backlog would later surface as a live-notification flood.
        let delay: Double = (isFirstLaunch && attempt == 0) ? 0 : 20
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self else { return }
            self.scanQueue.async {
                guard self.isRunning, !self.backfillDone else { return }
                let windowMs = isFirstLaunch ? 0 : 30 * 24 * 60 * 60 * 1000
                self.logger.info("\u{1F4E7} Startup \(isFirstLaunch ? "first-launch " : "")backlog sweep (pass \(attempt + 1))...")
                self.pollRecentEmails(windowMs: windowMs, backlog: true)
                if !self.backfillDone && self.isRunning {
                    self.scheduleBacklogSweep(isFirstLaunch: isFirstLaunch, attempt: attempt + 1)
                }
            }
        }
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
        // Re-arm the backlog sweep on the next start() (e.g. the daemon restarting us once FDA
        // is granted) so the initial sweep runs against real files rather than being skipped.
        backfillDone = false
        logger.info("\u{1F4E7} Email Scanner stopped")
    }

    // MARK: - State Persistence

    private func persistScannedFiles() {
        if let data = try? JSONEncoder().encode(scannedFiles) {
            try? data.write(to: URL(fileURLWithPath: stateFile))
        }
    }

    // MARK: - Poll

    /// - Parameter backlog: true for the startup/backfill sweep (30-day / first-launch-all).
    ///   Backlog finds alert critical-only; live-poll finds (new mail, rescued-from-junk)
    ///   alert normally. See `scanEmail(_:isBacklog:)`.
    private func pollRecentEmails(windowMs: Int, backlog: Bool = false) {
        // windowMs == 0 means scan ALL emails (first launch)
        let cutoff: TimeInterval = windowMs > 0
            ? Date().timeIntervalSince1970 - Double(windowMs) / 1000.0 - 5.0
            : 0
        let limit = windowMs == 0 ? 50000 : 20000
        // Until the first backlog sweep has completed, treat every poll as backlog so a
        // file-watch event mid-sweep can't fire live notifications on the junk backfill.
        let effectiveBacklog = backlog || !backfillDone
        let mailDir = config.emailScanner.mailDir
        let emlxFiles = findEmlxFiles(in: mailDir, limit: limit) { self.scannedFiles[$0] != nil }

        if emlxFiles.isEmpty {
            // Distinguish "FDA blocked" (can't even list the Mail dir) from "accessible but
            // empty". If it's genuinely accessible, there is no backlog to protect, so let a
            // backlog sweep count as complete — otherwise backfillDone could stick false forever
            // and permanently suppress live junk/trash notifications once mail does arrive.
            let accessible = (try? FileManager.default.contentsOfDirectory(atPath: mailDir)) != nil
            if accessible {
                fdaRequired = false
                // Accessible with no .emlx = there is no backlog to drain → backfill complete.
                if effectiveBacklog { backfillDone = true }
                logger.info("\u{1F4E7} Email poll: mailbox accessible but no .emlx found (empty)")
            } else {
                if !fdaRequired {
                    fdaRequired = true
                    scannerStatus = "Inactive — FDA required (cannot read Mail directory)"
                    notifyStatus()
                }
                logger.warn("\u{1F4E7} Email poll: cannot read Mail directory — FDA not active")
            }
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

            let existingMtime = scannedFiles[filePath]
            if existingMtime == nil {
                // Brand-new path — scan regardless of age. The time window is only an
                // optimization to skip re-reading known-unchanged files; a file we've
                // never seen must be scanned even if old, or a message rescued from Junk
                // (old received-date, new Inbox path) would teleport in unscanned.
                scannedFiles[filePath] = mtime
                scanEmail(filePath, isBacklog: effectiveBacklog)
                emailsScanned += 1
                newCount += 1
            } else if existingMtime != mtime && mtime >= cutoff {
                // Known file changed recently (e.g. marked read/unread) — rescan for
                // threats but don't inflate the unique count.
                scannedFiles[filePath] = mtime
                scanEmail(filePath, isBacklog: effectiveBacklog)
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

        // Backfill is complete only when a pass finds NO unseen files (newCount == 0). Because
        // findEmlxFiles returns ALL unseen files first (round-robin phase 1), newCount == 0 means
        // no unseen mail remains anywhere — the whole backlog is drained. Flipping here (rather
        // than after one capped pass) keeps leftover backlog on a large mailbox classified as
        // backlog (critical-only) until it's actually all scanned, instead of flooding live.
        if effectiveBacklog && newCount == 0 { backfillDone = true }

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

    /// - Parameter isBacklog: when true (startup/backfill sweep), non-critical finds are
    ///   logged but do not raise a user notification, so the first junk sweep can't flood.
    private func scanEmail(_ filePath: String, isBacklog: Bool) {
        guard FileManager.default.fileExists(atPath: filePath),
              let email = parseEmlx(filePath) else { return }

        // Mailbox the message lives in. Junk/Spam/Trash are "flagged": the provider
        // already treated them as suspicious/discarded, so we withhold the trust and
        // authentication suppression that a clean inbox would grant. `flaggedFolder` checks
        // the whole path so a subfolder nested under Junk/Trash counts too.
        let folderRole = Self.mailboxRole(forPath: filePath)
        let flaggedFolder = Self.isInFlaggedSubtree(forPath: filePath)

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
        // NOT applied in a flagged folder: a "trusted" domain whose message landed in
        // Junk is exactly the spoof/lookalike case — give it full scrutiny.
        if trust == .trusted && !flaggedFolder {
            confirmedThreats = confirmedThreats.filter { t in
                hardBypassCategories.contains(t.category)
            }
        }

        // Fully authenticated (SPF+DKIM+DMARC pass):
        // Suppress intent-only threats from authenticated senders.
        // Also withheld in a flagged folder (auth passing doesn't make junk safe).
        if auth.allPass && !flaggedFolder && !confirmedThreats.isEmpty {
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

        // Apply whitelist policy (final pass). Not honored in a flagged folder — a
        // whitelist match is only the From address, which a spoof reproduces; a
        // whitelisted sender's mail sitting in Junk should not be waved through.
        let senderPolicy = whitelist.policy(for: from)
        if senderPolicy.isWhitelisted && !flaggedFolder {
            confirmedThreats = confirmedThreats.filter { t in
                senderPolicy.shouldAlert(category: t.category, intentLayers: intent.score)
            }
        }

        // ── Record sender history ───────────────────────────────────
        // Only the Inbox banks "clean" credit toward sender trust. Threats are recorded from
        // anywhere, but a clean scan only builds trust when it's a real Inbox message — so a
        // spam/junk/archive message (or a mis-classified localized junk folder that fell
        // through to .custom) can never earn a domain the .trusted status that suppresses
        // Inbox alerts. This closes the junk-poisons-inbox-trust channel regardless of locale.
        let hadThreat = !confirmedThreats.isEmpty
        if !senderDomain.isEmpty && (hadThreat || folderRole == .inbox) {
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
            // Always record to the alert log. On the backlog sweep, only weaponized
            // (hard-bypass / critical) finds raise a user notification when they're in a
            // newly-covered folder (junk/trash/archive) — lesser matches in that
            // pre-existing pile are logged silently to avoid a burst. Inbox keeps its
            // prior always-notify behavior; live-poll finds (new mail, rescued-from-junk)
            // always notify. `isCritical` uses the effective `finalSeverity` so an
            // intent-driven CRITICAL (high pattern + critical intent score) is never
            // silently downgraded to a suppressed backlog notification.
            let isCritical = finalSeverity == .critical
                || confirmedThreats.contains { hardBypassCategories.contains($0.category) }
            let suppressPopup = isBacklog && Self.isInExpandedCoverageSubtree(forPath: filePath) && !isCritical
            logger.alert(alert)
            if suppressPopup {
                logger.info("\u{1F4E7} Backlog find (notification suppressed, non-critical): \(from) — \(subject)")
            } else {
                onAlert?(alert)
            }
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

    /// Enumerate .emlx files to consider this poll, with **per-mailbox fair budgeting** so no
    /// single folder can starve another under the global `limit`. A single DFS attributes each
    /// message to its nearest enclosing scannable mailbox "root" (the deepest `.mbox` ancestor
    /// that isn't a container). The budget is then filled by round-robin across roots — so every
    /// folder (incl. Inbox on multi-account setups) is served and none can hoard — taking ALL
    /// unseen (new) mail before ANY already-scanned file, so a large seen backlog never spends the
    /// budget on no-op re-reads while new mail waits. Roots are in priority order (Junk → Trash →
    /// Inbox → custom → Archive). `isSeen` reports whether a path is already in `scannedFiles`.
    ///
    /// Cost note: fair budgeting requires a full walk of the scanned mailboxes each poll (it can't
    /// know the shares without counting every root), i.e. O(scanned emails) stats per poll. That is
    /// fine at realistic sizes and is bounded by keeping Gmail "All Mail" (a whole-mailbox copy)
    /// off by default; only pathologically large multi-account stores would notice.
    private func findEmlxFiles(in dir: String, limit: Int, isSeen: (String) -> Bool) -> [String] {
        let fm = FileManager.default
        var byRoot: [String: (role: MailboxRole, files: [String])] = [:]

        // DFS carrying the current mailbox root context and whether we're inside [Gmail].
        func walk(_ d: String, rootPath: String?, rootRole: MailboxRole?, inGmail: Bool) {
            var curRoot = rootPath
            var curRole = rootRole
            var curInGmail = inGmail

            let name = (d as NSString).lastPathComponent
            if name.hasSuffix(".mbox") {
                var role = Self.mailboxRole(leaf: String(name.dropLast(".mbox".count)))
                if role == .container {
                    curInGmail = true   // descend; children are the real roots
                } else {
                    // Inside [Gmail]: Important/Starred are label views that always duplicate
                    // real mail (no config toggle) — always skip. All Mail / Sent / Drafts /
                    // Archive fall through to skipSubtree so their config toggles are honored
                    // (e.g. scan_all_mail=true actually scans [Gmail]/All Mail). At top level a
                    // same-named folder is a real user folder, scanned as .custom.
                    if curInGmail {
                        if role == .labelView { return }
                    } else if role == .labelView {
                        role = .custom
                    }
                    if skipSubtree(role: role) { return }
                    curRoot = d       // entering a new scannable mailbox root
                    curRole = role
                }
            }

            let entries: [String]
            do {
                entries = try fm.contentsOfDirectory(atPath: d)
            } catch {
                logger.warn("\u{1F4E7} Cannot read directory \(d): \(error.localizedDescription)")
                if d == dir { fdaRequired = true }
                return
            }
            for entry in entries {
                let full = (d as NSString).appendingPathComponent(entry)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: full, isDirectory: &isDir) else { continue }
                if isDir.boolValue {
                    walk(full, rootPath: curRoot, rootRole: curRole, inGmail: curInGmail)
                } else if entry.hasSuffix(".emlx"), let rp = curRoot, let rr = curRole {
                    byRoot[rp, default: (rr, [])].files.append(full)
                }
            }
        }

        walk(dir, rootPath: nil, rootRole: nil, inGmail: false)

        let roots = byRoot.sorted { a, b in
            let pa = Self.walkPriority(role: a.value.role)
            let pb = Self.walkPriority(role: b.value.role)
            return pa != pb ? pa < pb : a.key < b.key
        }
        guard !roots.isEmpty else { return [] }

        // Fill the budget by round-robin across roots so no folder is starved, and take ALL
        // unseen (new) mail before ANY already-scanned file — a huge already-scanned Junk folder
        // must never spend the budget on no-op re-reads while new Inbox mail waits. Roots are in
        // priority order, so within a round Junk is served just ahead of Inbox. Phase 1 = new
        // mail (what threat detection cares about); phase 2 fills any remainder with seen files
        // for change/rescan detection.
        var files: [String] = []
        func roundRobin(_ perRoot: [[String]]) {
            var idx = Array(repeating: 0, count: perRoot.count)
            var progressed = true
            while files.count < limit && progressed {
                progressed = false
                for r in 0..<perRoot.count where idx[r] < perRoot[r].count {
                    if files.count >= limit { break }
                    files.append(perRoot[r][idx[r]])
                    idx[r] += 1
                    progressed = true
                }
            }
        }
        roundRobin(roots.map { $0.value.files.filter { !isSeen($0) } })   // phase 1: new mail
        if files.count < limit {
            roundRobin(roots.map { $0.value.files.filter { isSeen($0) } }) // phase 2: rescan pool
        }
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
