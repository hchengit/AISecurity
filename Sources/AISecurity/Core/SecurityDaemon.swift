import Foundation
import AppKit

/// Main security daemon orchestrator — replaces mac-security-agent.js
/// Owns all modules, starts/stops them, handles clipboard monitoring and scheduled scans.
@MainActor
final class SecurityDaemon: ObservableObject {

    // MARK: - Published state for SwiftUI

    @Published var isRunning = false
    @Published var threatCount = 0
    @Published var emailsScanned = 0
    @Published var emailThreats = 0
    @Published var messagesScanned = 0
    @Published var messageThreats = 0
    @Published var mode: SecurityMode
    @Published var protectionTier: ProtectionTier
    @Published var scanStatusMessage: String?
    @Published var emailScannerStatus: String = "Starting..."

    /// The resolved effective config from Rust. Updated on tier change.
    private(set) var effectiveConfig: EffectiveSecurityConfig?

    /// Called when state changes so the menu can rebuild.
    var onStateChange: (() -> Void)?

    // MARK: - Modules (lazy — created on first start() to avoid blocking SwiftUI init)

    private(set) var logger: SecurityLogger!
    let config: SecurityConfig
    private(set) var whitelist: SenderWhitelist!
    private var detector: SensitiveDataDetector!
    private var guard_: PromptInjectionGuard!
    private var sanitizer: ExternalFileSanitizer!
    private(set) var watcher: FileWatcher!
    private var emailScanner: EmailScanner!
    private var messagesScanner: MessagesScanner!
    private var processMonitor: ProcessMonitor!
    private var tccMonitor: TCCMonitor!
    private var modelWatcher: ModelDirectoryWatcher!
    private var modulesReady = false

    // MARK: - Timers

    private var clipboardTimer: Timer?
    private var scheduledScanTimer: DispatchSourceTimer?
    private var feedRefreshTimer: DispatchSourceTimer?
    private var statusWriterTimer: DispatchSourceTimer?
    private var lastClipboard = ""
    private var startedAt = ""

    // MARK: - Init (lightweight — no module creation)

    init() {
        let cfg = SecurityConfig.shared
        self.config = cfg
        self.mode = cfg.mode
        self.protectionTier = cfg.protectionTier
    }

    /// Create all modules. Called once from start() or on-demand.
    func initModulesIfNeeded() { initModules() }
    private func initModules() {
        guard !modulesReady else { return }
        modulesReady = true
        startedAt = ISO8601DateFormatter().string(from: Date())
        logger = SecurityLogger(config: config)
        logger.setupNotifications()
        whitelist = SenderWhitelist(securityDir: config.securityDir)
        detector = SensitiveDataDetector()
        guard_ = PromptInjectionGuard(logger: logger)
        sanitizer = ExternalFileSanitizer(logger: logger)
        watcher = FileWatcher(logger: logger)
        // Initialize vault file tracker
        VaultManager.shared.tracker = VaultFileTracker(logger: logger)
        emailScanner = EmailScanner(logger: logger, whitelist: whitelist)
        processMonitor = ProcessMonitor(logger: logger)
        tccMonitor = TCCMonitor(logger: logger)
        modelWatcher = ModelDirectoryWatcher(logger: logger)
        messagesScanner = MessagesScanner(
            logger: logger,
            whitelist: whitelist,
            scanIntervalMs: 60000,
            autoDeleteCritical: false
        )
    }

    // MARK: - Start

    func start() {
        guard !isRunning else { return }

        initModules()
        logger.info("\u{1F510} Mac Security Agent starting", data: [
            "mode": config.mode.rawValue,
            "version": "2.0.0-swift",
            "pid": "\(ProcessInfo.processInfo.processIdentifier)"
        ])

        // 1. Startup scan of Downloads
        if config.externalFileSanitizer.scanDownloadsOnStart {
            let san = sanitizer!
            let log = logger!
            let cfg = config
            Task.detached {
                log.info("\u{1F50D} Startup scan of Downloads...")
                let downloadsDir = (cfg.home as NSString).appendingPathComponent("Downloads")
                let results = san.scanDirectory(downloadsDir)
                let threats = results.filter { !$0.safe && !$0.threats.isEmpty }
                log.info("\u{1F4CA} Startup scan: \(results.count) files, \(threats.count) threats")

                if !threats.isEmpty && cfg.shouldQuarantine {
                    for r in threats {
                        _ = san.quarantine(r.filePath)
                    }
                }
            }
        }

        // 2. File watcher
        if config.fileWatcher.enabled {
            let san = sanitizer!
            watcher.sanitizer = san   // connect for real-time malware scanning
            watcher.onAlert = { [weak self] alert in
                guard let self else { return }
                if alert.severity == .critical && self.config.shouldQuarantine {
                    if let fp = alert.filePath, alert.type == "EXTERNAL_FILE_THREAT" {
                        _ = san.quarantine(fp)
                    }
                }
                Task { @MainActor in
                    self.threatCount += 1
                }
            }
            watcher.start()
        }

        // 3. Email scanner
        emailScanner.onAlert = { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.emailThreats = self.emailScanner.threatsFound
                self.emailsScanned = self.emailScanner.emailsScanned
                self.emailScannerStatus = self.emailScanner.scannerStatus
                self.threatCount += 1
            }
        }
        emailScanner.onStatusUpdate = { [weak self] scanned, threats, status in
            Task { @MainActor in
                guard let self else { return }
                self.emailsScanned = scanned
                self.emailThreats = threats
                self.emailScannerStatus = status
                // Sync total threat count from all scanners
                self.threatCount = threats + self.messageThreats
            }
        }
        emailScanner.start()

        // Delayed email scanner verification (5s after start) + FDA retry at 30s
        let scanner = emailScanner!
        let log = logger!
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 5) { [weak self] in
            let status = scanner.scannerStatus
            let fdaNeeded = scanner.fdaRequired
            let scanned = scanner.emailsScanned
            let threats = scanner.threatsFound
            if fdaNeeded {
                log.warn("\u{1F4E7} Email scanning inactive: Full Disk Access required for ~/Library/Mail")
            }
            Task { @MainActor [weak self] in
                self?.emailScannerStatus = status
                self?.emailsScanned = scanned
                self?.emailThreats = threats
            }
        }
        // FDA retry: if scanners didn't start because FDA wasn't granted yet, try again after 30s
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self else { return }
            if !scanner.isRunning || scanner.fdaRequired {
                let mailDir = SecurityConfig.shared.emailScanner.mailDir
                if FileManager.default.isReadableFile(atPath: mailDir) {
                    log.info("\u{1F4E7} FDA now available — restarting email scanner")
                    scanner.stop()
                    scanner.start()
                    Task { @MainActor [weak self] in
                        self?.emailScannerStatus = scanner.scannerStatus
                    }
                }
            }
        }

        // 4. Messages scanner
        messagesScanner.onAlert = { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.messageThreats = self.messagesScanner.threatsFound
                self.messagesScanned = self.messagesScanner.messagesScanned
                self.threatCount += 1
            }
        }
        messagesScanner.start()

        // 5. Load effective config from Rust (tier-aware settings)
        loadEffectiveConfig()

        // 5b. Clipboard monitor — use effective config if available, else fall back to direct config
        let clipboardEnabled = effectiveConfig?.clipboardMonitoringEnabled ?? config.promptInjectionGuard.enabled
        let clipboardMs = effectiveConfig?.clipboardIntervalMs ?? UInt64(config.promptInjectionGuard.clipboardMonitorIntervalMs)
        if clipboardEnabled {
            startClipboardMonitor(intervalMs: clipboardMs)
        }

        // 6. Scheduled scan — use effective config if available
        let scanEnabled = effectiveConfig?.scheduledScanEnabled ?? config.scheduledScan.enabled
        let scanHours = effectiveConfig?.scheduledScanIntervalHours ?? UInt32(config.scheduledScan.intervalHours)
        if scanEnabled {
            startScheduledScan(intervalHours: scanHours)
        }

        // 7. Self-protection monitor (watch own binary, config, logs)
        startSelfProtectionMonitor()

        // 8. Process monitor + TCC monitor (Phase 13: AI Agent Threat Defense)
        processMonitor.start()
        tccMonitor.start()

        // 8b. Threat intelligence feeds (Phase 14)
        let feedInitOk = SecurityCoreBridge.feedInit(securityDir: config.securityDir)
        if feedInitOk {
            // Initial refresh on background thread
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let count = SecurityCoreBridge.feedRefresh()
                let entries = SecurityCoreBridge.feedTotalEntries()
                self?.logger?.info("\u{1F310} Threat feeds refreshed: \(count) entries downloaded, \(entries) total cached")
            }
            // Periodic refresh every 5 hours
            let refreshTimer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
            refreshTimer.schedule(deadline: .now() + 5 * 3600, repeating: 5 * 3600)
            refreshTimer.setEventHandler { [weak self] in
                let count = SecurityCoreBridge.feedRefresh()
                let entries = SecurityCoreBridge.feedTotalEntries()
                self?.logger?.info("\u{1F310} Threat feeds auto-refresh: \(count) entries, \(entries) total")
            }
            refreshTimer.resume()
            feedRefreshTimer = refreshTimer
        } else {
            logger.warn("\u{1F310} Threat feeds: failed to initialize database")
        }

        // 9. Model directory watcher (discovers + watches + verifies in real-time)
        modelWatcher.start()

        // 10. Status file writer (every 10s)
        startStatusWriter()

        isRunning = true
        logger.info("\u{2705} Mac Security Agent running", data: [
            "pid": "\(ProcessInfo.processInfo.processIdentifier)",
            "mode": config.mode.rawValue
        ])
        onStateChange?()
    }

    // MARK: - Stop

    func stop() {
        guard modulesReady else { isRunning = false; return }
        watcher.stop()
        emailScanner.stop()
        messagesScanner.stop()
        processMonitor.stop()
        tccMonitor.stop()
        modelWatcher.stop()
        feedRefreshTimer?.cancel()
        feedRefreshTimer = nil
        clipboardTimer?.invalidate()
        clipboardTimer = nil
        scheduledScanTimer?.cancel()
        scheduledScanTimer = nil
        statusWriterTimer?.cancel()
        statusWriterTimer = nil
        selfProtectionSources.forEach { $0.cancel() }
        selfProtectionSources.removeAll()
        isRunning = false
        logger.info("\u{1F4F4} Mac Security Agent stopped")
        onStateChange?()
    }

    // MARK: - Clipboard Monitor

    private func checkClipboard() {
        guard let content = NSPasteboard.general.string(forType: .string),
              !content.isEmpty, content != lastClipboard else { return }
        lastClipboard = content

        // Check prompt injection
        let _ = guard_.validate(content, source: "clipboard")

        // Check sensitive data
        let findings = detector.scanText(content, source: "clipboard")
        let significant = findings.filter { $0.severity >= .high }
        if !significant.isEmpty {
            let topSeverity = significant.map(\.severity).max() ?? .high
            logger.alert(SecurityAlert(
                type: "SENSITIVE_DATA_IN_CLIPBOARD",
                severity: topSeverity,
                message: "\u{1F4CB} Clipboard contains: \(significant.map(\.label).joined(separator: ", "))",
                findings: significant.map { FindingDetail(label: $0.label, category: $0.category, severity: $0.severity) }
            ))
            Task { @MainActor in
                self.threatCount += 1
            }
        }
    }

    // MARK: - Scheduled Scan

    private func runScheduledScan() {
        logger.info("\u{23F0} Running scheduled scan...")
        for dir in config.scheduledScan.scanDirectories {
            let results = sanitizer.scanDirectory(dir)
            let threats = results.filter { !$0.safe && !$0.threats.isEmpty }
            if !threats.isEmpty {
                logger.alert(SecurityAlert(
                    type: "SCHEDULED_SCAN_THREATS",
                    severity: .high,
                    message: "\u{1F50D} Scheduled scan: \(threats.count) threat(s) in \(dir)"
                ))
            }
        }
    }

    // MARK: - Status Writer

    private func startStatusWriter() {
        let statusFile = (config.securityDir as NSString).appendingPathComponent("status.json")
        writeStatus(to: statusFile)

        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [weak self] in
            self?.writeStatus(to: statusFile)
        }
        timer.resume()
        statusWriterTimer = timer
    }

    private func writeStatus(to path: String) {
        // Sync scanner counts to daemon's @Published properties and rebuild menu
        Task { @MainActor in
            self.emailsScanned = self.emailScanner.emailsScanned
            self.emailThreats = self.emailScanner.threatsFound
            self.messagesScanned = self.messagesScanner.messagesScanned
            self.messageThreats = self.messagesScanner.threatsFound
            self.onStateChange?()
        }

        let status: [String: Any] = [
            "pid": ProcessInfo.processInfo.processIdentifier,
            "running": true,
            "mode": config.mode.rawValue,
            "startedAt": startedAt,
            "emailsScanned": emailScanner.emailsScanned,
            "threatsFound": emailScanner.threatsFound,
            "messagesScanned": messagesScanner.messagesScanned,
            "textThreats": messagesScanner.threatsFound,
            "updatedAt": ISO8601DateFormatter().string(from: Date())
        ]

        if let data = try? JSONSerialization.data(withJSONObject: status, options: .prettyPrinted) {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    // MARK: - Self-Protection Monitor

    private var selfProtectionSources: [DispatchSourceFileSystemObject] = []

    /// Monitor critical app files for tampering: binary, config (NOT data files we write to).
    /// We only watch files that should NOT change during normal operation.
    /// Data files (sender-history.json, threat-feeds.db, email state, etc.) are excluded
    /// because the app itself writes to them constantly.
    private func startSelfProtectionMonitor() {
        let criticalPaths = [
            (config.securityDir as NSString).appendingPathComponent("config.toml"),        // config file
            (config.securityDir as NSString).appendingPathComponent("notification-config.json"), // credentials
        ]

        // Also monitor the app bundle
        let appBundlePath = Bundle.main.bundlePath
        let allPaths = criticalPaths + [appBundlePath]

        for path in allPaths {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            let fd = open(path, O_EVTONLY)
            guard fd >= 0 else { continue }

            let source = DispatchSource.makeFileSystemObjectSource(
                fileDescriptor: fd,
                eventMask: [.write, .delete, .rename, .attrib],
                queue: DispatchQueue.global(qos: .utility)
            )

            source.setEventHandler { [weak self] in
                let flags = source.data
                var changes: [String] = []
                if flags.contains(.write) { changes.append("modified") }
                if flags.contains(.delete) { changes.append("deleted") }
                if flags.contains(.rename) { changes.append("renamed") }
                if flags.contains(.attrib) { changes.append("permissions changed") }

                let alert = SecurityAlert(
                    type: "SELF_PROTECTION",
                    severity: .critical,
                    message: "\u{1F6A8} AISecurity self-protection: \(path) was \(changes.joined(separator: ", "))",
                    filePath: path
                )
                self?.logger.alert(alert)
                Task { @MainActor in
                    self?.threatCount += 1
                }
            }

            source.setCancelHandler { close(fd) }
            source.resume()
            selfProtectionSources.append(source)
        }

        logger.info("\u{1F6E1} Self-protection active: monitoring \(selfProtectionSources.count) critical paths")
    }

    // MARK: - Manual Scan

    func scanPath(_ targetPath: String) async {
        initModules()
        let resolved = targetPath.replacingOccurrences(of: "~", with: config.home)
        logger.info("\u{1F50D} Scanning: \(resolved)")

        let fm = FileManager.default
        guard fm.fileExists(atPath: resolved) else {
            logger.warn("Not found: \(resolved)")
            scanStatusMessage = "Path not found: \(resolved)"
            return
        }

        var isDir: ObjCBool = false
        fm.fileExists(atPath: resolved, isDirectory: &isDir)

        if isDir.boolValue {
            let results = sanitizer.scanDirectory(resolved)
            let threats = results.filter { !$0.safe && !$0.threats.isEmpty }
            let msg = "Scanned \(results.count) files — \(threats.count) threat\(threats.count == 1 ? "" : "s") found."
            logger.info(msg)
            scanStatusMessage = msg
        } else {
            let result = sanitizer.scanFile(resolved)
            if result.safe {
                logger.info("\u{2705} Clean: \(resolved)")
                scanStatusMessage = "Clean: \((resolved as NSString).lastPathComponent)"
            } else {
                logger.info("\u{1F6A8} THREAT in \(resolved)")
                scanStatusMessage = "THREAT in \((resolved as NSString).lastPathComponent)"
            }
        }
    }

    // MARK: - Recent Alerts

    func getRecentAlerts() -> [SecurityAlert] {
        guard modulesReady else { return [] }
        return logger.getRecentAlerts(limit: 50)
    }

    // MARK: - Protection Tier

    /// Load the effective config from Rust on startup.
    func loadEffectiveConfig() {
        effectiveConfig = SecurityCoreBridge.getEffectiveConfig()
        if let eff = effectiveConfig {
            protectionTier = eff.protectionTier
        }
    }

    /// Switch to a new protection tier at runtime.
    /// Persists to config.toml via Rust FFI, then hot-reloads affected modules.
    func setProtectionTier(_ tier: ProtectionTier) {
        let oldTier = protectionTier
        NSLog("[AISecurity] setProtectionTier called: %@ → %@", oldTier.displayName, tier.displayName)

        // 1. Persist to config.toml via Rust
        let persisted = SecurityCoreBridge.setProtectionTier(tier)
        NSLog("[AISecurity] setProtectionTier persisted=%d", persisted ? 1 : 0)
        guard persisted else {
            logger?.warn("Failed to persist protection tier to config.toml")
            return
        }

        // 2. Get the new effective config
        let newConfig = SecurityCoreBridge.getEffectiveConfig()
        NSLog("[AISecurity] getEffectiveConfig returned=%@", newConfig != nil ? "OK tier=\(newConfig!.protectionTier.displayName)" : "NIL")
        guard let newConfig = newConfig else {
            // Even if effective config fails to load, still update the tier
            protectionTier = tier
            logger?.warn("Failed to load effective config after tier change — tier updated anyway")
            onStateChange?()
            return
        }

        let oldConfig = effectiveConfig
        effectiveConfig = newConfig
        protectionTier = tier

        // 3. Hot-reload: diff old vs new and start/stop only what changed
        applyEffectiveConfig(old: oldConfig, new: newConfig)

        logger?.info("🛡️ Protection tier changed: \(oldTier.displayName) → \(tier.displayName)")
        onStateChange?()
    }

    /// Apply the effective config by diffing old vs new and starting/stopping modules.
    private func applyEffectiveConfig(old: EffectiveSecurityConfig?, new: EffectiveSecurityConfig) {
        guard modulesReady else { return }

        // -- Clipboard monitor --
        let oldClipboard = old?.clipboardMonitoringEnabled ?? config.promptInjectionGuard.enabled
        if new.clipboardMonitoringEnabled && !oldClipboard {
            // Start clipboard monitor
            startClipboardMonitor(intervalMs: new.clipboardIntervalMs)
        } else if !new.clipboardMonitoringEnabled && oldClipboard {
            // Stop clipboard monitor
            clipboardTimer?.invalidate()
            clipboardTimer = nil
            logger.info("📋 Clipboard monitor stopped (tier change)")
        } else if new.clipboardMonitoringEnabled,
                  let oldMs = old?.clipboardIntervalMs,
                  new.clipboardIntervalMs != oldMs {
            // Interval changed — restart
            clipboardTimer?.invalidate()
            clipboardTimer = nil
            startClipboardMonitor(intervalMs: new.clipboardIntervalMs)
        }

        // -- Messages scanner --
        let oldMessages = old?.messagesScanningEnabled ?? config.messagesScanner.enabled
        if new.messagesScanningEnabled && !oldMessages {
            messagesScanner.start()
            logger.info("💬 Messages scanner started (tier change)")
        } else if !new.messagesScanningEnabled && oldMessages {
            messagesScanner.stop()
            logger.info("💬 Messages scanner stopped (tier change)")
        }

        // -- Scheduled scan --
        let oldScheduled = old?.scheduledScanEnabled ?? config.scheduledScan.enabled
        if new.scheduledScanEnabled && !oldScheduled {
            startScheduledScan(intervalHours: new.scheduledScanIntervalHours)
        } else if !new.scheduledScanEnabled && oldScheduled {
            scheduledScanTimer?.cancel()
            scheduledScanTimer = nil
            logger.info("⏰ Scheduled scan stopped (tier change)")
        } else if new.scheduledScanEnabled,
                  let oldHours = old?.scheduledScanIntervalHours,
                  new.scheduledScanIntervalHours != oldHours {
            // Interval changed — restart
            scheduledScanTimer?.cancel()
            scheduledScanTimer = nil
            startScheduledScan(intervalHours: new.scheduledScanIntervalHours)
        }

        logger.info("🛡️ Effective config applied: \(new.protectionTier.displayName)")
    }

    /// Start clipboard monitor with configurable interval.
    private func startClipboardMonitor(intervalMs: UInt64) {
        let intervalSec = Double(intervalMs) / 1000.0
        clipboardTimer = Timer.scheduledTimer(withTimeInterval: intervalSec, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.checkClipboard()
            }
        }
        logger.info("📋 Clipboard monitor active (every \(intervalMs)ms)")
    }

    /// Start scheduled scan with configurable interval.
    private func startScheduledScan(intervalHours: UInt32) {
        let intervalSecs = Double(intervalHours) * 3600
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + intervalSecs, repeating: intervalSecs)
        timer.setEventHandler { [weak self] in
            self?.runScheduledScan()
        }
        timer.resume()
        scheduledScanTimer = timer
        logger.info("⏰ Scheduled scan active (every \(intervalHours)h)")
    }
}
