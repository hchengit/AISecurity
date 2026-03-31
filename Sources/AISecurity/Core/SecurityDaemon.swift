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
    @Published var scanStatusMessage: String?

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
    private var modulesReady = false

    // MARK: - Timers

    private var clipboardTimer: Timer?
    private var scheduledScanTimer: DispatchSourceTimer?
    private var statusWriterTimer: DispatchSourceTimer?
    private var lastClipboard = ""
    private var startedAt = ""

    // MARK: - Init (lightweight — no module creation)

    init() {
        let cfg = SecurityConfig.shared
        self.config = cfg
        self.mode = cfg.mode
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
        emailScanner = EmailScanner(logger: logger, whitelist: whitelist)
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
                    // Show in-app alert for vault file access (macOS notifications may be suppressed)
                    if alert.type == "VAULT_FILE_ACCESS" {
                        let a = NSAlert()
                        a.messageText = "\u{1F6A8} Vault File Access Detected"
                        a.informativeText = alert.message
                        a.alertStyle = .critical
                        a.addButton(withTitle: "OK")
                        NSApplication.shared.activate(ignoringOtherApps: true)
                        a.runModal()
                    }
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
                self.threatCount += 1
            }
        }
        emailScanner.start()

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

        // 5. Clipboard monitor
        if config.promptInjectionGuard.enabled {
            startClipboardMonitor()
        }

        // 6. Scheduled scan
        if config.scheduledScan.enabled {
            let intervalSecs = Double(config.scheduledScan.intervalHours) * 3600
            let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
            timer.schedule(deadline: .now() + intervalSecs, repeating: intervalSecs)
            timer.setEventHandler { [weak self] in
                self?.runScheduledScan()
            }
            timer.resume()
            scheduledScanTimer = timer
        }

        // 7. Status file writer (every 10s)
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
        clipboardTimer?.invalidate()
        clipboardTimer = nil
        scheduledScanTimer?.cancel()
        scheduledScanTimer = nil
        statusWriterTimer?.cancel()
        statusWriterTimer = nil
        isRunning = false
        logger.info("\u{1F4F4} Mac Security Agent stopped")
        onStateChange?()
    }

    // MARK: - Clipboard Monitor

    private func startClipboardMonitor() {
        let intervalSec = Double(config.promptInjectionGuard.clipboardMonitorIntervalMs) / 1000.0
        clipboardTimer = Timer.scheduledTimer(withTimeInterval: intervalSec, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.checkClipboard()
            }
        }
        logger.info("\u{1F4CB} Clipboard monitor active (every \(config.promptInjectionGuard.clipboardMonitorIntervalMs)ms)")
    }

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
        // Sync scanner counts to daemon's @Published properties so the menu picks them up
        Task { @MainActor in
            self.emailsScanned = self.emailScanner.emailsScanned
            self.emailThreats = self.emailScanner.threatsFound
            self.messagesScanned = self.messagesScanner.messagesScanned
            self.messageThreats = self.messagesScanner.threatsFound
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
}
