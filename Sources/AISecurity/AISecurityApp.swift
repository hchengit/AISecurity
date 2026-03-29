import AppKit
import SwiftUI

// MARK: - Entry Point

// Minimal AppKit entry point — no SwiftUI App, no MenuBarExtra.
// Matches the architecture of the original Python rumps menu bar app.

@main
enum AISecurity {
    @MainActor static var appDelegate: AppDelegate?

    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)   // no Dock icon
        let delegate = AppDelegate()
        appDelegate = delegate
        app.delegate = delegate
        app.run()
    }
}

// MARK: - App Delegate

@MainActor
class AppDelegate: NSObject, NSApplicationDelegate {

    var statusItem: NSStatusItem!
    private var daemon: SecurityDaemon?
    private var refreshTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Create status item in applicationDidFinishLaunching (run loop is active)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "shield.lefthalf.filled",
                                   accessibilityDescription: "AISecurity")
            button.image?.isTemplate = true   // adapts to light/dark menu bar
        }
        statusItem.isVisible = true

        // Warm up Rust security-core lazy statics
        SecurityCoreBridge.initialize()

        // Start daemon
        daemon = SecurityDaemon()
        daemon!.onStateChange = { [weak self] in
            DispatchQueue.main.async { self?.rebuildMenu() }
        }
        daemon!.start()
        rebuildMenu()

        // Periodic refresh
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            DispatchQueue.main.async { self?.rebuildMenu() }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        daemon?.stop()
    }

    // MARK: - Build Menu

    private func rebuildMenu() {
        guard let daemon = daemon else { return }
        let menu = NSMenu()
        menu.autoenablesItems = false

        let running = daemon.isRunning

        // Status
        let header = NSMenuItem(title: running ? "AISecurity Active" : "AISecurity Stopped",
                                action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)

        let modeItem = NSMenuItem(title: "Mode: \(daemon.mode.rawValue)",
                                  action: nil, keyEquivalent: "")
        modeItem.isEnabled = false
        menu.addItem(modeItem)

        menu.addItem(.separator())

        // Stats
        addStat(menu, "Emails scanned: \(daemon.emailsScanned)")
        addStat(menu, "Email threats: \(daemon.emailThreats)")
        addStat(menu, "Texts scanned: \(daemon.messagesScanned)")
        addStat(menu, "Text threats: \(daemon.messageThreats)")
        addStat(menu, "Total alerts: \(daemon.threatCount)")

        menu.addItem(.separator())

        // Actions
        menu.addItem(makeItem("Scan Downloads Now", action: #selector(scanDownloads)))
        menu.addItem(makeItem("View Recent Threats", action: #selector(showThreats)))
        menu.addItem(makeItem("View Activity Log",  action: #selector(showLog)))

        menu.addItem(.separator())

        if running {
            menu.addItem(makeItem("Stop Agent", action: #selector(stopAgent)))
        } else {
            menu.addItem(makeItem("Start Agent", action: #selector(startAgent)))
        }

        let quit = makeItem("Quit AISecurity", action: #selector(quitApp))
        quit.keyEquivalent = "q"
        menu.addItem(quit)

        statusItem.menu = menu

        // Update icon — SF Symbols adapt to light/dark menu bar
        let symbolName = daemon.threatCount > 0
            ? "exclamationmark.shield.fill"
            : "shield.lefthalf.filled"
        if let img = NSImage(systemSymbolName: symbolName,
                             accessibilityDescription: "AISecurity") {
            img.isTemplate = true
            statusItem.button?.image = img
        }
    }

    private func addStat(_ menu: NSMenu, _ title: String) {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = true
        menu.addItem(item)
    }

    private func makeItem(_ title: String, action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        return item
    }

    // MARK: - Actions

    @objc private func scanDownloads() {
        guard let daemon = daemon else { return }
        daemon.initModulesIfNeeded()
        let dir = (daemon.config.home as NSString).appendingPathComponent("Downloads")
        Task { @MainActor in
            await daemon.scanPath(dir)
            self.rebuildMenu()
        }
    }

    @objc private func showThreats() {
        guard let daemon = daemon else { return }
        WindowManager.shared.showThreats(daemon: daemon)
    }

    @objc private func showLog() {
        guard let daemon = daemon else { return }
        WindowManager.shared.showLog(config: daemon.config)
    }

    @objc private func startAgent() {
        if daemon == nil { daemon = SecurityDaemon() }
        daemon!.start()
        rebuildMenu()
    }

    @objc private func stopAgent() {
        daemon?.stop()
        rebuildMenu()
    }

    @objc private func quitApp() {
        daemon?.stop()
        NSApplication.shared.terminate(nil)
    }
}

// MARK: - Window Manager

@MainActor
final class WindowManager {
    static let shared = WindowManager()

    private var threatsWindow: NSWindow?
    private var logWindow: NSWindow?

    func showThreats(daemon: SecurityDaemon) {
        if let w = threatsWindow, w.isVisible {
            w.makeKeyAndOrderFront(nil)
            NSApplication.shared.activate(ignoringOtherApps: true)
            return
        }
        let alerts = daemon.getRecentAlerts()
        let view = ThreatsWindowView(alerts: alerts, whitelist: daemon.whitelist)
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: controller)
        window.title = "AISecurity \u{2014} Recent Threats"
        window.setContentSize(NSSize(width: 620, height: 500))
        window.styleMask = [.titled, .closable, .resizable, .miniaturizable]
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        threatsWindow = window
    }

    func showLog(config: SecurityConfig) {
        if let w = logWindow, w.isVisible {
            w.makeKeyAndOrderFront(nil)
            NSApplication.shared.activate(ignoringOtherApps: true)
            return
        }
        let view = LogWindowView(config: config)
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: controller)
        window.title = "AISecurity \u{2014} Activity Log"
        window.setContentSize(NSSize(width: 620, height: 400))
        window.styleMask = [.titled, .closable, .resizable, .miniaturizable]
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        logWindow = window
    }
}

// MARK: - Threats Window (SwiftUI)

struct ThreatsWindowView: View {
    let alerts: [SecurityAlert]
    let whitelist: SenderWhitelist?
    @State private var dismissed: Set<String> = Self.loadDismissed()
    @State private var showDeleteConfirm = false
    @State private var whitelistConfirmSender: String?

    var visibleAlerts: [SecurityAlert] {
        alerts.filter { !dismissed.contains(alertId($0)) }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.title2)
                Text("Recent Threats")
                    .font(.title2.bold())
                Spacer()
                if !visibleAlerts.isEmpty {
                    Button("Clear All") {
                        for a in visibleAlerts { dismissed.insert(alertId(a)) }
                        Self.saveDismissed(dismissed)
                    }
                    .buttonStyle(.bordered)

                    Button(action: { showDeleteConfirm = true }) {
                        Label("Delete All", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                }
                Text("\(visibleAlerts.count) alert\(visibleAlerts.count == 1 ? "" : "s")")
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(.bar)

            Divider()

            if visibleAlerts.isEmpty {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.green)
                    Text("No threats detected")
                        .font(.title3)
                    Text("The agent is monitoring your system.")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                List {
                    ForEach(visibleAlerts.indices, id: \.self) { i in
                        let alert = visibleAlerts[i]
                        threatRow(alert)
                            .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                                Button(role: .destructive) {
                                    deleteAlert(alert)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                                Button {
                                    dismissed.insert(alertId(alert))
                                    Self.saveDismissed(dismissed)
                                } label: {
                                    Label("Dismiss", systemImage: "eye.slash")
                                }
                                .tint(.orange)
                            }
                            .swipeActions(edge: .leading, allowsFullSwipe: false) {
                                Button {
                                    if alert.type == "EMAIL_THREAT_DETECTED" {
                                        openInMail(alert)
                                    } else {
                                        openMessages(alert)
                                    }
                                } label: {
                                    Label("Open", systemImage: alert.type == "EMAIL_THREAT_DETECTED" ? "envelope" : "message")
                                }
                                .tint(.blue)

                                if let sender = alert.from ?? alert.sender, !sender.isEmpty,
                                   whitelist != nil {
                                    Button {
                                        whitelistConfirmSender = sender
                                    } label: {
                                        Label("Trust", systemImage: "person.badge.shield.checkmark")
                                    }
                                    .tint(.green)
                                }
                            }
                    }
                }
            }
        }
        .frame(minWidth: 560, minHeight: 350)
        .alert("Delete All Threats?", isPresented: $showDeleteConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Delete All", role: .destructive) {
                deleteAllAlerts()
            }
        } message: {
            Text("This permanently deletes all threat records from the alerts log. This cannot be undone.")
        }
        .alert("Trust Sender?", isPresented: Binding(
            get: { whitelistConfirmSender != nil },
            set: { if !$0 { whitelistConfirmSender = nil } }
        )) {
            Button("Cancel", role: .cancel) { whitelistConfirmSender = nil }
            Button("Trust Sender") {
                if let sender = whitelistConfirmSender {
                    whitelist?.add(sender, note: "Trusted from threats view")
                    // Dismiss all alerts from this sender
                    for a in visibleAlerts where (a.from ?? a.sender) == sender {
                        dismissed.insert(alertId(a))
                    }
                    Self.saveDismissed(dismissed)
                }
                whitelistConfirmSender = nil
            }
        } message: {
            if let sender = whitelistConfirmSender {
                Text("Add \(sender) to your trusted senders list? Future emails/messages from this sender will skip social engineering and urgency checks.\n\nMalicious attachments, URLs, and malware will still be detected.")
            }
        }
    }

    // MARK: - Threat Row

    @ViewBuilder
    private func threatRow(_ alert: SecurityAlert) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                SeverityBadge(severity: alert.severity)
                Text(alert.type == "EMAIL_THREAT_DETECTED" ? "EMAIL" : "MESSAGE")
                    .font(.headline.monospaced())
                Spacer()
                Text(formatTimestamp(alert.timestamp))
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Text(alert.message)
                .font(.body)
                .lineLimit(3)
            if let from = alert.from ?? alert.sender {
                Label(from, systemImage: "person")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            if let subject = alert.subject {
                Label(subject, systemImage: "envelope")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    // MARK: - Actions

    private static let mailAppPath: String = {
        // Prefer /System/Applications, fall back to /Applications
        for candidate in ["/System/Applications/Mail.app", "/Applications/Mail.app"] {
            if FileManager.default.fileExists(atPath: candidate) { return candidate }
        }
        return "/System/Applications/Mail.app"
    }()

    private func openInMail(_ alert: SecurityAlert) {
        // Open the .emlx file directly in Mail if we have the path
        if let fp = alert.filePath, FileManager.default.fileExists(atPath: fp) {
            NSWorkspace.shared.open(
                [URL(fileURLWithPath: fp)],
                withApplicationAt: URL(fileURLWithPath: Self.mailAppPath),
                configuration: NSWorkspace.OpenConfiguration()
            )
            return
        }
        // Fallback: open Mail app
        NSWorkspace.shared.open(URL(fileURLWithPath: Self.mailAppPath))
    }

    private func openMessages(_ alert: SecurityAlert) {
        let sender = alert.sender ?? ""
        if let url = URL(string: "imessage://\(sender)") {
            NSWorkspace.shared.open(url)
        } else {
            NSWorkspace.shared.open(URL(string: "imessage://")!)
        }
    }

    private func showInFinder(_ path: String) {
        let url = URL(fileURLWithPath: path)
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }

    /// Delete a single alert from alerts.log and dismiss it
    private func deleteAlert(_ alert: SecurityAlert) {
        dismissed.insert(alertId(alert))
        Self.saveDismissed(dismissed)
        Self.removeFromAlertsLog(matching: alertId(alert))
    }

    /// Delete ALL visible alerts — archives alerts.log and clears dismissed
    private func deleteAllAlerts() {
        let alertsPath = Self.alertsLogPath
        let archivePath = alertsPath + ".old"
        let fm = FileManager.default
        try? fm.removeItem(atPath: archivePath)
        try? fm.moveItem(atPath: alertsPath, toPath: archivePath)
        fm.createFile(atPath: alertsPath, contents: nil)
        dismissed.removeAll()
        Self.saveDismissed(dismissed)
    }

    // MARK: - Persistence

    private func alertId(_ alert: SecurityAlert) -> String {
        "\(alert.timestamp)-\(alert.type)-\(alert.from ?? alert.sender ?? "")"
    }

    private static let dismissedPath: String = {
        (SecurityConfig.shared.securityDir as NSString).appendingPathComponent("dismissed.json")
    }()

    private static let alertsLogPath: String = {
        (SecurityConfig.shared.paths.logDir as NSString).appendingPathComponent("alerts.log")
    }()

    private static func loadDismissed() -> Set<String> {
        guard let data = FileManager.default.contents(atPath: dismissedPath),
              let arr = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return Set(arr)
    }

    private static func saveDismissed(_ ids: Set<String>) {
        if let data = try? JSONEncoder().encode(Array(ids)) {
            try? data.write(to: URL(fileURLWithPath: dismissedPath))
        }
    }

    /// Remove lines from alerts.log that match the given alert ID
    private static func removeFromAlertsLog(matching id: String) {
        guard let data = FileManager.default.contents(atPath: alertsLogPath),
              let content = String(data: data, encoding: .utf8) else { return }
        let parts = id.split(separator: "-", maxSplits: 2)
        guard parts.count >= 2 else { return }
        let timestamp = String(parts[0])
        let filtered = content.components(separatedBy: "\n")
            .filter { line in
                !line.contains(timestamp) || line.isEmpty ? true :
                    !line.contains(String(parts[1]))
            }
            .joined(separator: "\n")
        try? filtered.data(using: .utf8)?.write(to: URL(fileURLWithPath: alertsLogPath))
    }

    private func formatTimestamp(_ iso: String) -> String {
        let formatter = ISO8601DateFormatter()
        guard let date = formatter.date(from: iso) else { return iso }
        let display = DateFormatter()
        display.dateStyle = .short
        display.timeStyle = .medium
        return display.string(from: date)
    }
}

// MARK: - Log Window (SwiftUI)

struct LogWindowView: View {
    let config: SecurityConfig
    @State private var logLines: [String] = []
    @State private var refreshTimer: Timer?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "doc.text")
                    .font(.title2)
                Text("Activity Log")
                    .font(.title2.bold())
                Spacer()
                Button("Refresh") { loadLog() }
                    .buttonStyle(.bordered)
            }
            .padding()
            .background(.bar)

            Divider()

            if logLines.isEmpty {
                Spacer()
                Text("No log entries yet.")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(logLines.indices, id: \.self) { i in
                            Text(logLines[i])
                                .font(.system(.caption, design: .monospaced))
                                .textSelection(.enabled)
                                .padding(.horizontal, 8)
                        }
                    }
                    .padding(.vertical, 8)
                }
            }
        }
        .frame(minWidth: 500, minHeight: 250)
        .onAppear {
            loadLog()
            refreshTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
                loadLog()
            }
        }
        .onDisappear {
            refreshTimer?.invalidate()
            refreshTimer = nil
        }
    }

    private func loadLog() {
        let logPath = (config.audit.logDir as NSString)
            .appendingPathComponent("security.log")
        guard let data = FileManager.default.contents(atPath: logPath),
              let content = String(data: data, encoding: .utf8) else {
            logLines = ["(no log file found at \(logPath))"]
            return
        }
        let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }
        logLines = Array(lines.suffix(200).reversed())
    }
}

// MARK: - Severity Badge

struct SeverityBadge: View {
    let severity: SeverityLevel

    var body: some View {
        Text(severity.rawValue)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.2))
            .foregroundColor(color)
            .clipShape(RoundedRectangle(cornerRadius: 4))
    }

    private var color: Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .blue
        }
    }
}
