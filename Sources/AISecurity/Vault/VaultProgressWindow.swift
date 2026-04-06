import AppKit

/// Floating progress panel for batch vault operations with cancel support.
final class VaultProgressWindow {

    private let panel: NSPanel
    private let progressBar: NSProgressIndicator
    private let statusLabel: NSTextField
    private let fileLabel: NSTextField
    private let cancelButton: NSButton

    /// Set to true from any thread to cancel the operation.
    private var _cancelled = false
    private let lock = NSLock()
    var cancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return _cancelled
    }

    init(title: String, total: Int) {
        // Panel setup
        panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 140),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        panel.title = title
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.center()

        let contentView = NSView(frame: panel.contentView!.bounds)

        // Status label: "Protecting 42 of 1,226 files..."
        statusLabel = NSTextField(labelWithString: "Preparing...")
        statusLabel.frame = NSRect(x: 20, y: 100, width: 380, height: 20)
        statusLabel.font = .systemFont(ofSize: 13, weight: .medium)
        contentView.addSubview(statusLabel)

        // Progress bar
        progressBar = NSProgressIndicator(frame: NSRect(x: 20, y: 72, width: 380, height: 20))
        progressBar.style = .bar
        progressBar.isIndeterminate = false
        progressBar.minValue = 0
        progressBar.maxValue = Double(total)
        progressBar.doubleValue = 0
        contentView.addSubview(progressBar)

        // File label: current file name
        fileLabel = NSTextField(labelWithString: "")
        fileLabel.frame = NSRect(x: 20, y: 48, width: 380, height: 16)
        fileLabel.font = .systemFont(ofSize: 11)
        fileLabel.textColor = .secondaryLabelColor
        fileLabel.lineBreakMode = .byTruncatingMiddle
        contentView.addSubview(fileLabel)

        // Cancel button
        cancelButton = NSButton(title: "Cancel", target: nil, action: nil)
        cancelButton.frame = NSRect(x: 310, y: 12, width: 90, height: 28)
        cancelButton.bezelStyle = .rounded
        cancelButton.target = self
        cancelButton.action = #selector(cancelClicked)
        contentView.addSubview(cancelButton)

        panel.contentView = contentView
    }

    @objc private func cancelClicked() {
        lock.lock()
        _cancelled = true
        lock.unlock()
        statusLabel.stringValue = "Cancelling..."
        cancelButton.isEnabled = false
    }

    func show() {
        panel.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    func dismiss() {
        panel.close()
    }

    /// Update progress from any thread. Safe to call from the C callback.
    func update(current: Int, total: Int, currentPath: String) {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.progressBar.doubleValue = Double(current)
            self.statusLabel.stringValue = "Protecting \(current) of \(total) files..."
            self.fileLabel.stringValue = (currentPath as NSString).lastPathComponent
        }
    }
}
