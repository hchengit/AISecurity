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
        // Diagnostic: confirm we reach this point
        let diagPath = (NSHomeDirectory() as NSString).appendingPathComponent(".mac-security/logs/menubar-debug.log")
        var diag = "[\(Date())] applicationDidFinishLaunching reached. Creating status item...\n"

        // Integrity check: before we touch any data or load any modules, verify
        // the bundle we're running from matches its code signature. In a dev
        // build this is a no-op; in a production install (running from
        // /Applications/) a mismatch terminates the process with a visible
        // alert, preventing a tampered copy from starting the daemon.
        guard CodeSignatureGuard.verifyOrRefuseStartup() else {
            return   // verifyOrRefuseStartup already called NSApp.terminate
        }

        // Create status item in applicationDidFinishLaunching (run loop is active)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            updateMenuBarIcon(tier: SecurityConfig.shared.protectionTier, hasThreats: false)
            diag += "[\(Date())] Status item created. Frame: \(button.frame)\n"
        } else {
            diag += "[\(Date())] ERROR: statusItem.button is nil!\n"
        }
        statusItem.isVisible = true
        diag += "[\(Date())] statusItem.isVisible = true\n"
        try? diag.write(toFile: diagPath, atomically: true, encoding: .utf8)

        // Warm up Rust security-core lazy statics
        SecurityCoreBridge.initialize()

        // Install Keychain-backed master key into the Rust crypto core BEFORE
        // anything that reads encrypted app data (whitelist, manifest, etc.).
        // Fail closed: if we can't unlock the key store, we must NOT start the
        // daemon — that would silently downgrade to the old default-passphrase
        // path or write plaintext fallbacks.
        switch MasterKey.install() {
        case .installedExisting:
            diag += "[\(Date())] Master key loaded from Keychain\n"
        case .installedGenerated:
            diag += "[\(Date())] Master key generated and stored in Keychain (first run)\n"
        case .failed(let msg):
            diag += "[\(Date())] FATAL: master key install failed: \(msg)\n"
            try? diag.write(toFile: diagPath, atomically: true, encoding: .utf8)
            // Show a blocking alert and exit — do not proceed without a key.
            let alert = NSAlert()
            alert.messageText = "AISecurity cannot start"
            alert.informativeText = "The encryption master key could not be accessed in the login Keychain.\n\n\(msg)\n\nUnlock your Keychain and relaunch the app."
            alert.alertStyle = .critical
            alert.addButton(withTitle: "Quit")
            alert.runModal()
            NSApp.terminate(nil)
            return
        }
        try? diag.write(toFile: diagPath, atomically: true, encoding: .utf8)

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

        // Register for Finder Services (right-click > Services)
        // "Protect with AISecurity Vault" + "Hash Model with AISecurity"
        NSApp.servicesProvider = self
        NSApp.registerServicesMenuSendTypes([.fileURL, .string, NSPasteboard.PasteboardType("NSFilenamesPboardType")], returnTypes: [])
        NSUpdateDynamicServices()
    }

    func applicationWillTerminate(_ notification: Notification) {
        daemon?.stop()
    }

    // MARK: - Handle .vault file opens (double-click from Finder)

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        let vaultFiles = filenames.filter { $0.hasSuffix(".vault") }
        guard !vaultFiles.isEmpty else {
            sender.reply(toOpenOrPrint: .failure)
            return
        }

        // Activate app so dialogs appear in front
        NSApplication.shared.activate(ignoringOtherApps: true)

        guard ensureVaultSetup() else {
            sender.reply(toOpenOrPrint: .failure)
            return
        }

        // Ask: temporary or permanent decrypt?
        let choice = NSAlert()
        choice.messageText = "Decrypt \(vaultFiles.count) file(s)?"
        choice.informativeText = "Choose how to decrypt:"
        choice.alertStyle = .informational
        choice.addButton(withTitle: "Open Temporarily")  // first = default
        choice.addButton(withTitle: "Decrypt Permanently")
        choice.addButton(withTitle: "Cancel")
        let choiceResponse = choice.runModal()
        guard choiceResponse != .alertThirdButtonReturn else {
            sender.reply(toOpenOrPrint: .cancel)
            return
        }
        let isTemporary = (choiceResponse == .alertFirstButtonReturn)

        // Always require fresh auth
        VaultManager.shared.clearPassphrase()
        VaultManager.shared.withAuth(
            reason: "Authenticate to decrypt files",
            passphrasePrompt: "Enter Vault Passphrase to Decrypt",
            onPassphrase: { passphrase in
                VaultOperationScope.begin()
                for vf in vaultFiles {
                    let orig = String(vf.dropLast(".vault".count))
                    FinderTags.unlockFile(vf)
                    FinderTags.unlockFile(orig)
                }
                let result = VaultManager.shared.unlockFiles(vaultFiles, passphrase: passphrase)
                VaultOperationScope.end()
                if result.success {
                    let originalPaths = vaultFiles.map { String($0.dropLast(".vault".count)) }
                    if isTemporary {
                        // "Open Temporarily" must work regardless of where the
                        // .vault file lives (vault manifest, portable export
                        // folder, USB drive, iCloud, etc.). The original bug:
                        // this path hid the .vault but never registered with
                        // TemporaryDecryptMonitor, so re-encrypt + unhide
                        // never ran. Files outside the tracking manifest
                        // would get permanently-hidden .vault files.
                        //
                        // Fix sequence:
                        //   1. Verify plaintext actually materialized on disk.
                        //      If Rust unlock claimed success but wrote nothing
                        //      (iCloud placeholder, permission issue, etc.),
                        //      surface that clearly instead of hiding the .vault.
                        //   2. Hide only the .vault files whose plaintext
                        //      really exists.
                        //   3. Register ALL successfully-decrypted plaintext
                        //      paths with TemporaryDecryptMonitor so the
                        //      re-encrypt + unhide cleanup is scheduled.
                        //   4. Open the plaintext in its default app.

                        var materialized: [(vault: String, plaintext: String)] = []
                        var missing: [String] = []
                        for (vf, orig) in zip(vaultFiles, originalPaths) {
                            if FileManager.default.fileExists(atPath: orig) {
                                materialized.append((vf, orig))
                            } else {
                                missing.append(orig)
                            }
                        }

                        if !missing.isEmpty && materialized.isEmpty {
                            VaultDialogs.showError("Decryption reported success but no plaintext files were written. The .vault file(s) remain intact — try 'Decrypt Permanently' or decrypt via the Vault window.")
                            sender.reply(toOpenOrPrint: .failure)
                            return
                        }

                        // Hide only the .vaults whose plaintext actually landed.
                        for pair in materialized {
                            let url = URL(fileURLWithPath: pair.vault)
                            try? (url as NSURL).setResourceValue(true, forKey: .isHiddenKey)
                        }

                        // Schedule re-encryption so closing the plaintext
                        // re-seals the .vault and unhides it. Works for
                        // files outside the vault manifest — vaultLock is
                        // generic and doesn't require a manifest entry.
                        let plaintextPaths = materialized.map(\.plaintext)
                        TemporaryDecryptMonitor.shared.watch(
                            paths: plaintextPaths,
                            passphrase: passphrase,
                            securityDir: SecurityConfig.shared.securityDir
                        )

                        // Open each plaintext in its default app.
                        for pair in materialized {
                            NSWorkspace.shared.open(URL(fileURLWithPath: pair.plaintext))
                        }

                        if missing.isEmpty {
                            VaultDialogs.showSuccess("\(materialized.count) file(s) opened temporarily.\nThey will re-encrypt automatically when you close them.")
                        } else {
                            VaultDialogs.showSuccess("\(materialized.count) file(s) opened temporarily; \(missing.count) could not be decrypted (check Activity Log).")
                        }
                    } else {
                        // Permanent: remove from vault
                        let removeResult = VaultManager.shared.removeFiles(originalPaths, passphrase: passphrase)
                        if removeResult.success {
                            for orig in originalPaths {
                                FinderTags.removeTag(orig)
                                VaultManager.shared.untrackFiles([orig])
                            }
                            VaultManager.shared.syncTracker(passphrase: passphrase)
                        }
                        for orig in originalPaths {
                            if FileManager.default.fileExists(atPath: orig) {
                                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: orig)])
                            }
                        }
                        VaultDialogs.showSuccess("\(result.entriesAffected) file(s) permanently decrypted and removed from vault.")
                    }
                } else {
                    VaultDialogs.showError(result.message)
                }
                sender.reply(toOpenOrPrint: result.success ? .success : .failure)
            },
            onCancel: { sender.reply(toOpenOrPrint: .cancel) },
            onError: { msg in
                VaultDialogs.showError(msg)
                sender.reply(toOpenOrPrint: .failure)
            }
        )
    }

    // MARK: - Build Menu

    /// Check if the app has Full Disk Access by trying to read a protected directory.
    private func checkFDA() -> Bool {
        let testPath = (FileManager.default.homeDirectoryForCurrentUser.path as NSString)
            .appendingPathComponent("Library/Mail")
        return FileManager.default.isReadableFile(atPath: testPath)
    }

    private func rebuildMenu() {
        guard let daemon = daemon else { return }
        let menu = NSMenu()

        let running = daemon.isRunning
        let hasFDA = checkFDA()

        // Status header with tier and FDA indicator
        let tierName = daemon.protectionTier.displayName
        let statusText: String
        if !running {
            statusText = "\u{23F8}\u{FE0F}  AISecurity Sleeping"
        } else if hasFDA {
            statusText = "\u{1F7E2}  AISecurity — \(tierName)"
        } else {
            statusText = "\u{1F534}  AISecurity — \(tierName) (No FDA)"
        }
        let header = NSMenuItem(title: statusText, action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)

        // FDA warning if missing
        if running && !hasFDA {
            let fdaWarn = NSMenuItem(title: "    Grant Full Disk Access in System Settings", action: nil, keyEquivalent: "")
            fdaWarn.isEnabled = false
            menu.addItem(fdaWarn)
        }

        menu.addItem(.separator())

        // -- Protection Level selector (submenu) --
        let tierSubmenu = NSMenu()
        for tier in ProtectionTier.allCases {
            let isCurrent = (tier == daemon.protectionTier)
            let title = "\(tier.displayName) — \(tier.description)"
            let item = NSMenuItem(title: title, action: #selector(changeTier(_:)), keyEquivalent: "")
            item.target = self
            item.tag = tier.menuTag
            item.state = isCurrent ? .on : .off
            tierSubmenu.addItem(item)
        }
        let tierParent = NSMenuItem(title: "\u{1F6E1} Protection: \(daemon.protectionTier.displayName)", action: nil, keyEquivalent: "")
        tierParent.submenu = tierSubmenu
        menu.addItem(tierParent)

        // -- Agent Intent Protection toggle (approval-check kill switch) --
        //
        // Flips ~/.mac-security/bypass. While the file exists, these three
        // approval paths short-circuit to Allow (and still log to the
        // audit file as a bypass):
        //
        //   • PreToolUse hook (intent-hook) — Claude Code Bash/Write/Edit
        //   • MCP server (aisec-mcp) — verify_intent / evaluate_privacy
        //   • HTTP listener (:7459) — /intent/verify, /privacy/evaluate
        //
        // Toggling this does NOT disable email scanning, file watcher,
        // prompt-injection guard, vault, sensitive-data detection, model
        // verifier, or any other AISecurity protection — only the
        // agent-action approval gates.
        let bypassActive = isAgentBypassActive()
        let aiProtTitle = bypassActive
            ? "\u{1F916} Agent Intent Protection: OFF — approval bypassed"
            : "\u{1F916} Agent Intent Protection: ON"
        let aiProtItem = NSMenuItem(title: aiProtTitle, action: #selector(toggleAgentBypass), keyEquivalent: "")
        aiProtItem.target = self
        aiProtItem.state = bypassActive ? .off : .on
        menu.addItem(aiProtItem)

        // Dimmed subtitle so users know exactly what this controls.
        let aiProtSub = NSMenuItem(
            title: "    Approves agent shell/file/net actions before they run",
            action: nil, keyEquivalent: "")
        aiProtSub.isEnabled = false
        menu.addItem(aiProtSub)

        menu.addItem(.separator())

        // Stats
        addStat(menu, "Email: \(daemon.emailScannerStatus)")
        addStat(menu, "Emails scanned today: \(daemon.emailsScanned)")
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

        // Vault
        let vaultHeader = NSMenuItem(title: "\u{1F512} Vault", action: nil, keyEquivalent: "")
        vaultHeader.isEnabled = false
        menu.addItem(vaultHeader)
        menu.addItem(makeItem("Protect Files...", action: #selector(vaultProtectFiles)))
        menu.addItem(makeItem("Open Vault...", action: #selector(vaultOpenWindow)))
        menu.addItem(makeItem("Export Portable Vault...", action: #selector(vaultExportPortable)))
        menu.addItem(makeItem("Change Passphrase...", action: #selector(vaultChangePassphrase)))
        menu.addItem(makeItem("Forgot Passphrase...", action: #selector(vaultForgotPassphrase)))

        menu.addItem(.separator())

        // AI Models — grouped by runtime, hides tiny metadata blobs
        let manifest = loadModelManifest() ?? [:]
        let displayModels = filterUserFacingModels(manifest)
        let groupedModels = groupModelsByRuntime(displayModels)
        let modelsSubmenu = buildModelsSubmenu(grouped: groupedModels, totalHashed: manifest.count, displayCount: displayModels.count)
        let modelsParent = NSMenuItem(title: "\u{1F9E0} AI Models (\(displayModels.count))", action: nil, keyEquivalent: "")
        modelsParent.submenu = modelsSubmenu
        menu.addItem(modelsParent)

        menu.addItem(.separator())

        let notifHeader = NSMenuItem(title: "\u{1F514} Notifications", action: nil, keyEquivalent: "")
        notifHeader.isEnabled = false
        menu.addItem(notifHeader)
        menu.addItem(makeItem("Notification Settings...", action: #selector(openNotificationSettings)))

        menu.addItem(.separator())

        if running {
            menu.addItem(makeItem("Sleep", action: #selector(pauseAgent)))
        } else {
            menu.addItem(makeItem("Wake", action: #selector(resumeAgent)))
        }
        menu.addItem(makeItem("Restart", action: #selector(relaunchApp)))

        let quit = makeItem("Shut Down", action: #selector(quitApp))
        quit.keyEquivalent = "q"
        menu.addItem(quit)

        statusItem.menu = menu

        // Update icon — tier-aware + threat indicator, colored & sized for visibility
        debugLog("rebuildMenu: tier=\(daemon.protectionTier.displayName) threats=\(daemon.threatCount)")
        updateMenuBarIcon(tier: daemon.protectionTier, hasThreats: daemon.threatCount > 0)
    }

    /// Render the menu bar icon: always shows tier symbol + color. Threats = red tint instead.
    private func updateMenuBarIcon(tier: ProtectionTier, hasThreats: Bool) {
        guard let button = statusItem?.button else { return }

        // Always use the tier-specific symbol so the icon visually changes per tier
        let symbolName: String
        switch tier {
        case .relaxed:  symbolName = "shield"                 // outline
        case .balanced: symbolName = "shield.lefthalf.filled" // half-filled
        case .strict:   symbolName = "lock.shield"            // lock + shield
        }

        // Color: tier color normally, red if threats active
        let tintColor: NSColor
        if hasThreats {
            tintColor = .systemRed
        } else {
            switch tier {
            case .relaxed:  tintColor = .systemGreen
            case .balanced: tintColor = .systemBlue
            case .strict:   tintColor = .systemOrange
            }
        }

        let pointSize: CGFloat = 20
        let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: .medium)

        let baseImage: NSImage
        if let img = NSImage(systemSymbolName: symbolName, accessibilityDescription: "AISecurity") {
            baseImage = img
        } else if let img = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "AISecurity") {
            // Fallback if symbol not found on this macOS version
            baseImage = img
        } else {
            return
        }

        let sized = baseImage.withSymbolConfiguration(config) ?? baseImage

        // Draw tinted — NOT template, we want the color to show
        let drawSize = sized.size
        let tinted = NSImage(size: drawSize, flipped: false) { rect in
            sized.draw(in: rect)
            tintColor.set()
            rect.fill(using: .sourceAtop)
            return true
        }
        tinted.isTemplate = false
        button.image = tinted
    }

    private func addStat(_ menu: NSMenu, _ title: String) {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        // With autoenablesItems=true (default), action:nil items get greyed out.
        // Re-enable autoenablesItems=false at menu level is risky for other items.
        // Instead, use a dummy action to keep them visually enabled.
        item.action = #selector(noOp)
        item.target = self
        menu.addItem(item)
    }

    @objc func noOp() { /* dummy action so stat items appear enabled in menu */ }

    // MARK: - Model Manifest Helpers

    private struct ModelManifestEntry: Decodable {
        let hash: String
        let size_bytes: UInt64
        let first_seen: String
        let last_verified: String

        var sizeBytes: UInt64 { size_bytes }
    }

    private func loadModelManifest() -> [String: ModelManifestEntry]? {
        let path = (SecurityConfig.shared.securityDir as NSString)
            .appendingPathComponent("model-manifest.json")
        guard let data = FileManager.default.contents(atPath: path),
              let manifest = try? JSONDecoder().decode([String: ModelManifestEntry].self, from: data) else {
            return nil
        }
        return manifest
    }

    private func formatModelSize(_ bytes: UInt64) -> String {
        let gb = Double(bytes) / (1024 * 1024 * 1024)
        let mb = Double(bytes) / (1024 * 1024)
        if gb >= 1.0 { return String(format: "%.1f GB", gb) }
        if mb >= 1.0 { return String(format: "%.0f MB", mb) }
        return "\(bytes) B"
    }

    /// Filter manifest to only user-facing models.
    /// Hides: Ollama metadata blobs (<10MB), duplicates, non-model files in build dirs.
    private func filterUserFacingModels(_ manifest: [String: ModelManifestEntry]) -> [(String, ModelManifestEntry)] {
        manifest.filter { path, entry in
            // Hide Ollama blobs under 10MB (metadata, not model weights)
            if path.contains("/.ollama/models/blobs/sha256-") && entry.sizeBytes < 10 * 1024 * 1024 {
                return false
            }
            return true
        }.map { ($0.key, $0.value) }
    }

    /// Group models by the runtime/source directory they belong to.
    private func groupModelsByRuntime(_ models: [(String, ModelManifestEntry)]) -> [(String, [(String, ModelManifestEntry)])] {
        var groups: [String: [(String, ModelManifestEntry)]] = [:]

        for (path, entry) in models {
            let runtime = detectRuntime(path)
            groups[runtime, default: []].append((path, entry))
        }

        // Sort each group by size descending
        for key in groups.keys {
            groups[key]?.sort { $0.1.sizeBytes > $1.1.sizeBytes }
        }

        // Fixed display order
        let order = ["Ollama", "LM Studio", "LeanInfer", "Lean_llama.cpp", "HuggingFace", "MLX", "GPT4All", "Other"]
        var result: [(String, [(String, ModelManifestEntry)])] = []
        for name in order {
            if let items = groups[name], !items.isEmpty {
                result.append((name, items))
            }
        }
        return result
    }

    /// Detect which runtime a model belongs to by its path.
    private func detectRuntime(_ path: String) -> String {
        let lower = path.lowercased()
        if lower.contains("/.ollama/") { return "Ollama" }
        if lower.contains("/.lmstudio/") || lower.contains("/lm-studio/") { return "LM Studio" }
        if lower.contains("/leaninfer/") { return "LeanInfer" }
        if lower.contains("/lean_llama.cpp/") { return "Lean_llama.cpp" }
        if lower.contains("/huggingface/") { return "HuggingFace" }
        if lower.contains("/.cache/mlx/") { return "MLX" }
        if lower.contains("/gpt4all") { return "GPT4All" }
        return "Other"
    }

    /// Build the AI Models submenu with grouped, scrollable display.
    private func buildModelsSubmenu(
        grouped: [(String, [(String, ModelManifestEntry)])],
        totalHashed: Int,
        displayCount: Int
    ) -> NSMenu {
        let submenu = NSMenu()

        if grouped.isEmpty {
            let empty = NSMenuItem(title: "    No models tracked", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            submenu.addItem(empty)
            return submenu
        }

        for (runtime, models) in grouped {
            // Group header (bold-looking via prefix)
            let header = NSMenuItem(title: "\(runtime) (\(models.count))", action: nil, keyEquivalent: "")
            header.isEnabled = false
            submenu.addItem(header)

            // Show top 10 per group — most users have a few per runtime
            for (path, info) in models.prefix(10) {
                let name = (path as NSString).lastPathComponent
                // Truncate very long names
                let displayName = name.count > 45 ? String(name.prefix(42)) + "..." : name
                let size = formatModelSize(info.sizeBytes)
                let item = NSMenuItem(
                    title: "    \u{2705} \(displayName) (\(size))",
                    action: #selector(noOp),
                    keyEquivalent: ""
                )
                item.target = self
                item.toolTip = path
                submenu.addItem(item)
            }
            if models.count > 10 {
                let more = NSMenuItem(title: "    ... and \(models.count - 10) more", action: nil, keyEquivalent: "")
                more.isEnabled = false
                submenu.addItem(more)
            }
            submenu.addItem(.separator())
        }

        // Footer stats
        let hiddenCount = totalHashed - displayCount
        let summary = hiddenCount > 0
            ? "\(displayCount) shown, \(hiddenCount) metadata hidden"
            : "\(displayCount) tracked"
        let summaryItem = NSMenuItem(title: summary, action: nil, keyEquivalent: "")
        summaryItem.isEnabled = false
        submenu.addItem(summaryItem)

        return submenu
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

    /// Retained auth gate for tier change — must survive until callback fires.
    private var tierAuthGate: AuthGate?

    @objc func changeTier(_ sender: NSMenuItem) {
        guard let daemon = daemon else { return }
        let newTier = ProtectionTier.from(rawValue: sender.tag)
        guard newTier != daemon.protectionTier else { return }

        let isDowngrade = newTier.isDowngradeFrom(daemon.protectionTier)

        if isDowngrade {
            // Downgrade = risky action → require vault passphrase
            NSApplication.shared.activate(ignoringOtherApps: true)
            guard ensureVaultSetup() else { return }

            VaultManager.shared.withAuth(
                reason: "Authenticate to lower protection level",
                passphrasePrompt: "Enter Vault Passphrase to Downgrade",
                onPassphrase: { [weak self] _ in
                    // Passphrase verified — show confirmation
                    let alert = NSAlert()
                    alert.messageText = "Switch to \(newTier.displayName) protection?"
                    alert.informativeText = self?.downgradeDescription(from: daemon.protectionTier, to: newTier) ?? ""
                    alert.alertStyle = .warning
                    alert.addButton(withTitle: "Switch to \(newTier.displayName)")
                    alert.addButton(withTitle: "Cancel")
                    let response = alert.runModal()
                    guard response == .alertFirstButtonReturn else { return }

                    daemon.setProtectionTier(newTier)
                    self?.rebuildMenu()
                },
                onCancel: { },
                onError: { msg in
                    let alert = NSAlert()
                    alert.messageText = "Authentication Failed"
                    alert.informativeText = msg
                    alert.alertStyle = .warning
                    alert.runModal()
                }
            )
        } else {
            // Upgrade = safe action → Touch ID / system password (fast)
            tierAuthGate = AuthGate(sessionTimeoutSeconds: 60)
            tierAuthGate?.authenticate(reason: "Authenticate to increase protection level") { [weak self] success, error in
                defer { self?.tierAuthGate = nil }
                guard success else {
                    if let error = error {
                        let alert = NSAlert()
                        alert.messageText = "Authentication Failed"
                        alert.informativeText = error
                        alert.alertStyle = .warning
                        alert.runModal()
                    }
                    return
                }
                daemon.setProtectionTier(newTier)
                self?.rebuildMenu()
            }
        }
    }

    // MARK: - AI Agent Protection (bypass kill switch)

    /// Path to the bypass sentinel file. Honored by intent-hook, aisec-mcp,
    /// and the in-daemon HTTP listener via security_core::bypass::active().
    private var agentBypassPath: String {
        (SecurityConfig.shared.securityDir as NSString).appendingPathComponent("bypass")
    }

    private func isAgentBypassActive() -> Bool {
        FileManager.default.fileExists(atPath: agentBypassPath)
    }

    @objc func toggleAgentBypass() {
        if isAgentBypassActive() {
            // Currently bypassed → re-enabling protection.
            // No friction — going back to a safer state is always one click.
            enableAgentProtection()
        } else {
            // Currently protected → disabling = risky. Match the tier-
            // downgrade flow: require the vault passphrase, show an
            // explicit warning, and only proceed on confirmation.
            requireAuthToDisableAgentProtection()
        }
    }

    /// Enable protection: remove the bypass file. One click, no auth.
    private func enableAgentProtection() {
        try? FileManager.default.removeItem(atPath: agentBypassPath)
        rebuildMenu()
    }

    /// Disable protection: passphrase gate + explicit warning + log who did it.
    private func requireAuthToDisableAgentProtection() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        guard ensureVaultSetup() else { return }

        VaultManager.shared.withAuth(
            reason: "Authenticate to disable Agent Intent Protection",
            passphrasePrompt: "Enter Vault Passphrase to Disable Protection",
            onPassphrase: { [weak self] _ in
                guard let self = self else { return }

                let alert = NSAlert()
                alert.messageText = "Disable Agent Intent Protection?"
                alert.informativeText = """
                This toggle affects ONLY the routine approval gates for AI agents. Other AISecurity protections are not changed.

                WHAT TURNS OFF (routine approval):
                  • Shell / file / network actions — Claude Code and other MCP-aware agents can run commands (rm, curl, git push, etc.) and write files without being asked. Normal developer workflow stops stalling on approval prompts.

                WHAT STAYS ON — always, regardless of this toggle (critical-secret floor):
                  • SSH private keys, API keys (OpenAI sk-, Anthropic sk-ant-, GitHub ghp_, AWS AKIA), PEM private-key blocks, .env secrets, passwords
                  • Crypto wallet keys and BIP39 seed phrases (xprv, zprv, WIF, eth privkey)
                  • Credit-card numbers, bank routing / account numbers, CVVs
                  These are still blocked from leaving the machine in any LLM prompt. An explicit config.toml edit is required to allow them — not this menu.

                ALSO UNCHANGED:
                  • File watcher on ~/Downloads, ~/Desktop, ~/Documents
                  • Clipboard monitor, email + Messages phishing detection
                  • Prompt-injection guard, Vault, model verifier, threat feeds, process monitor, self-protection

                AUDIT TRAIL:
                  Every bypassed request and every floor block is appended to ~/.mac-security/logs/ai-services-audit.jsonl.

                Re-enable anytime from this menu — no passphrase needed to turn protection back on.
                """
                alert.alertStyle = .critical
                alert.addButton(withTitle: "Disable Protection")
                alert.addButton(withTitle: "Cancel")
                let response = alert.runModal()
                guard response == .alertFirstButtonReturn else { return }

                // Write the bypass sentinel.
                let path = self.agentBypassPath
                let parent = (path as NSString).deletingLastPathComponent
                try? FileManager.default.createDirectory(
                    atPath: parent, withIntermediateDirectories: true, attributes: nil)
                let iso = ISO8601DateFormatter().string(from: Date())
                let user = NSUserName()
                let payload = "bypass enabled \(iso) via menu bar by \(user)\n"
                try? payload.write(toFile: path, atomically: true, encoding: .utf8)

                self.rebuildMenu()
            },
            onCancel: { },
            onError: { msg in
                let alert = NSAlert()
                alert.messageText = "Authentication Failed"
                alert.informativeText = msg
                alert.alertStyle = .warning
                alert.runModal()
            }
        )
    }

    private func debugLog(_ msg: String) {
        let path = (NSHomeDirectory() as NSString).appendingPathComponent(".mac-security/logs/tier-debug.log")
        let line = "[\(Date())] \(msg)\n"
        if let fh = FileHandle(forWritingAtPath: path) {
            fh.seekToEndOfFile()
            fh.write(line.data(using: .utf8)!)
            fh.closeFile()
        } else {
            try? line.write(toFile: path, atomically: true, encoding: .utf8)
        }
    }

    /// Describe what gets disabled when downgrading tiers.
    private func downgradeDescription(from: ProtectionTier, to: ProtectionTier) -> String {
        var disabled: [String] = []

        if from != .relaxed && to == .relaxed {
            disabled.append("Clipboard monitoring")
            disabled.append("Messages scanning")
            disabled.append("Scheduled full scans")
            disabled.append("Auto-quarantine")
            disabled.append("Email intent analysis")
        } else if from == .strict && to == .balanced {
            disabled.append("Desktop directory monitoring")
            disabled.append("Auto-quarantine for HIGH severity (kept for CRITICAL)")
            disabled.append("Faster clipboard polling (5s instead of 2s)")
        }

        var text = "This will disable:\n"
        for item in disabled {
            text += "  • \(item)\n"
        }
        text += "\nAlways-forbidden protections (SSN, credit cards, wallet keys, etc.) remain active regardless of tier."
        return text
    }

    @objc private func resumeAgent() {
        if daemon == nil { daemon = SecurityDaemon() }
        daemon!.start()
        rebuildMenu()
    }

    @objc private func pauseAgent() {
        daemon?.stop()
        rebuildMenu()
    }

    // MARK: - Hash Model Service Handler (right-click > Services > "Hash Model with AISecurity")

    @objc func hashModelService(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        NSApplication.shared.activate(ignoringOtherApps: true)

        // Extract file paths from pasteboard
        guard let urls = pboard.readObjects(forClasses: [NSURL.self], options: [
            .urlReadingFileURLsOnly: true
        ]) as? [URL], !urls.isEmpty else {
            error.pointee = "No files selected" as NSString
            return
        }

        let modelExtensions: Set<String> = [
            "gguf", "ggml", "safetensors", "bin", "pth", "pt",
            "onnx", "mlmodel", "mlpackage", "npz", "npy"
        ]

        // Filter to model files only
        let rawModelPaths = urls.filter { url in
            let ext = url.pathExtension.lowercased()
            return modelExtensions.contains(ext) ||
                   url.lastPathComponent.hasPrefix("sha256-") // Ollama blobs
        }.map { $0.path }

        guard !rawModelPaths.isEmpty else {
            let alert = NSAlert()
            alert.messageText = "No Model Files Found"
            alert.informativeText = "Selected files are not recognized model formats.\nSupported: .gguf, .safetensors, .bin, .pth, .onnx, .mlmodel, .npz"
            alert.alertStyle = .warning
            alert.runModal()
            return
        }

        // Validate paths: reject symlinks and sensitive-root targets before
        // passing anything to the hasher. A user-invoked right-click Service
        // is exactly the surface where a dropped symlink attack would land.
        let (modelPaths, rejected) = PathGuard.validateBatch(rawModelPaths)
        if !rejected.isEmpty {
            let list = rejected.map { "• \($0.0)\n   \($0.1)" }.joined(separator: "\n")
            let alert = NSAlert()
            alert.messageText = "\(rejected.count) file(s) refused"
            alert.informativeText = "AISecurity won't hash these — they're symlinks or point into protected locations:\n\n\(list)"
            alert.alertStyle = .warning
            alert.runModal()
            // Proceed with whatever survived validation.
        }
        guard !modelPaths.isEmpty else { return }

        // Hash them via Rust model verifier
        if let json = SecurityCoreBridge.modelVerify(securityDir: SecurityConfig.shared.securityDir),
           let data = json.data(using: .utf8),
           let results = try? JSONDecoder().decode([[String: String]].self, from: data) {
            let newCount = results.filter { $0["status"] == "NewModel" }.count
            let verifiedCount = results.filter { $0["status"] == "Verified" }.count

            let alert = NSAlert()
            alert.messageText = "Model Hashing Complete"
            if newCount > 0 {
                alert.informativeText = "\(newCount) new model(s) hashed and added to manifest.\n\(verifiedCount) model(s) already tracked and verified."
            } else if verifiedCount > 0 {
                alert.informativeText = "\(verifiedCount) model(s) already tracked — hashes verified ✓"
            } else {
                alert.informativeText = "Models processed. Check Activity Log for details."
            }
            alert.alertStyle = .informational
            alert.runModal()
        } else {
            let alert = NSAlert()
            alert.messageText = "Hash Model"
            alert.informativeText = "Model verification triggered for \(modelPaths.count) file(s).\nCheck the Activity Log for results."
            alert.alertStyle = .informational
            alert.runModal()
        }

        rebuildMenu()
    }

    // MARK: - Vault Actions

    private func ensureVaultSetup() -> Bool {
        let mgr = VaultManager.shared
        if mgr.isSetup { return true }

        // First-time setup wizard
        guard let passphrase = VaultDialogs.runSetupWizard() else { return false }
        let result = mgr.setup()
        guard result.success else {
            VaultDialogs.showError(result.message)
            return false
        }
        guard mgr.setInitialPassphrase(passphrase) else {
            VaultDialogs.showError("Failed to set vault passphrase.")
            return false
        }
        return true
    }

    // MARK: - Finder Services Handler (right-click > Services > "Protect with AISecurity Vault")

    @objc func protectFilesService(_ pboard: NSPasteboard, userData: String, error: AutoreleasingUnsafeMutablePointer<NSString>) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        guard ensureVaultSetup() else {
            error.pointee = "Vault setup required" as NSString
            return
        }

        // Extract file paths from pasteboard
        guard let urls = pboard.readObjects(forClasses: [NSURL.self], options: [
            .urlReadingFileURLsOnly: true
        ]) as? [URL], !urls.isEmpty else {
            error.pointee = "No files selected" as NSString
            return
        }

        let rawPaths = urls.map { $0.path }

        // Protect operation is destructive (it rewrites the file as a .vault),
        // so a symlink attack here is worse than on hashing — it could encrypt
        // and irreversibly corrupt the target. Validate and bail out loudly on
        // any rejection so the user knows why their file wasn't encrypted.
        let (paths, rejected) = PathGuard.validateBatch(rawPaths)
        if !rejected.isEmpty {
            let list = rejected.map { "• \($0.0)\n   \($0.1)" }.joined(separator: "\n")
            let alert = NSAlert()
            alert.messageText = "\(rejected.count) file(s) refused"
            alert.informativeText = "AISecurity won't encrypt these — they're symlinks or point into protected locations (SSH keys, Keychain, system files):\n\n\(list)"
            alert.alertStyle = .warning
            alert.runModal()
        }
        guard !paths.isEmpty else {
            error.pointee = "All selected files were refused by path policy" as NSString
            return
        }

        // Pick protection level
        guard let protection = VaultDialogs.pickProtectionLevel() else { return }

        // Confirm
        guard VaultDialogs.confirmEncrypt(paths: paths, protection: protection) else { return }

        // Authenticate + add (use cached passphrase if available)
        VaultManager.shared.withAuth(
            reason: "Authenticate to protect files",
            passphrasePrompt: "Enter Vault Passphrase",
            onPassphrase: { passphrase in
                VaultOperationScope.begin()
                let result = VaultManager.shared.addFiles(paths, protection: protection, passphrase: passphrase)
                if result.success {
                    for path in paths {
                        FinderTags.addTag(path, protection: protection)
                    }
                    VaultManager.shared.trackFiles(paths, protection: protection)
                    VaultManager.shared.syncTracker(passphrase: passphrase)
                    NotificationCenter.default.post(name: .vaultDidChange, object: nil)
                    VaultDialogs.showSuccess(result.message)
                } else {
                    VaultDialogs.showError(result.message)
                }
                VaultOperationScope.end()
            },
            onCancel: {},
            onError: { VaultDialogs.showError($0) }
        )
    }

    // MARK: - Menu Bar Protect Files

    @objc private func vaultProtectFiles() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        guard ensureVaultSetup() else { return }

        // Pick protection level
        guard let protection = VaultDialogs.pickProtectionLevel() else { return }

        // File picker
        let panel = NSOpenPanel()
        panel.title = "Select Files to Protect"
        panel.message = "Choose files or folders to add to your vault."
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.canCreateDirectories = false

        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        let paths = panel.urls.map { $0.path }

        // Confirm
        guard VaultDialogs.confirmEncrypt(paths: paths, protection: protection) else { return }

        // Authenticate + add (reuses cached passphrase within session)
        VaultManager.shared.withAuth(
            reason: "Authenticate to protect files",
            passphrasePrompt: "Enter Vault Passphrase",
            onPassphrase: { passphrase in
                let useBatchProgress = paths.count > 20

                if useBatchProgress {
                    // Async batch with progress window
                    let progressWindow = VaultProgressWindow(title: "Protecting Files...", total: paths.count)
                    progressWindow.show()

                    VaultOperationScope.begin()

                    DispatchQueue.global(qos: .userInitiated).async {
                        let secDir = SecurityConfig.shared.securityDir

                        // C callback that updates the progress window and checks cancel
                        let callback: @convention(c) (UInt32, UInt32, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Bool = { current, total, pathPtr, userData in
                            guard let userData,
                                  let win = userData.assumingMemoryBound(to: VaultProgressWindow.self).pointee as VaultProgressWindow? else {
                                return true
                            }
                            let path = pathPtr.flatMap { String(cString: $0) } ?? ""
                            win.update(current: Int(current), total: Int(total), currentPath: path)
                            return !win.cancelled
                        }

                        // Pass progress window pointer as user data
                        var winRef = progressWindow
                        let result = withUnsafeMutablePointer(to: &winRef) { ptr in
                            SecurityCoreBridge.vaultAddWithProgress(
                                securityDir: secDir, paths: paths,
                                protection: protection, passphrase: passphrase,
                                callback: callback,
                                userData: UnsafeMutableRawPointer(ptr)
                            )
                        }

                        DispatchQueue.main.async {
                            progressWindow.dismiss()
                            VaultOperationScope.end()

                            if result.success {
                                for path in paths {
                                    FinderTags.addTag(path, protection: protection)
                                }
                                VaultManager.shared.trackFiles(paths, protection: protection)
                                VaultManager.shared.syncTracker(passphrase: passphrase)
                                VaultDialogs.showSuccess(result.message)
                            } else {
                                VaultDialogs.showError(result.message)
                            }
                        }
                    }
                } else {
                    // Small batch — synchronous (existing flow)
                    VaultOperationScope.begin()
                    let result = VaultManager.shared.addFiles(paths, protection: protection, passphrase: passphrase)
                    if result.success {
                        for path in paths {
                            FinderTags.addTag(path, protection: protection)
                        }
                        VaultManager.shared.trackFiles(paths, protection: protection)
                        VaultManager.shared.syncTracker(passphrase: passphrase)
                        VaultDialogs.showSuccess(result.message)
                    } else {
                        VaultDialogs.showError(result.message)
                    }
                    VaultOperationScope.end()
                }
            },
            onCancel: {},
            onError: { VaultDialogs.showError($0) }
        )
    }

    /// "Export Portable Vault..." — bundles one or more .vault files with the
    /// standalone Python decryptor so the user can move the bundle to a USB
    /// drive (or any other machine) and still decrypt on a computer without
    /// AISecurity installed. No passphrase, no key material travels in the
    /// export — only ciphertext + a public tool.
    @objc private func vaultExportPortable() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        PortableVaultExport.run()
    }

    @objc private func vaultOpenWindow() {
        guard ensureVaultSetup() else { return }

        // Reuse cached passphrase within session (cleared when vault window closes or app quits)
        VaultManager.shared.withAuth(
            reason: "Authenticate to open vault",
            passphrasePrompt: "Enter Vault Passphrase",
            onPassphrase: { passphrase in
                // Refresh watched-paths cache so FileWatcher can monitor vault files
                VaultManager.shared.syncTracker(passphrase: passphrase)
                DispatchQueue.main.async {
                    WindowManager.shared.showVault(
                        securityDir: SecurityConfig.shared.securityDir,
                        passphrase: passphrase
                    )
                }
            },
            onCancel: {},
            onError: { VaultDialogs.showError($0) }
        )
    }

    @objc private func vaultChangePassphrase() {
        guard ensureVaultSetup() else { return }

        // Check lockout before prompting
        if VaultManager.shared.isLockedOut {
            let secs = VaultManager.shared.lockoutRemainingSeconds
            VaultDialogs.showError("Vault locked out. Too many failed attempts.\nTry again in \(secs / 60)m \(secs % 60)s.")
            return
        }

        VaultManager.shared.authGate.authenticate(reason: "Authenticate to change vault passphrase") { success, error in
            guard success else {
                if let e = error { VaultDialogs.showError(e) }
                return
            }

            guard let passes = VaultDialogs.promptChangePassphrase() else { return }
            let result = VaultManager.shared.changePassphrase(old: passes.old, new: passes.new)
            if result.success {
                VaultManager.shared.syncTracker(passphrase: passes.new)
                VaultDialogs.showSuccess(result.message)
            } else {
                VaultDialogs.showError(result.message)
            }
        }
    }

    @objc private func vaultForgotPassphrase() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        if let newPass = VaultDialogs.promptForgotPassphrase() {
            VaultManager.shared.syncTracker(passphrase: newPass)
            VaultDialogs.showSuccess("Vault passphrase has been reset. You can now use your new passphrase.")
        }
    }

    // MARK: - Notification Settings

    @objc private func openNotificationSettings() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        NotificationSetupDialog.show()
    }

    // MARK: - App Lifecycle

    @objc private func relaunchApp() {
        daemon?.stop()
        VaultManager.shared.clearPassphrase()

        // Delegate the stop+restart dance to launchd directly. `launchctl
        // kickstart -k <service-target>` terminates the running instance and
        // launchd's KeepAlive=true then relaunches it. This replaces the
        // previous approach of invoking `/bin/zsh -c "...open -a \(appPath)..."`
        // where `appPath` was interpolated into a shell string — a shell
        // injection surface if the bundle path ever contained quotes or
        // command substitution metacharacters.
        //
        // Arguments are passed as a fixed array to Process, never parsed by
        // a shell, so there is no interpolation risk.
        let uid = getuid()
        let serviceTarget = "gui/\(uid)/com.aisecurity.shield"

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["kickstart", "-k", serviceTarget]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        try? task.run()

        // launchd will send SIGTERM to us; terminate explicitly as a fallback
        // in case kickstart fails (e.g. not managed by launchd in some dev flows).
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            NSApplication.shared.terminate(nil)
        }
    }

    @objc private func quitApp() {
        daemon?.stop()
        VaultManager.shared.clearPassphrase()
        NSApplication.shared.terminate(nil)
    }
}

// MARK: - Window Manager

@MainActor
final class WindowManager {
    static let shared = WindowManager()

    private var threatsWindow: NSWindow?
    private var logWindow: NSWindow?
    private var vaultWindow: NSWindow?

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
        window.setContentSize(NSSize(width: 1200, height: 900))
        window.styleMask = [.titled, .closable, .resizable, .miniaturizable]
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        threatsWindow = window
    }

    func showVault(securityDir: String, passphrase: String) {
        if let w = vaultWindow, w.isVisible {
            w.makeKeyAndOrderFront(nil)
            NSApplication.shared.activate(ignoringOtherApps: true)
            return
        }
        let view = VaultWindowView(securityDir: securityDir, passphrase: passphrase)
        let controller = NSHostingController(rootView: view)
        let window = NSWindow(contentViewController: controller)
        window.title = "AISecurity \u{2014} Vault"
        window.setContentSize(NSSize(width: 1200, height: 900))
        window.styleMask = [.titled, .closable, .resizable, .miniaturizable]
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
        vaultWindow = window
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
        window.setContentSize(NSSize(width: 1200, height: 900))
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
                    .font(.title)
                Text("Recent Threats")
                    .font(.title.bold())
                Spacer()
                if !visibleAlerts.isEmpty {
                    Button("Clear All") {
                        for a in visibleAlerts { dismissed.insert(alertId(a)) }
                        Self.saveDismissed(dismissed)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)

                    Button(action: { showDeleteConfirm = true }) {
                        Label("Delete All", systemImage: "trash")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.large)
                    .tint(.red)
                }
                Text("\(visibleAlerts.count) alert\(visibleAlerts.count == 1 ? "" : "s")")
                    .font(.title3)
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
                                // Open — only for emails and messages
                                if alert.type == "EMAIL_THREAT_DETECTED" {
                                    Button {
                                        openInMail(alert)
                                    } label: {
                                        Label("Open", systemImage: "envelope")
                                    }
                                    .tint(.blue)
                                } else if alert.type == "MESSAGE_THREAT_DETECTED" {
                                    Button {
                                        openMessages(alert)
                                    } label: {
                                        Label("Open", systemImage: "message")
                                    }
                                    .tint(.blue)
                                } else if let fp = alert.filePath {
                                    Button {
                                        showInFinder(fp)
                                    } label: {
                                        Label("Show", systemImage: "folder")
                                    }
                                    .tint(.blue)
                                }

                                // Trust — for emails and messages with a sender
                                if (alert.type == "EMAIL_THREAT_DETECTED" || alert.type == "MESSAGE_THREAT_DETECTED"),
                                   let sender = alert.from ?? alert.sender, !sender.isEmpty,
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
        .frame(minWidth: 1000, minHeight: 600)
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

    private func alertTypeLabel(_ type: String) -> (text: String, icon: String) {
        switch type {
        case "EMAIL_THREAT_DETECTED": return ("EMAIL", "envelope.fill")
        case "MESSAGE_THREAT_DETECTED": return ("MESSAGE", "message.fill")
        case "VAULT_FILE_ACCESS": return ("VAULT", "lock.shield")
        case "SELF_PROTECTION": return ("SELF-PROTECT", "shield.lefthalf.filled")
        case "EXTERNAL_FILE_THREAT": return ("MALWARE", "exclamationmark.triangle.fill")
        case "SENSITIVE_DATA_IN_FILE": return ("SENSITIVE DATA", "doc.text.magnifyingglass")
        case "PROTECTED_PATH_ACCESS": return ("PROTECTED PATH", "folder.badge.questionmark")
        default: return ("ALERT", "exclamationmark.shield")
        }
    }

    @ViewBuilder
    private func threatRow(_ alert: SecurityAlert) -> some View {
        let typeInfo = alertTypeLabel(alert.type)
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                SeverityBadge(severity: alert.severity)
                Text(typeInfo.text)
                    .font(.system(size: 18, weight: .bold, design: .monospaced))
                Spacer()
                Text(formatTimestamp(alert.timestamp))
                    .font(.system(size: 16))
                    .foregroundColor(.secondary)
            }
            Text(alert.message)
                .font(.system(size: 17))
                .lineLimit(3)
            if let from = alert.from ?? alert.sender, !from.isEmpty {
                Label(from, systemImage: "person")
                    .font(.system(size: 16))
                    .foregroundColor(.secondary)
            }
            if let subject = alert.subject, !subject.isEmpty {
                Label(subject, systemImage: "envelope")
                    .font(.system(size: 16))
                    .foregroundColor(.secondary)
            }
            if let preview = alert.preview, !preview.isEmpty {
                Text(preview)
                    .font(.system(size: 15))
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
            if let filePath = alert.filePath,
               alert.type != "EMAIL_THREAT_DETECTED" && alert.type != "MESSAGE_THREAT_DETECTED" {
                Label((filePath as NSString).lastPathComponent, systemImage: "doc")
                    .font(.system(size: 16))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 6)
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
        // Use sms: scheme which opens the existing conversation thread
        // (imessage:// opens a new message compose window)
        if !sender.isEmpty, let url = URL(string: "sms:\(sender)") {
            NSWorkspace.shared.open(url)
        } else {
            // Fallback: just open Messages app
            NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Messages.app"))
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
    @State private var refreshID = UUID()

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "doc.text")
                    .font(.title)
                Text("Activity Log")
                    .font(.title.bold())
                Spacer()
                Button("Refresh") {
                    DispatchQueue.main.async { loadLog() }
                }
                .buttonStyle(.bordered)
                .controlSize(.large)
            }
            .padding()
            .background(.bar)

            Divider()

            if logLines.isEmpty {
                Spacer()
                Text("No log entries yet.")
                    .font(.title3)
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(logLines.enumerated()), id: \.offset) { i, line in
                            Text(line)
                                .font(.system(size: 17, design: .monospaced))
                                .textSelection(.enabled)
                                .padding(.horizontal, 12)
                        }
                    }
                    .padding(.vertical, 12)
                    .id(refreshID)
                }
            }
        }
        .frame(minWidth: 1000, minHeight: 600)
        .onAppear { loadLog() }
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
        refreshID = UUID() // force SwiftUI to re-render
    }
}

// MARK: - Severity Badge

struct SeverityBadge: View {
    let severity: SeverityLevel

    var body: some View {
        Text(severity.rawValue)
            .font(.system(size: 15, weight: .bold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.2))
            .foregroundColor(color)
            .clipShape(RoundedRectangle(cornerRadius: 5))
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
