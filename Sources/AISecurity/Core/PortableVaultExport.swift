import AppKit
import Foundation

/// "Export Portable Vault" — lets the user ship encrypted files plus the
/// standalone Python decryptor to any destination (USB drive, folder, etc.)
/// so the file can be decrypted on a computer without AISecurity installed.
///
/// Source modes supported:
///   1. "From your Vault"   — pick among files already tracked by the Vault
///                            (already encrypted, just needs copying).
///   2. "From Finder"       — pick any files. Files that already end in
///                            `.vault` are exported as-is. Plaintext files
///                            are encrypted on the fly using the user's
///                            vault passphrase, then the resulting `.vault`
///                            ciphertext is exported.
///
/// Security properties (unchanged from previous iteration):
///   - The export bundle contains ciphertext + the signed Python decryptor
///     + requirements.txt + README.txt. NO passphrase, NO key material.
///   - Decryptor is sealed into AISecurity's code signature; tamper shows
///     up at startup (Fix #6).
///   - README contains instructions only, no hints about the passphrase.
enum PortableVaultExport {

    // MARK: - Entry point

    @MainActor
    static func run() {
        switch pickMode() {
        case .cancel:
            return
        case .fromVault:
            runFromVault()
        case .fromFinder:
            runFromFinder()
        }
    }

    // MARK: - Mode picker

    private enum Mode { case fromVault, fromFinder, cancel }

    @MainActor
    private static func pickMode() -> Mode {
        let alert = NSAlert()
        alert.messageText = "Export Portable Vault"
        alert.informativeText = """
        Choose where to pick files from:

        • "From Vault" — pick among files that are already protected by your Vault.
        • "From Finder" — pick any file. If it's already encrypted (.vault) it will be exported as-is; if it's a plaintext file, AISecurity will encrypt it first and export the encrypted copy.
        """
        alert.alertStyle = .informational
        alert.addButton(withTitle: "From Vault")
        alert.addButton(withTitle: "From Finder")
        alert.addButton(withTitle: "Cancel")
        switch alert.runModal() {
        case .alertFirstButtonReturn:  return .fromVault
        case .alertSecondButtonReturn: return .fromFinder
        default:                       return .cancel
        }
    }

    // MARK: - From Vault

    @MainActor
    private static func runFromVault() {
        let manifest = VaultTrackingStore.shared.load()

        // For export we need the .vault ciphertext. Entries where
        // `originalPath + ".vault"` exists on disk are eligible.
        let eligible: [VaultTrackingManifest.Entry] = manifest.entries.filter { entry in
            FileManager.default.fileExists(atPath: entry.originalPath + ".vault")
                || (entry.watchPath.hasSuffix(".vault") && FileManager.default.fileExists(atPath: entry.watchPath))
        }

        guard !eligible.isEmpty else {
            showError(
                "No vault files found",
                detail: "Your vault is empty, or the on-disk .vault files have been moved. Use 'Protect Files…' first, or choose 'From Finder' instead."
            )
            return
        }

        guard let picked = pickVaultEntries(eligible) else {
            return   // user cancelled
        }

        // Map each chosen entry to its ciphertext path.
        let vaultPaths: [URL] = picked.compactMap { entry in
            let candidate1 = entry.originalPath + ".vault"
            if FileManager.default.fileExists(atPath: candidate1) {
                return URL(fileURLWithPath: candidate1)
            }
            if entry.watchPath.hasSuffix(".vault")
                && FileManager.default.fileExists(atPath: entry.watchPath) {
                return URL(fileURLWithPath: entry.watchPath)
            }
            return nil
        }

        guard !vaultPaths.isEmpty else {
            showError("Selected files not found on disk", detail: "The vault ciphertext files for your selection could not be located.")
            return
        }

        continueToDestination(vaultFiles: vaultPaths)
    }

    /// Show a scrollable table of vault entries and return the selection.
    @MainActor
    private static func pickVaultEntries(_ entries: [VaultTrackingManifest.Entry]) -> [VaultTrackingManifest.Entry]? {
        // Build a simple accessory view: NSTableView inside an NSScrollView.
        let rowHeight: CGFloat = 20
        let visibleRows: Int = min(12, max(4, entries.count))
        let width: CGFloat = 520
        let height: CGFloat = CGFloat(visibleRows) * rowHeight + 24

        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: width, height: height))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder

        let table = NSTableView(frame: scroll.bounds)
        table.allowsMultipleSelection = true
        table.rowHeight = rowHeight
        table.usesAlternatingRowBackgroundColors = true

        let pathCol = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("path"))
        pathCol.title = "File"
        pathCol.width = 380
        table.addTableColumn(pathCol)

        let protCol = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("protection"))
        protCol.title = "Protection"
        protCol.width = 120
        table.addTableColumn(protCol)

        let ds = VaultEntryTableDS(entries: entries)
        table.dataSource = ds
        table.delegate = ds
        scroll.documentView = table

        let alert = NSAlert()
        alert.messageText = "Select files to export"
        alert.informativeText = "Hold ⌘ or ⇧ to multi-select."
        alert.accessoryView = scroll
        alert.addButton(withTitle: "Export Selected")
        alert.addButton(withTitle: "Cancel")

        let resp = alert.runModal()
        guard resp == .alertFirstButtonReturn else { return nil }

        let selected = table.selectedRowIndexes
        if selected.isEmpty {
            showError("Nothing selected", detail: "Select at least one file, or cancel.")
            return nil
        }
        return selected.compactMap { idx in entries.indices.contains(idx) ? entries[idx] : nil }
    }

    // MARK: - From Finder

    @MainActor
    private static func runFromFinder() {
        let panel = NSOpenPanel()
        panel.title = "Choose files to export"
        panel.message = "Pick any file. .vault files are exported as-is; other files will be encrypted first using your vault passphrase."
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowedContentTypes = []   // any type
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }

        // Classify each URL into (already-encrypted, needs-encryption).
        var alreadyEncrypted: [URL] = []
        var plaintext: [URL] = []
        for url in panel.urls {
            if url.pathExtension.lowercased() == "vault" {
                alreadyEncrypted.append(url)
            } else {
                plaintext.append(url)
            }
        }

        if plaintext.isEmpty {
            // Nothing to encrypt — proceed straight to destination.
            continueToDestination(vaultFiles: alreadyEncrypted)
            return
        }

        // Need to encrypt some files. Walk through vault setup, protection
        // level, confirmation, passphrase, and addFiles.
        guard ensureVaultReady() else { return }

        guard let protection = VaultDialogs.pickProtectionLevel() else { return }

        let plaintextPaths = plaintext.map { $0.path }
        guard VaultDialogs.confirmEncrypt(paths: plaintextPaths, protection: protection) else { return }

        // Auth → passphrase → addFiles. `withAuth` is callback-based; we
        // complete the rest of the flow inside the passphrase callback.
        VaultManager.shared.withAuth(
            reason: "Authenticate to encrypt files for portable export",
            passphrasePrompt: "Enter Vault Passphrase",
            onPassphrase: { passphrase in
                DispatchQueue.main.async {
                    encryptThenExport(
                        alreadyEncrypted: alreadyEncrypted,
                        plaintextPaths: plaintextPaths,
                        protection: protection,
                        passphrase: passphrase
                    )
                }
            },
            onCancel: {},
            onError: { msg in
                DispatchQueue.main.async { showError("Authentication failed", detail: msg) }
            }
        )
    }

    @MainActor
    private static func encryptThenExport(
        alreadyEncrypted: [URL],
        plaintextPaths: [String],
        protection: SecurityCoreBridge.ProtectionLevel,
        passphrase: String
    ) {
        VaultOperationScope.begin()
        let result = VaultManager.shared.addFiles(plaintextPaths, protection: protection, passphrase: passphrase)
        VaultOperationScope.end()

        if !result.success {
            showError("Encryption failed", detail: result.message)
            return
        }

        // Also do the post-encryption housekeeping that protectFilesService
        // performs, so the new vault entries are properly tracked.
        for path in plaintextPaths {
            FinderTags.addTag(path, protection: protection)
        }
        VaultManager.shared.trackFiles(plaintextPaths, protection: protection)
        VaultManager.shared.syncTracker(passphrase: passphrase)
        NotificationCenter.default.post(name: .vaultDidChange, object: nil)

        // Combine newly-created .vault files with the ones the user already
        // picked as ciphertext.
        let newlyEncrypted: [URL] = plaintextPaths.compactMap { path in
            let vp = path + ".vault"
            return FileManager.default.fileExists(atPath: vp) ? URL(fileURLWithPath: vp) : nil
        }

        let combined = alreadyEncrypted + newlyEncrypted
        guard !combined.isEmpty else {
            showError("Nothing to export", detail: "Encryption succeeded but no .vault files could be located. Inspect ~/.mac-security/logs/alerts.log.")
            return
        }
        continueToDestination(vaultFiles: combined)
    }

    @MainActor
    private static func ensureVaultReady() -> Bool {
        let mgr = VaultManager.shared
        if mgr.isSetup { return true }
        // First-time setup wizard — matches protectFilesService flow.
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

    // MARK: - Destination + copy (shared tail)

    @MainActor
    private static func continueToDestination(vaultFiles: [URL]) {
        guard !vaultFiles.isEmpty else { return }

        guard let destRoot = pickDestinationFolder() else { return }

        guard let toolURL = Bundle.main.url(
            forResource: "vault-decrypt",
            withExtension: "py"
        ) else {
            showError(
                "Decryptor script missing from app bundle",
                detail: "Reinstall AISecurity — the Portable Vault decryptor is not where it should be."
            )
            return
        }

        let stamp = timestampString()
        let exportDir = destRoot.appendingPathComponent("AISecurity-Portable-Vault-\(stamp)")
        do {
            try FileManager.default.createDirectory(
                at: exportDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
        } catch {
            showError("Could not create export folder", detail: error.localizedDescription)
            return
        }

        var copied: [String] = []
        var failures: [(String, String)] = []
        for src in vaultFiles {
            let dst = exportDir.appendingPathComponent(src.lastPathComponent)
            do {
                try FileManager.default.copyItem(at: src, to: dst)
                copied.append(src.lastPathComponent)
            } catch {
                failures.append((src.lastPathComponent, error.localizedDescription))
            }
        }

        do {
            let dst = exportDir.appendingPathComponent("vault-decrypt.py")
            try FileManager.default.copyItem(at: toolURL, to: dst)
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dst.path)
        } catch {
            showError("Could not copy decryptor script", detail: error.localizedDescription)
            return
        }

        let requirementsPath = exportDir.appendingPathComponent("requirements.txt")
        try? "cryptography>=42\n".write(to: requirementsPath, atomically: true, encoding: .utf8)

        let readmeText = buildReadme(copiedVaultFiles: copied)
        let readmePath = exportDir.appendingPathComponent("README.txt")
        try? readmeText.write(to: readmePath, atomically: true, encoding: .utf8)

        showResult(exportDir: exportDir, copied: copied, failures: failures)
    }

    @MainActor
    private static func pickDestinationFolder() -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Choose destination folder (e.g. USB drive)"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Choose"
        panel.message = "Pick the folder or USB drive where the portable vault bundle should be written."
        guard panel.runModal() == .OK, let chosen = panel.url else { return nil }

        // Warn if the destination lives inside iCloud Drive (or any other
        // cloud-synced location we can detect). Two classes of problem:
        //   1. "Open Temporarily" on the exported .vault can race with iCloud
        //      sync — plaintext may briefly reach Apple's servers before
        //      the local re-encrypt completes.
        //   2. iCloud's "Optimize Mac Storage" can evict files and leave
        //      .icloud placeholders. The decryptor will fail on placeholders.
        // The user gets a clear choice: continue anyway, or pick a different
        // folder. Not a hard block — they may intentionally want iCloud
        // backup of the ciphertext, which is fine as long as they don't
        // "Open Temporarily" from the iCloud copy.
        if let reason = cloudSyncedReason(for: chosen) {
            let warn = NSAlert()
            warn.messageText = "This folder is synced by \(reason)"
            warn.informativeText = """
            AISecurity recommends exporting portable vault bundles to a local drive or a USB drive — not to a cloud-synced location.

            Why: "Open Temporarily" on the exported .vault can race with cloud sync, and cloud storage may evict files and leave placeholders the decryptor can't read.

            Storing only the encrypted ciphertext in iCloud is fine if you only ever decrypt on a local copy. If you'd like to change your selection, click "Choose Different Folder".
            """
            warn.alertStyle = .warning
            warn.addButton(withTitle: "Choose Different Folder")
            warn.addButton(withTitle: "Continue Anyway")
            if warn.runModal() == .alertFirstButtonReturn {
                return pickDestinationFolder()   // re-pick
            }
        }

        return chosen
    }

    /// Returns a human-readable reason string if the URL is inside a known
    /// cloud-synced location, or nil if it's local-only (to the best of our
    /// ability to detect).
    private static func cloudSyncedReason(for url: URL) -> String? {
        let path = url.path
        let home = NSHomeDirectory()

        // iCloud Drive root (Desktop & Documents sync + standard iCloud Drive)
        let iCloudRoots = [
            "\(home)/Library/Mobile Documents/",
            "\(home)/iCloud Drive/",
        ]
        for root in iCloudRoots {
            if path.hasPrefix(root) { return "iCloud Drive" }
        }

        // When "Desktop & Documents" sync is ON, ~/Documents and ~/Desktop
        // are symlinks/bind-mounts into Mobile Documents. Detect by checking
        // if either dir's realpath lands under Mobile Documents.
        let syncCandidates = ["\(home)/Documents", "\(home)/Desktop"]
        for candidate in syncCandidates {
            if path == candidate || path.hasPrefix(candidate + "/") {
                let resolved = URL(fileURLWithPath: candidate).resolvingSymlinksInPath().path
                if resolved.contains("Mobile Documents") {
                    return "iCloud Drive (Desktop & Documents sync)"
                }
            }
        }

        // Common third-party cloud folders
        let thirdParty: [(prefix: String, name: String)] = [
            ("\(home)/Dropbox",                            "Dropbox"),
            ("\(home)/Google Drive",                       "Google Drive"),
            ("\(home)/CloudStorage/GoogleDrive",           "Google Drive"),
            ("\(home)/Library/CloudStorage/GoogleDrive",   "Google Drive"),
            ("\(home)/Library/CloudStorage/OneDrive",      "OneDrive"),
            ("\(home)/OneDrive",                           "OneDrive"),
            ("\(home)/Box",                                "Box"),
            ("\(home)/Library/CloudStorage/Box",           "Box"),
        ]
        for (prefix, name) in thirdParty {
            if path == prefix || path.hasPrefix(prefix + "/") { return name }
        }

        return nil
    }

    @MainActor
    private static func showResult(exportDir: URL, copied: [String], failures: [(String, String)]) {
        let alert = NSAlert()
        if failures.isEmpty {
            alert.messageText = "Portable vault exported"
            alert.informativeText = """
            \(copied.count) file(s) copied with the decryptor and instructions to:

            \(exportDir.path)

            On any computer, open README.txt inside that folder and follow the 3-step decryption instructions.
            """
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Reveal in Finder")
            alert.addButton(withTitle: "Done")
            if alert.runModal() == .alertFirstButtonReturn {
                NSWorkspace.shared.activateFileViewerSelecting([exportDir])
            }
        } else {
            let list = failures.map { "• \($0.0): \($0.1)" }.joined(separator: "\n")
            alert.messageText = "Export completed with \(failures.count) error(s)"
            alert.informativeText = """
            Succeeded: \(copied.count) file(s). Failed:

            \(list)

            Folder: \(exportDir.path)
            """
            alert.alertStyle = .warning
            alert.runModal()
        }
    }

    @MainActor
    private static func showError(_ title: String, detail: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = detail
        alert.alertStyle = .warning
        alert.runModal()
    }

    // MARK: - Content builders

    private static func buildReadme(copiedVaultFiles: [String]) -> String {
        let fileList = copiedVaultFiles.map { "    \($0)" }.joined(separator: "\n")
        return """
        AISecurity Portable Vault Bundle
        ================================

        This folder contains one or more encrypted files and a standalone
        tool that can decrypt them on any computer with Python 3.

        Files in this bundle:
        \(fileList)
            vault-decrypt.py     — the decryption tool
            requirements.txt     — Python dependency
            README.txt           — this file

        To decrypt a file
        -----------------

        1. Install Python 3 if you don't have it:
             macOS:   already installed
             Linux:   usually already installed; otherwise `sudo apt install python3 python3-pip`
             Windows: download from https://www.python.org/downloads/

        2. Install the one dependency (in a terminal, inside this folder):
             pip install -r requirements.txt
           or directly:
             pip install cryptography

        3. Decrypt a file:
             python3 vault-decrypt.py <file.vault>

           Example:
             python3 vault-decrypt.py secret.pdf.vault

           You'll be prompted for the passphrase you set when the file was
           encrypted in AISecurity. The decrypted file is written next to
           the .vault file with the .vault extension removed.

        Security notes
        --------------

        • The encrypted files cannot be decrypted without the passphrase.
          Losing this folder is not a security incident — losing the
          passphrase is.

        • Do NOT write your passphrase in this README or anywhere on the
          drive. Keep it in your head or in a separate secure location.

        • The decryption tool (vault-decrypt.py) is a plain Python script.
          You can read it yourself before running it.

        • This tool does not phone home, log anything, or make network
          connections. Everything happens locally on your machine.

        For questions or to verify the tool, see the AISecurity project.
        """
    }

    private static func timestampString() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f.string(from: Date())
    }
}

/// Data source / delegate for the vault-entries picker table.
/// Kept as a separate class (not a private struct) so NSTableView can hold a
/// weak reference to it — nested private types inside an enum don't get
/// @MainActor isolation the same way and the table expects NSObject-backed
/// delegates.
final class VaultEntryTableDS: NSObject, NSTableViewDataSource, NSTableViewDelegate {

    private let entries: [VaultTrackingManifest.Entry]

    init(entries: [VaultTrackingManifest.Entry]) {
        self.entries = entries
        super.init()
    }

    func numberOfRows(in tableView: NSTableView) -> Int { entries.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard entries.indices.contains(row), let col = tableColumn else { return nil }
        let identifier = NSUserInterfaceItemIdentifier("cell-" + col.identifier.rawValue)
        let cell: NSTableCellView
        if let reused = tableView.makeView(withIdentifier: identifier, owner: nil) as? NSTableCellView {
            cell = reused
        } else {
            cell = NSTableCellView()
            cell.identifier = identifier
            let field = NSTextField(labelWithString: "")
            field.lineBreakMode = .byTruncatingMiddle
            field.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
            field.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(field)
            cell.textField = field
            NSLayoutConstraint.activate([
                field.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
                field.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
                field.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
        }

        let entry = entries[row]
        switch col.identifier.rawValue {
        case "path":
            cell.textField?.stringValue = entry.originalPath
        case "protection":
            cell.textField?.stringValue = entry.protection
        default:
            cell.textField?.stringValue = ""
        }
        return cell
    }
}
