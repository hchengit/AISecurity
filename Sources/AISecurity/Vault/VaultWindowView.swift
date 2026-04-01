import SwiftUI
import AppKit

// MARK: - Vault Window View

struct VaultWindowView: View {
    let securityDir: String
    let passphrase: String
    @State private var entries: [SecurityCoreBridge.VaultEntry] = []
    @State private var selectedPaths: Set<String> = []
    @State private var expandedFolders: Set<String> = [] // tracks which folders are expanded
    @State private var trashAlertShown: Set<String> = [] // prevent repeated trash restore dialogs
    @State private var fileMonitors: [String: Any] = [:] // for temporary unlock tracking

    // MARK: - Grouped entries by protection section

    private var lockedEntries: [SecurityCoreBridge.VaultEntry] {
        entries.filter { $0.protection.isLocked }
    }
    private var readOnlyEntries: [SecurityCoreBridge.VaultEntry] {
        entries.filter { $0.protection.isReadOnly }
    }
    private var localOnlyEntries: [SecurityCoreBridge.VaultEntry] {
        entries.filter { $0.protection == .localOnly }
    }

    /// Group entries by their parent folder, sorted by folder name.
    private func folderGroups(_ sectionEntries: [SecurityCoreBridge.VaultEntry]) -> [(folder: String, entries: [SecurityCoreBridge.VaultEntry])] {
        let grouped = Dictionary(grouping: sectionEntries) { entry in
            (entry.originalPath as NSString).deletingLastPathComponent
        }
        return grouped.sorted { $0.key < $1.key }.map { (folder: $0.key, entries: $0.value) }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "lock.shield")
                    .font(.title2)
                Text("AISecurity Vault")
                    .font(.title2.bold())
                Spacer()
                Text("\(entries.count) protected item\(entries.count == 1 ? "" : "s")")
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(.bar)

            Divider()

            if entries.isEmpty {
                Spacer()
                VStack(spacing: 12) {
                    Image(systemName: "lock.open")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("Your vault is empty")
                        .font(.title3)
                    Text("Use \"Protect Files...\" from the menu bar to add files.")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                List(selection: $selectedPaths) {
                    // Locked (Encrypted) section
                    if !lockedEntries.isEmpty {
                        sectionHeader(icon: "lock.fill", iconColor: .red,
                                      title: "Encrypted", count: lockedEntries.count)
                        sectionFolders(title: "Encrypted", sectionEntries: lockedEntries)
                    }

                    // Read-Only section
                    if !readOnlyEntries.isEmpty {
                        sectionHeader(icon: "book.closed.fill", iconColor: .blue,
                                      title: "Read-Only", count: readOnlyEntries.count)
                        sectionFolders(title: "Read-Only", sectionEntries: readOnlyEntries)
                    }

                    // Local-Only section (pure local-only, no combo)
                    if !localOnlyEntries.isEmpty {
                        sectionHeader(icon: "network.slash", iconColor: .orange,
                                      title: "Local-Only", count: localOnlyEntries.count)
                        sectionFolders(title: "Local-Only", sectionEntries: localOnlyEntries)
                    }
                }
                .listStyle(.plain)

                Divider()

                // Action bar
                HStack(spacing: 12) {
                    let selectedCount = selectedPaths.count
                    let label = selectedCount == 0 ? "All" : "\(selectedCount) selected"

                    Button {
                        temporaryUnlock()
                    } label: {
                        Label("Open Temporarily", systemImage: "lock.open.rotation")
                    }
                    .buttonStyle(.bordered)
                    .help("Decrypt and open. Files re-encrypt when you close them.")
                    .disabled(selectedLockedCount == 0 && !selectedPaths.isEmpty)

                    Button {
                        permanentUnlock()
                    } label: {
                        Label("Release Protection", systemImage: "lock.open")
                    }
                    .buttonStyle(.bordered)
                    .tint(.orange)
                    .help("Permanently decrypt and remove from vault.")

                    Button {
                        toggleLocalOnly()
                    } label: {
                        Label("Toggle Local-Only", systemImage: "network.slash")
                    }
                    .buttonStyle(.bordered)
                    .tint(.purple)
                    .help("Add or remove local-only network monitoring for selected items.")
                    .disabled(onlyPureLocalOnlySelected)

                    Button {
                        changeProtection()
                    } label: {
                        Label("Change Protection", systemImage: "arrow.triangle.2.circlepath")
                    }
                    .buttonStyle(.bordered)
                    .tint(.indigo)
                    .help("Change protection level (e.g. read-only to encrypted).")

                    Spacer()

                    Text(label)
                        .foregroundColor(.secondary)
                        .font(.caption)

                    Button {
                        selectedPaths = Set(entries.map(\.originalPath))
                    } label: {
                        Text("Select All")
                    }
                    .buttonStyle(.bordered)

                    Button {
                        selectedPaths.removeAll()
                    } label: {
                        Text("Clear")
                    }
                    .buttonStyle(.bordered)
                }
                .padding()
            }
        }
        .frame(minWidth: 700, minHeight: 500)
        .onAppear {
            reload()
            checkTrashForVaultFiles()
        }
    }

    // MARK: - Flat Section Header + Folder Groups (avoids Section+DisclosureGroup nesting bug)

    /// Non-selectable header row for a protection category.
    @ViewBuilder
    private func sectionHeader(icon: String, iconColor: Color, title: String, count: Int) -> some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(iconColor)
            Text("\(title) (\(count))")
                .font(.headline)
            Spacer()
        }
        .padding(.top, 8)
        .padding(.bottom, 2)
        .listRowSeparator(.hidden)
    }

    /// Folder disclosure groups for a protection section — placed directly in the List (no Section wrapper).
    @ViewBuilder
    private func sectionFolders(title: String, sectionEntries: [SecurityCoreBridge.VaultEntry]) -> some View {
        let groups = folderGroups(sectionEntries)
        ForEach(groups, id: \.folder) { group in
            DisclosureGroup(
                isExpanded: Binding(
                    get: { expandedFolders.contains("\(title):\(group.folder)") },
                    set: { expanded in
                        let key = "\(title):\(group.folder)"
                        if expanded { expandedFolders.insert(key) }
                        else { expandedFolders.remove(key) }
                    }
                )
            ) {
                ForEach(group.entries, id: \.originalPath) { entry in
                    entryRow(entry)
                        .tag(entry.originalPath)
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "folder.fill")
                        .foregroundColor(.accentColor)
                        .frame(width: 16)
                    Text(shortenedFolder(group.folder))
                        .font(.body)
                    Spacer()
                    Text("\(group.entries.count) file\(group.entries.count == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - Computed helpers

    private var selectedLockedCount: Int {
        if selectedPaths.isEmpty {
            return lockedEntries.count
        }
        return lockedEntries.filter { selectedPaths.contains($0.originalPath) }.count
    }

    /// True if all selected items are pure local-only (no combo), meaning toggle would be meaningless.
    private var onlyPureLocalOnlySelected: Bool {
        let targets = targetPaths()
        if targets.isEmpty { return false }
        return targets.allSatisfy { p in
            entries.first(where: { $0.originalPath == p })?.protection == .localOnly
        }
    }

    // MARK: - Entry Row

    @ViewBuilder
    private func entryRow(_ entry: SecurityCoreBridge.VaultEntry) -> some View {
        HStack(spacing: 10) {
            // File/folder icon
            Image(systemName: entry.isDirectory ? "folder.fill" : fileIcon(for: entry.originalPath))
                .foregroundColor(iconColor(for: entry))
                .frame(width: 20)

            Text((entry.originalPath as NSString).lastPathComponent)
                .font(.body)
                .lineLimit(1)

            Spacer()

            // Status badges
            statusBadges(entry)

            // Size
            Text(formatSize(entry.sizeBytes))
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 65, alignment: .trailing)
        }
        .padding(.vertical, 3)
    }

    @ViewBuilder
    private func statusBadges(_ entry: SecurityCoreBridge.VaultEntry) -> some View {
        HStack(spacing: 4) {
            // Primary status badge
            if entry.protection.isLocked && entry.isUnlocked {
                badge("DECRYPTED", color: .green)
            } else if entry.protection.isLocked {
                badge("ENCRYPTED", color: .red)
            } else if entry.protection.isReadOnly {
                badge("READ-ONLY", color: .blue)
            } else if entry.protection == .localOnly {
                badge("MONITORED", color: .orange)
            }

            // Local-only indicator for combo protections
            if entry.protection.isLocalOnly && entry.protection != .localOnly {
                badge("LOCAL", color: .orange)
            }
        }
    }

    @ViewBuilder
    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.2))
            .foregroundColor(color)
            .clipShape(RoundedRectangle(cornerRadius: 4))
    }

    // MARK: - Actions

    private func targetPaths() -> [String] {
        if selectedPaths.isEmpty {
            return entries.map(\.originalPath)
        }
        return Array(selectedPaths)
    }

    private func temporaryUnlock() {
        let paths = targetPaths()
        let lockedPaths = paths.filter { p in
            entries.first(where: { $0.originalPath == p })?.protection.isLocked == true
        }
        let readOnlyPaths = paths.filter { p in
            entries.first(where: { $0.originalPath == p })?.protection.isReadOnly == true
        }
        let localOnlyPaths = paths.filter { p in
            entries.first(where: { $0.originalPath == p })?.protection == .localOnly
        }

        var messages: [String] = []

        // Unlock encrypted files temporarily
        if !lockedPaths.isEmpty {
            // Split into already-unlocked (just open) vs still-encrypted (decrypt first)
            let alreadyOpen = lockedPaths.filter { p in
                entries.first(where: { $0.originalPath == p })?.isUnlocked == true
            }
            let needsDecrypt = lockedPaths.filter { p in
                entries.first(where: { $0.originalPath == p })?.isUnlocked != true
            }

            // Decrypt any that are still encrypted
            if !needsDecrypt.isEmpty {
                VaultOperationScope.begin()
                // Remove immutable flags so vault can write original + read .vault
                for path in needsDecrypt { FinderTags.unprotectFromDeletion(path) }
                let result = SecurityCoreBridge.vaultUnlock(
                    securityDir: securityDir, paths: needsDecrypt, passphrase: passphrase)
                if result.success && result.entriesAffected > 0 {
                    messages.append("\(result.entriesAffected) file(s) decrypted")
                    // Hide .vault files in Finder while originals are temporarily open
                    for path in needsDecrypt {
                        let vaultFile = path + ".vault"
                        if FileManager.default.fileExists(atPath: vaultFile) {
                            let url = URL(fileURLWithPath: vaultFile)
                            try? (url as NSURL).setResourceValue(true, forKey: .isHiddenKey)
                        }
                    }
                } else if !result.success {
                    messages.append("Decrypt failed: \(result.message)")
                }
                VaultOperationScope.end()
            }

            // Open all files (both newly decrypted and already open)
            var opened = 0
            for path in lockedPaths {
                if FileManager.default.fileExists(atPath: path) {
                    NSWorkspace.shared.open(URL(fileURLWithPath: path))
                    opened += 1
                }
            }
            if opened > 0 {
                messages.append("\(opened) file(s) opened temporarily")
                // Start watching for close — re-encrypt when done
                startReEncryptTimer(paths: lockedPaths)
            }
        }

        // Restore write for read-only (temporary)
        if !readOnlyPaths.isEmpty {
            #if os(macOS)
            for path in readOnlyPaths {
                let url = URL(fileURLWithPath: path)
                if FileManager.default.fileExists(atPath: path) {
                    FinderTags.unlockFile(path) // remove immutable flag first
                    try? FileManager.default.setAttributes(
                        [.posixPermissions: 0o644], ofItemAtPath: path)
                    NSWorkspace.shared.open(url)
                }
            }
            messages.append("\(readOnlyPaths.count) read-only file(s) temporarily writable")
            // Re-lock after delay
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 300) {
                for path in readOnlyPaths {
                    try? FileManager.default.setAttributes(
                        [.posixPermissions: 0o444], ofItemAtPath: path)
                    FinderTags.lockFile(path) // re-apply immutable flag
                }
            }
            #endif
        }

        // Local-only just opens
        if !localOnlyPaths.isEmpty {
            for path in localOnlyPaths {
                if FileManager.default.fileExists(atPath: path) {
                    NSWorkspace.shared.open(URL(fileURLWithPath: path))
                }
            }
            messages.append("\(localOnlyPaths.count) local-only file(s) opened")
        }

        if !messages.isEmpty {
            VaultDialogs.showSuccess(messages.joined(separator: "\n"))
        }
        reload()
    }

    private func permanentUnlock() {
        let paths = targetPaths()
        let count = paths.count

        let alert = NSAlert()
        alert.messageText = "Release Protection for \(count) item(s)?"
        alert.informativeText = "Encrypted files will be permanently decrypted.\nRead-only files will have write access restored.\nLocal-only monitoring will be removed.\n\nThese items will no longer be protected by AISecurity Vault."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Release Protection")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else { return }

        VaultOperationScope.begin()
        // Remove deletion protection before vault operations
        for path in paths { FinderTags.unprotectFromDeletion(path) }
        let result = SecurityCoreBridge.vaultRemove(
            securityDir: securityDir, paths: paths, passphrase: passphrase)
        if result.success {
            for path in paths { FinderTags.removeTag(path) }
            VaultManager.shared.refreshWatchedPaths(passphrase: passphrase)
            VaultDialogs.showSuccess(result.message)
        } else {
            VaultDialogs.showError(result.message)
        }
        VaultOperationScope.end()
        reload()
    }

    private func toggleLocalOnly() {
        let paths = targetPaths()
        // Filter out pure local-only entries (toggle is meaningless for them)
        let toggleable = paths.filter { p in
            guard let entry = entries.first(where: { $0.originalPath == p }) else { return false }
            return entry.protection != .localOnly
        }
        guard !toggleable.isEmpty else { return }

        // Describe what will happen
        let adding = toggleable.filter { p in
            guard let entry = entries.first(where: { $0.originalPath == p }) else { return false }
            return !entry.protection.isLocalOnly
        }
        let removing = toggleable.filter { p in
            guard let entry = entries.first(where: { $0.originalPath == p }) else { return false }
            return entry.protection.isLocalOnly
        }

        var desc: [String] = []
        if !adding.isEmpty { desc.append("\(adding.count) item(s) will gain local-only monitoring") }
        if !removing.isEmpty { desc.append("\(removing.count) item(s) will lose local-only monitoring") }

        let alert = NSAlert()
        alert.messageText = "Toggle Local-Only Monitoring?"
        alert.informativeText = desc.joined(separator: "\n") + "\n\nLocal-only monitoring alerts you when any process tries to send protected files over the network."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Toggle")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else { return }

        VaultOperationScope.begin()
        let result = SecurityCoreBridge.vaultToggleLocalOnly(
            securityDir: securityDir, paths: toggleable, passphrase: passphrase)
        if result.success {
            // Update Finder tags for changed entries
            for path in toggleable {
                if let entry = entries.first(where: { $0.originalPath == path }) {
                    // Re-apply tag based on new protection (toggle flips it)
                    let newProt: SecurityCoreBridge.ProtectionLevel
                    switch entry.protection {
                    case .locked: newProt = .lockedLocal
                    case .lockedLocal: newProt = .locked
                    case .readOnly: newProt = .readOnlyLocal
                    case .readOnlyLocal: newProt = .readOnly
                    default: continue
                    }
                    FinderTags.removeTag(path)
                    FinderTags.addTag(path, protection: newProt)
                }
            }
            VaultManager.shared.refreshWatchedPaths(passphrase: passphrase)
            VaultDialogs.showSuccess(result.message)
        } else {
            VaultDialogs.showError(result.message)
        }
        VaultOperationScope.end()
        reload()
    }

    private func changeProtection() {
        let paths = targetPaths()
        guard !paths.isEmpty else { return }

        // Pick new protection level
        guard let newProtection = VaultDialogs.pickProtectionLevel() else { return }

        let count = paths.count
        let alert = NSAlert()
        alert.messageText = "Change protection for \(count) item(s)?"
        alert.informativeText = "Current protection will be released and files will be re-protected as: \(newProtection.label).\n\nThis requires decrypting and re-encrypting files."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Change")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        VaultOperationScope.begin()
        // Step 1: Remove deletion protection
        for path in paths { FinderTags.unprotectFromDeletion(path) }

        // Step 2: Remove from vault (decrypts if needed)
        let removeResult = SecurityCoreBridge.vaultRemove(
            securityDir: securityDir, paths: paths, passphrase: passphrase)
        guard removeResult.success else {
            VaultDialogs.showError("Failed to release: \(removeResult.message)")
            VaultOperationScope.end()
            reload()
            return
        }

        // Step 3: Re-add with new protection
        let addResult = SecurityCoreBridge.vaultAdd(
            securityDir: securityDir, paths: paths, protection: newProtection, passphrase: passphrase)
        if addResult.success {
            for path in paths {
                FinderTags.removeTag(path)
                FinderTags.addTag(path, protection: newProtection)
                FinderTags.protectFromDeletion(path, protection: newProtection)
            }
            VaultManager.shared.refreshWatchedPaths(passphrase: passphrase)
            VaultDialogs.showSuccess("\(addResult.entriesAffected) file(s) changed to \(newProtection.label)")
        } else {
            VaultDialogs.showError("Re-protection failed: \(addResult.message)")
        }
        VaultOperationScope.end()
        reload()
    }

    /// Start a timer to re-encrypt temporarily unlocked files.
    private func startReEncryptTimer(paths: [String]) {
        // Check every 30 seconds if the files are still open
        // Re-encrypt when no process has them open
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 30) {
            self.checkAndReEncrypt(paths: paths, attempts: 0)
        }
    }

    private func checkAndReEncrypt(paths: [String], attempts: Int) {
        // Give up after 2 hours (240 checks × 30 seconds)
        guard attempts < 240 else { return }

        var stillOpen: [String] = []
        for path in paths {
            if FileManager.default.fileExists(atPath: path) && isFileOpen(path) {
                stillOpen.append(path)
            }
        }

        let toReEncrypt = paths.filter { !stillOpen.contains($0) && FileManager.default.fileExists(atPath: $0) }

        if !toReEncrypt.isEmpty {
            VaultOperationScope.begin()
            let _ = SecurityCoreBridge.vaultLock(
                securityDir: securityDir, paths: toReEncrypt, passphrase: passphrase)
            // Unhide .vault files and re-apply deletion protection
            for path in toReEncrypt {
                let vaultFile = path + ".vault"
                if FileManager.default.fileExists(atPath: vaultFile) {
                    let url = URL(fileURLWithPath: vaultFile)
                    try? (url as NSURL).setResourceValue(false, forKey: .isHiddenKey)
                    FinderTags.lockFile(vaultFile)
                }
            }
            VaultOperationScope.end()
        }

        if !stillOpen.isEmpty {
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 30) {
                self.checkAndReEncrypt(paths: stillOpen, attempts: attempts + 1)
            }
        }
    }

    /// Check if a file is currently open by any process (via lsof).
    private func isFileOpen(_ path: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-t", path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return !data.isEmpty
        } catch {
            return false
        }
    }

    // MARK: - Helpers

    /// One-time check for vault files in Trash (called on window open only).
    private func checkTrashForVaultFiles() {
        let fm = FileManager.default
        let trashDir = (fm.homeDirectoryForCurrentUser.path as NSString).appendingPathComponent(".Trash")
        var trashedFiles: [(expected: String, trashPath: String, fileName: String)] = []

        for entry in entries {
            let expectedPath = entry.protection.isLocked ? entry.vaultPath : entry.originalPath
            guard !expectedPath.isEmpty, !fm.fileExists(atPath: expectedPath) else { continue }

            let fileName = (expectedPath as NSString).lastPathComponent
            let trashPath = (trashDir as NSString).appendingPathComponent(fileName)
            if fm.fileExists(atPath: trashPath) {
                trashedFiles.append((expected: expectedPath, trashPath: trashPath, fileName: fileName))
            }
        }

        guard !trashedFiles.isEmpty else { return }

        let fileList = trashedFiles.map(\.fileName).joined(separator: "\n")
        let alert = NSAlert()
        alert.messageText = "\(trashedFiles.count) vault file(s) found in Trash"
        alert.informativeText = "These files are tracked in your vault but were moved to Trash:\n\n\(fileList)\n\nRestore them to their original locations?"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Restore All")
        alert.addButton(withTitle: "Leave in Trash")

        if alert.runModal() == .alertFirstButtonReturn {
            for file in trashedFiles {
                try? fm.moveItem(atPath: file.trashPath, toPath: file.expected)
                FinderTags.lockFile(file.expected)
            }
            reload()
        }
    }

    private func reload() {
        entries = SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)

        // Always expand all folders after data changes
        expandedFolders.removeAll()
        for entry in entries {
            let folder = (entry.originalPath as NSString).deletingLastPathComponent
            let sectionTitle: String
            if entry.protection.isLocked { sectionTitle = "Encrypted" }
            else if entry.protection.isReadOnly { sectionTitle = "Read-Only" }
            else { sectionTitle = "Local-Only" }
            expandedFolders.insert("\(sectionTitle):\(folder)")
        }
    }

    private func shortenedFolder(_ folder: String) -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if folder.hasPrefix(home) {
            return "~" + folder.dropFirst(home.count)
        }
        return folder
    }

    private func fileIcon(for path: String) -> String {
        let ext = (path as NSString).pathExtension.lowercased()
        switch ext {
        case "pdf": return "doc.richtext"
        case "doc", "docx": return "doc.text"
        case "xls", "xlsx": return "tablecells"
        case "ppt", "pptx": return "rectangle.stack"
        case "txt", "md", "rtf": return "doc.plaintext"
        case "jpg", "jpeg", "png", "gif", "heic": return "photo"
        case "mp4", "mov", "avi": return "film"
        case "mp3", "wav", "m4a": return "music.note"
        case "zip", "rar", "7z", "tar", "gz": return "doc.zipper"
        case "key", "pem", "p12": return "key"
        case "wallet", "vault": return "lock"
        default: return "doc"
        }
    }

    private func iconColor(for entry: SecurityCoreBridge.VaultEntry) -> Color {
        if entry.protection.isLocked {
            return entry.isUnlocked ? .green : .red
        }
        if entry.protection.isReadOnly { return .blue }
        return .orange
    }

    private func parentPath(_ path: String) -> String {
        let parent = (path as NSString).deletingLastPathComponent
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if parent.hasPrefix(home) {
            return "~" + parent.dropFirst(home.count)
        }
        return parent
    }

    private func formatSize(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return "\(bytes / 1024) KB" }
        return String(format: "%.1f MB", Double(bytes) / (1024 * 1024))
    }
}
