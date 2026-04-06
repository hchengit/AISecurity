import SwiftUI
import AppKit

// MARK: - Vault Window View

struct VaultWindowView: View {
    let securityDir: String
    let passphrase: String
    @State private var entries: [SecurityCoreBridge.VaultEntry] = []
    @State private var selectedPaths: Set<String> = []
    @State private var showAuditLog = false

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

    private var allSelected: Bool {
        !entries.isEmpty && selectedPaths.count == entries.count
    }

    /// Whether any selected files are temporarily decrypted (is_unlocked = true)
    private var hasUnlockedSelected: Bool {
        entries.contains { selectedPaths.contains($0.originalPath) && $0.isUnlocked }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "lock.shield")
                    .font(.title)
                Text("AISecurity Vault")
                    .font(.title.bold())
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
                        .font(.system(size: 64))
                        .foregroundColor(.secondary)
                    Text("Your vault is empty")
                        .font(.title2)
                    Text("Use \"Protect Files...\" from the menu bar to add files.")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                // Select All row
                HStack {
                    Button {
                        if allSelected {
                            selectedPaths.removeAll()
                        } else {
                            selectedPaths = Set(entries.map(\.originalPath))
                        }
                    } label: {
                        Image(systemName: allSelected ? "checkmark.square.fill" : "square")
                            .foregroundColor(allSelected ? .accentColor : .secondary)
                    }
                    .buttonStyle(.plain)

                    Text("Select All")
                        .font(.body)
                        .foregroundColor(.secondary)

                    Spacer()

                    if !selectedPaths.isEmpty {
                        Text("\(selectedPaths.count) selected")
                            .font(.body)
                            .foregroundColor(.accentColor)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 6)
                .background(.bar)

                Divider()

                // File list with checkboxes
                List {
                    if !lockedEntries.isEmpty {
                        sectionHeader(icon: "lock.fill", iconColor: .red,
                                      title: "Encrypted", count: lockedEntries.count)
                        ForEach(lockedEntries, id: \.originalPath) { entry in
                            entryRow(entry)
                        }
                    }

                    if !readOnlyEntries.isEmpty {
                        sectionHeader(icon: "book.closed.fill", iconColor: .blue,
                                      title: "Read-Only", count: readOnlyEntries.count)
                        ForEach(readOnlyEntries, id: \.originalPath) { entry in
                            entryRow(entry)
                        }
                    }

                    if !localOnlyEntries.isEmpty {
                        sectionHeader(icon: "network.slash", iconColor: .orange,
                                      title: "Local-Only", count: localOnlyEntries.count)
                        ForEach(localOnlyEntries, id: \.originalPath) { entry in
                            entryRow(entry)
                        }
                    }
                }
                .listStyle(.plain)

                Divider()

                // Action bar: Action dropdown + Audit + Clear
                HStack(spacing: 10) {
                    // Action dropdown menu
                    Menu {
                        Button("Decrypt Once (auto re-encrypts)") {
                            temporaryUnlock()
                        }

                        Button("Decrypt Permanently") {
                            decryptPermanently()
                        }

                        if hasUnlockedSelected {
                            Button("Re-encrypt Now") {
                                reencryptUnlocked()
                            }
                        }

                        Divider()

                        Button("Change to Encrypted") {
                            applyProtection(.locked)
                        }

                        Button("Change to Encrypted + Local") {
                            applyProtection(.lockedLocal)
                        }

                        Divider()

                        Button("Change to Read-Only") {
                            applyProtection(.readOnly)
                        }

                        Button("Change to Read-Only + Local") {
                            applyProtection(.readOnlyLocal)
                        }

                        Divider()

                        Button("Change to Local-Only") {
                            applyProtection(.localOnly)
                        }

                        Divider()

                        Button("Release Protection", role: .destructive) {
                            releaseProtection()
                        }
                    } label: {
                        Label("Action", systemImage: "ellipsis.circle")
                    }
                    .menuStyle(.borderedButton)
                    .fixedSize()
                    .disabled(selectedPaths.isEmpty)

                    Button {
                        showAuditLog = true
                    } label: {
                        Label("Audit Log", systemImage: "doc.text.magnifyingglass")
                    }
                    .buttonStyle(.bordered)

                    Spacer()

                    Button("Clear Selection") {
                        selectedPaths.removeAll()
                    }
                    .buttonStyle(.bordered)
                    .disabled(selectedPaths.isEmpty)
                }
                .padding()
            }
        }
        .frame(minWidth: 900, minHeight: 650)
        .sheet(isPresented: $showAuditLog) {
            VaultAuditLogView()
        }
        .onAppear {
            let currentEntries = SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
            entries = currentEntries
            VaultManager.shared.syncTracker(passphrase: passphrase)
            cleanupDeletedEntries(currentEntries)

            // Re-register any temporarily unlocked files with the auto-re-encrypt monitor
            // (in case the app was restarted while files were temporarily decrypted)
            let unlockedPaths = currentEntries
                .filter { $0.isUnlocked && $0.protection.isLocked }
                .map(\.originalPath)
                .filter { FileManager.default.fileExists(atPath: $0) }
            if !unlockedPaths.isEmpty {
                TemporaryDecryptMonitor.shared.watch(
                    paths: unlockedPaths, passphrase: passphrase, securityDir: securityDir)
            }
        }
        .onDisappear {
            VaultManager.shared.clearPassphrase()
        }
        .onReceive(NotificationCenter.default.publisher(for: .vaultDidChange)) { _ in
            reload()
        }
    }

    // MARK: - Section Header

    @ViewBuilder
    private func sectionHeader(icon: String, iconColor: Color, title: String, count: Int) -> some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(iconColor)
            Text("\(title) (\(count))")
                .font(.title3.bold())
            Spacer()
        }
        .padding(.top, 8)
        .padding(.bottom, 2)
        .listRowSeparator(.hidden)
    }

    // MARK: - Entry Row (with checkbox)

    @ViewBuilder
    private func entryRow(_ entry: SecurityCoreBridge.VaultEntry) -> some View {
        let isSelected = selectedPaths.contains(entry.originalPath)

        HStack(spacing: 10) {
            // Checkbox
            Button {
                if isSelected {
                    selectedPaths.remove(entry.originalPath)
                } else {
                    selectedPaths.insert(entry.originalPath)
                }
            } label: {
                Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                    .foregroundColor(isSelected ? .accentColor : .secondary)
            }
            .buttonStyle(.plain)

            // File icon
            Image(systemName: entry.isDirectory ? "folder.fill" : fileIcon(for: entry.originalPath))
                .foregroundColor(iconColor(for: entry))
                .frame(width: 24)

            // File name + path
            VStack(alignment: .leading, spacing: 2) {
                Text((entry.originalPath as NSString).lastPathComponent)
                    .font(.title3)
                    .lineLimit(1)
                Text(shortenedFolder((entry.originalPath as NSString).deletingLastPathComponent))
                    .font(.body)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            // Status badges
            statusBadges(entry)

            // Size
            Text(formatSize(entry.sizeBytes))
                .font(.body)
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .trailing)
        }
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .onTapGesture {
            if isSelected {
                selectedPaths.remove(entry.originalPath)
            } else {
                selectedPaths.insert(entry.originalPath)
            }
        }
    }

    @ViewBuilder
    private func statusBadges(_ entry: SecurityCoreBridge.VaultEntry) -> some View {
        HStack(spacing: 4) {
            if entry.protection.isLocked && entry.isUnlocked {
                badge("DECRYPTED", color: .green)
            } else if entry.protection.isLocked {
                badge("ENCRYPTED", color: .red)
            } else if entry.protection.isReadOnly {
                badge("READ-ONLY", color: .blue)
            } else if entry.protection == .localOnly {
                badge("MONITORED", color: .orange)
            }

            if entry.protection.isLocalOnly && entry.protection != .localOnly {
                badge("LOCAL", color: .orange)
            }
        }
    }

    @ViewBuilder
    private func badge(_ text: String, color: Color) -> some View {
        Text(text)
            .font(.callout.bold())
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(color.opacity(0.2))
            .foregroundColor(color)
            .clipShape(RoundedRectangle(cornerRadius: 4))
    }

    // MARK: - Actions

    private func selectedEntries() -> [SecurityCoreBridge.VaultEntry] {
        entries.filter { selectedPaths.contains($0.originalPath) }
    }

    /// Decrypt once — opens files, auto re-encrypts when closed
    private func temporaryUnlock() {
        let selected = selectedEntries()
        let lockedPaths = selected.filter { $0.protection.isLocked }.map(\.originalPath)
        let readOnlyPaths = selected.filter { $0.protection.isReadOnly }.map(\.originalPath)
        let localOnlyPaths = selected.filter { $0.protection == .localOnly }.map(\.originalPath)

        var messages: [String] = []

        if !lockedPaths.isEmpty {
            let needsDecrypt = lockedPaths.filter { p in
                entries.first(where: { $0.originalPath == p })?.isUnlocked != true
            }

            if !needsDecrypt.isEmpty {
                VaultOperationScope.begin()
                for path in needsDecrypt { FinderTags.unlockFile(path); FinderTags.unlockFile(path + ".vault") }
                let result = SecurityCoreBridge.vaultUnlock(
                    securityDir: securityDir, paths: needsDecrypt, passphrase: passphrase)
                if result.success && result.entriesAffected > 0 {
                    messages.append("\(result.entriesAffected) file(s) decrypted")
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

            var openedPaths: [String] = []
            for path in lockedPaths {
                if FileManager.default.fileExists(atPath: path) {
                    NSWorkspace.shared.open(URL(fileURLWithPath: path))
                    openedPaths.append(path)
                }
            }
            if !openedPaths.isEmpty {
                TemporaryDecryptMonitor.shared.watch(
                    paths: openedPaths, passphrase: passphrase, securityDir: securityDir)
                messages.append("\(openedPaths.count) file(s) opened — will auto-re-encrypt when closed")
            }
        }

        if !readOnlyPaths.isEmpty {
            for path in readOnlyPaths {
                if FileManager.default.fileExists(atPath: path) {
                    FinderTags.unlockFile(path)
                    try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
                    NSWorkspace.shared.open(URL(fileURLWithPath: path))
                }
            }
            messages.append("\(readOnlyPaths.count) read-only file(s) temporarily writable (5 min)")
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 300) {
                for path in readOnlyPaths {
                    try? FileManager.default.setAttributes([.posixPermissions: 0o444], ofItemAtPath: path)
                    FinderTags.lockFile(path)
                }
            }
        }

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

    /// Re-encrypt files that were temporarily decrypted
    private func reencryptUnlocked() {
        let selected = selectedEntries()
        let unlockedPaths = selected.filter { $0.isUnlocked && $0.protection.isLocked }.map(\.originalPath)
        guard !unlockedPaths.isEmpty else {
            VaultDialogs.showError("No temporarily decrypted files selected.")
            return
        }

        VaultOperationScope.begin()
        TemporaryDecryptMonitor.shared.unwatch(paths: unlockedPaths)
        for path in unlockedPaths { FinderTags.unlockFile(path); FinderTags.unlockFile(path + ".vault") }

        let result = SecurityCoreBridge.vaultLock(
            securityDir: securityDir, paths: unlockedPaths, passphrase: passphrase)
        if result.success {
            for path in unlockedPaths {
                // Unhide .vault file
                let vaultFile = path + ".vault"
                if FileManager.default.fileExists(atPath: vaultFile) {
                    let url = URL(fileURLWithPath: vaultFile)
                    try? (url as NSURL).setResourceValue(false, forKey: .isHiddenKey)
                }
                FinderTags.lockFile(vaultFile)
                VaultAuditLog.shared.log(.fileLocked, path: path, detail: "manually re-encrypted")
            }
            VaultManager.shared.syncTracker(passphrase: passphrase)
            VaultDialogs.showSuccess("\(result.entriesAffected) file(s) re-encrypted")
        } else {
            VaultDialogs.showError(result.message)
        }
        VaultOperationScope.end()
        reload()
    }

    /// Decrypt permanently — removes encryption but keeps in vault as decrypted
    private func decryptPermanently() {
        let selected = selectedEntries()
        let lockedPaths = selected.filter { $0.protection.isLocked }.map(\.originalPath)
        guard !lockedPaths.isEmpty else {
            VaultDialogs.showError("No encrypted files selected.")
            return
        }

        let alert = NSAlert()
        alert.messageText = "Permanently decrypt \(lockedPaths.count) file(s)?"
        alert.informativeText = "Files will be decrypted and removed from the vault. This cannot be undone."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Decrypt")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        VaultOperationScope.begin()
        TemporaryDecryptMonitor.shared.unwatch(paths: lockedPaths)
        for path in lockedPaths { FinderTags.unlockFile(path); FinderTags.unlockFile(path + ".vault") }
        let result = SecurityCoreBridge.vaultRemove(
            securityDir: securityDir, paths: lockedPaths, passphrase: passphrase)
        if result.success {
            for path in lockedPaths { FinderTags.removeTag(path); FinderTags.removeTag(path + ".vault") }
            VaultManager.shared.syncTracker(passphrase: passphrase)
            VaultDialogs.showSuccess(result.message)
        } else {
            VaultDialogs.showError(result.message)
        }
        VaultOperationScope.end()
        reload()
    }

    /// Apply a new protection level to selected files
    private func applyProtection(_ newProtection: SecurityCoreBridge.ProtectionLevel) {
        let selected = selectedEntries()
        let paths = selected.map(\.originalPath)
        guard !paths.isEmpty else { return }

        // If files are temporarily unlocked and target is the same locked level, just re-lock
        let unlockedSameLevel = selected.filter { $0.isUnlocked && $0.protection == newProtection }
        if !unlockedSameLevel.isEmpty && unlockedSameLevel.count == selected.count {
            reencryptUnlocked()
            return
        }

        // For unlocked files changing to a locked protection, re-lock them first
        let needsRelock = selected.filter { $0.isUnlocked && $0.protection.isLocked }
        if !needsRelock.isEmpty {
            VaultOperationScope.begin()
            let relockPaths = needsRelock.map(\.originalPath)
            for path in relockPaths { FinderTags.unlockFile(path); FinderTags.unlockFile(path + ".vault") }
            _ = SecurityCoreBridge.vaultLock(securityDir: securityDir, paths: relockPaths, passphrase: passphrase)
            VaultOperationScope.end()
        }

        // Confirm
        let count = paths.count
        let alert = NSAlert()
        alert.messageText = "Change \(count) file(s) to \(newProtection.label)?"
        alert.informativeText = protectionDescription(newProtection)
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Change")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        VaultOperationScope.begin()
        TemporaryDecryptMonitor.shared.unwatch(paths: paths)
        for path in paths { FinderTags.unlockFile(path); FinderTags.unlockFile(path + ".vault") }

        let result = SecurityCoreBridge.vaultChangeProtection(
            securityDir: securityDir, paths: paths,
            newProtection: newProtection, passphrase: passphrase)

        if result.success {
            for path in paths {
                FinderTags.removeTag(path)
                FinderTags.removeTag(path + ".vault")
                let tagPath = newProtection.isLocked ? (path + ".vault") : path
                FinderTags.addTag(tagPath, protection: newProtection)
            }
            VaultManager.shared.syncTracker(passphrase: passphrase)
            VaultDialogs.showSuccess(result.message)
        } else {
            VaultDialogs.showError(result.message)
        }
        VaultOperationScope.end()
        reload()
    }

    /// Release all protection — remove from vault entirely
    private func releaseProtection() {
        let paths = Array(selectedPaths)
        guard !paths.isEmpty else { return }

        let alert = NSAlert()
        alert.messageText = "Release protection for \(paths.count) file(s)?"
        alert.informativeText = "All protections will be removed. Encrypted files will be decrypted. Read-only permissions restored. This cannot be undone."
        alert.alertStyle = .critical
        alert.addButton(withTitle: "Release")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        VaultOperationScope.begin()
        TemporaryDecryptMonitor.shared.unwatch(paths: paths)
        for path in paths { FinderTags.unlockFile(path); FinderTags.unlockFile(path + ".vault") }
        let result = SecurityCoreBridge.vaultRemove(
            securityDir: securityDir, paths: paths, passphrase: passphrase)
        if result.success {
            for path in paths { FinderTags.removeTag(path); FinderTags.removeTag(path + ".vault") }
            VaultManager.shared.syncTracker(passphrase: passphrase)
            VaultDialogs.showSuccess(result.message)
        } else {
            VaultDialogs.showError(result.message)
        }
        VaultOperationScope.end()
        reload()
    }

    private func protectionDescription(_ prot: SecurityCoreBridge.ProtectionLevel) -> String {
        switch prot {
        case .locked:
            return "Files will be encrypted with AES-256-GCM. Originals securely deleted."
        case .readOnly:
            return "Files will be set to read-only (chmod 444). Encrypted files will be decrypted first."
        case .localOnly:
            return "Files monitored for network exfiltration. Encrypted files will be decrypted first."
        case .readOnlyLocal:
            return "Read-only + network monitoring. Encrypted files will be decrypted first."
        case .lockedLocal:
            return "Encrypted + network monitoring."
        }
    }

    // MARK: - Cleanup

    private func cleanupDeletedEntries(_ checkEntries: [SecurityCoreBridge.VaultEntry]) {
        let fm = FileManager.default
        var missing: [SecurityCoreBridge.VaultEntry] = []

        for entry in checkEntries {
            let originalExists = !entry.originalPath.isEmpty && fm.fileExists(atPath: entry.originalPath)
            let vaultExists = !entry.vaultPath.isEmpty && fm.fileExists(atPath: entry.vaultPath)
            let computedVault = entry.originalPath + ".vault"
            let computedVaultExists = fm.fileExists(atPath: computedVault)

            if !originalExists && !vaultExists && !computedVaultExists {
                missing.append(entry)
            }
        }

        guard !missing.isEmpty else { return }

        let names = missing.map { ($0.originalPath as NSString).lastPathComponent }.joined(separator: "\n")
        let alert = NSAlert()
        alert.messageText = "\(missing.count) Vault Entry(s) — Files Missing"
        alert.informativeText = "These protected files no longer exist on disk:\n\n\(names)\n\nRemove them from the vault?"
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Remove from Vault")
        alert.addButton(withTitle: "Keep Entries")

        if alert.runModal() == .alertFirstButtonReturn {
            VaultOperationScope.begin()
            let paths = missing.map(\.originalPath)
            let result = SecurityCoreBridge.vaultRemove(
                securityDir: securityDir, paths: paths, passphrase: passphrase)
            if result.success {
                VaultManager.shared.untrackFiles(paths)
                VaultManager.shared.syncTracker(passphrase: passphrase)
            }
            VaultOperationScope.end()
            reload()
        }
    }

    // MARK: - Helpers

    private func reload() {
        entries = SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
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

    private func formatSize(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return "\(bytes / 1024) KB" }
        return String(format: "%.1f MB", Double(bytes) / (1024 * 1024))
    }
}

// MARK: - Audit Log Viewer

struct VaultAuditLogView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var entries: [VaultAuditLog.AuditEntry] = []
    @State private var filterEvent: String = "All"

    private let eventTypes = ["All", "FILE_ADDED", "FILE_REMOVED", "FILE_MOVED", "FILE_DELETED",
                              "PROTECTION_CHANGED", "FILE_UNLOCKED", "FILE_LOCKED",
                              "FILE_MODIFIED", "UNAUTHORIZED_ACCESS", "THREAT_DETECTED",
                              "PASSPHRASE_CHANGED"]

    var filteredEntries: [VaultAuditLog.AuditEntry] {
        if filterEvent == "All" { return entries }
        return entries.filter { $0.event == filterEvent }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "doc.text.magnifyingglass")
                    .font(.title)
                Text("Vault Audit Log")
                    .font(.title.bold())
                Spacer()

                Picker("Filter:", selection: $filterEvent) {
                    ForEach(eventTypes, id: \.self) { Text($0) }
                }
                .frame(width: 220)

                Button("Close") { dismiss() }
                    .buttonStyle(.bordered)
            }
            .padding()

            Divider()

            if filteredEntries.isEmpty {
                Spacer()
                Text("No audit log entries found.")
                    .foregroundColor(.secondary)
                Spacer()
            } else {
                List(filteredEntries.reversed(), id: \.timestamp) { entry in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(entry.event)
                                .font(.caption.bold())
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(colorForEvent(entry.event).opacity(0.2))
                                .cornerRadius(4)
                            Text(formatTimestamp(entry.timestamp))
                                .font(.body)
                                .foregroundColor(.secondary)
                        }
                        if !entry.path.isEmpty {
                            Text(entry.path)
                                .font(.body)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                        if !entry.detail.isEmpty {
                            Text(entry.detail)
                                .font(.body)
                                .foregroundColor(.secondary)
                                .lineLimit(2)
                        }
                    }
                    .padding(.vertical, 2)
                }
                .listStyle(.plain)
            }
        }
        .frame(minWidth: 800, minHeight: 550)
        .onAppear {
            entries = VaultAuditLog.shared.getEntries(limit: 500)
        }
    }

    private func colorForEvent(_ event: String) -> Color {
        switch event {
        case "FILE_ADDED": return .green
        case "FILE_REMOVED": return .orange
        case "FILE_MOVED": return .blue
        case "FILE_DELETED": return .red
        case "FILE_MODIFIED", "UNAUTHORIZED_ACCESS": return .red
        case "THREAT_DETECTED": return .red
        case "FILE_UNLOCKED": return .yellow
        case "FILE_LOCKED": return .green
        case "PROTECTION_CHANGED": return .purple
        case "PASSPHRASE_CHANGED": return .indigo
        default: return .gray
        }
    }

    private func formatTimestamp(_ ts: String) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = formatter.date(from: ts) else { return ts }
        let display = DateFormatter()
        display.dateStyle = .short
        display.timeStyle = .medium
        return display.string(from: date)
    }
}
