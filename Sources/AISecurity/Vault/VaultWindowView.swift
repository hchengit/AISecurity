import SwiftUI
import AppKit

// MARK: - Vault Window View

struct VaultWindowView: View {
    let securityDir: String
    let passphrase: String
    @State private var entries: [SecurityCoreBridge.VaultEntry] = []
    @State private var selectedPaths: Set<String> = []
    @State private var fileMonitors: [String: Any] = [:] // for temporary unlock tracking

    private var lockedEntries: [SecurityCoreBridge.VaultEntry] {
        entries.filter { $0.protection == .locked }
    }
    private var readOnlyEntries: [SecurityCoreBridge.VaultEntry] {
        entries.filter { $0.protection == .readOnly }
    }
    private var localOnlyEntries: [SecurityCoreBridge.VaultEntry] {
        entries.filter { $0.protection == .localOnly }
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
                        Section {
                            ForEach(lockedEntries, id: \.originalPath) { entry in
                                entryRow(entry)
                                    .tag(entry.originalPath)
                            }
                        } header: {
                            HStack {
                                Image(systemName: "lock.fill")
                                    .foregroundColor(.red)
                                Text("Encrypted (\(lockedEntries.count))")
                                    .font(.headline)
                            }
                        }
                    }

                    // Read-Only section
                    if !readOnlyEntries.isEmpty {
                        Section {
                            ForEach(readOnlyEntries, id: \.originalPath) { entry in
                                entryRow(entry)
                                    .tag(entry.originalPath)
                            }
                        } header: {
                            HStack {
                                Image(systemName: "book.closed.fill")
                                    .foregroundColor(.blue)
                                Text("Read-Only (\(readOnlyEntries.count))")
                                    .font(.headline)
                            }
                        }
                    }

                    // Local-Only section
                    if !localOnlyEntries.isEmpty {
                        Section {
                            ForEach(localOnlyEntries, id: \.originalPath) { entry in
                                entryRow(entry)
                                    .tag(entry.originalPath)
                            }
                        } header: {
                            HStack {
                                Image(systemName: "network.slash")
                                    .foregroundColor(.orange)
                                Text("Local-Only (\(localOnlyEntries.count))")
                                    .font(.headline)
                            }
                        }
                    }
                }

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
        .frame(minWidth: 650, minHeight: 450)
        .onAppear { reload() }
    }

    private var selectedLockedCount: Int {
        if selectedPaths.isEmpty {
            return lockedEntries.count
        }
        return lockedEntries.filter { selectedPaths.contains($0.originalPath) }.count
    }

    // MARK: - Entry Row

    @ViewBuilder
    private func entryRow(_ entry: SecurityCoreBridge.VaultEntry) -> some View {
        HStack(spacing: 10) {
            // File/folder icon
            Image(systemName: entry.isDirectory ? "folder.fill" : fileIcon(for: entry.originalPath))
                .foregroundColor(iconColor(for: entry))
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 2) {
                Text((entry.originalPath as NSString).lastPathComponent)
                    .font(.body)
                    .lineLimit(1)

                Text(parentPath(entry.originalPath))
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            // Status badge
            statusBadge(entry)

            // Size
            Text(formatSize(entry.sizeBytes))
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 65, alignment: .trailing)
        }
        .padding(.vertical, 3)
    }

    @ViewBuilder
    private func statusBadge(_ entry: SecurityCoreBridge.VaultEntry) -> some View {
        if entry.protection == .locked && entry.isUnlocked {
            Text("DECRYPTED")
                .font(.caption2.bold())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.green.opacity(0.2))
                .foregroundColor(.green)
                .clipShape(RoundedRectangle(cornerRadius: 4))
        } else if entry.protection == .locked {
            Text("ENCRYPTED")
                .font(.caption2.bold())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.red.opacity(0.2))
                .foregroundColor(.red)
                .clipShape(RoundedRectangle(cornerRadius: 4))
        } else if entry.protection == .readOnly {
            Text("READ-ONLY")
                .font(.caption2.bold())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.blue.opacity(0.2))
                .foregroundColor(.blue)
                .clipShape(RoundedRectangle(cornerRadius: 4))
        } else {
            Text("MONITORED")
                .font(.caption2.bold())
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color.orange.opacity(0.2))
                .foregroundColor(.orange)
                .clipShape(RoundedRectangle(cornerRadius: 4))
        }
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
            entries.first(where: { $0.originalPath == p })?.protection == .locked
        }
        let readOnlyPaths = paths.filter { p in
            entries.first(where: { $0.originalPath == p })?.protection == .readOnly
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
                let result = SecurityCoreBridge.vaultUnlock(
                    securityDir: securityDir, paths: needsDecrypt, passphrase: passphrase)
                if result.success && result.entriesAffected > 0 {
                    messages.append("\(result.entriesAffected) file(s) decrypted")
                } else if !result.success {
                    messages.append("Decrypt failed: \(result.message)")
                }
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

        let result = SecurityCoreBridge.vaultRemove(
            securityDir: securityDir, paths: paths, passphrase: passphrase)
        if result.success {
            for path in paths { FinderTags.removeTag(path) }
            VaultDialogs.showSuccess(result.message)
        } else {
            VaultDialogs.showError(result.message)
        }
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
            let _ = SecurityCoreBridge.vaultLock(
                securityDir: securityDir, paths: toReEncrypt, passphrase: passphrase)
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

    private func reload() {
        entries = SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
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
        switch entry.protection {
        case .locked: return entry.isUnlocked ? .green : .red
        case .readOnly: return .blue
        case .localOnly: return .orange
        }
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
