import Foundation
import AppKit

/// Single owner of all vault file monitoring.
/// Uses one serial queue for thread safety, macOS bookmarks for move tracking,
/// and per-file DispatchSources for real-time event detection.
final class VaultFileTracker {

    // MARK: - Types

    struct TrackedFile {
        let originalPath: String
        let vaultPath: String
        let protection: SecurityCoreBridge.ProtectionLevel
        var bookmark: Data?
        var dispatchSource: DispatchSourceFileSystemObject?
        var fileDescriptor: Int32?
    }

    // MARK: - State (all access via serialQueue)

    private let serialQueue = DispatchQueue(label: "com.aisecurity.vault.tracker", qos: .utility)
    private var trackedFiles: [String: TrackedFile] = [:]  // keyed by originalPath
    private var alertedPaths: Set<String> = []             // dedup: one alert per event
    private var suppressCount = 0
    private let logger: SecurityLogger
    private let securityDir: String

    // Pending operations queued when passphrase is unavailable
    private var pendingMoves: [(old: String, new: String)] = []
    private var pendingDeletions: [String] = []

    // Periodic cleanup timer for detecting permanently deleted files
    private var cleanupTimer: DispatchSourceTimer?

    init(logger: SecurityLogger) {
        self.logger = logger
        self.securityDir = SecurityConfig.shared.securityDir
        // Auto-load tracked files from unencrypted sidecar (no passphrase needed).
        // This makes vault monitoring always-on from the moment the app launches.
        autoLoadFromSidecar()
        // Restore any pending operations from previous crash/restart
        loadPendingOps()
        // Start periodic cleanup timer to detect permanently deleted files
        startCleanupTimer()
    }

    /// Load all tracked files from the unencrypted sidecar and begin monitoring immediately.
    private func autoLoadFromSidecar() {
        let manifest = VaultTrackingStore.shared.load()
        guard !manifest.entries.isEmpty else { return }
        for entry in manifest.entries {
            let protection = SecurityCoreBridge.ProtectionLevel.from(sidecarKey: entry.protection)
            track(originalPath: entry.originalPath, vaultPath: entry.watchPath, protection: protection)
        }
        logger.info("\u{1F512} Vault tracker auto-loaded \(manifest.entries.count) file(s) from sidecar")
    }

    // MARK: - Track / Untrack

    /// Start tracking a vault-protected file. Creates bookmark + DispatchSource.
    func track(originalPath: String, vaultPath: String, protection: SecurityCoreBridge.ProtectionLevel) {
        serialQueue.async { [weak self] in
            guard let self else { return }

            // Determine which file to watch (the one that exists on disk)
            let watchPath = protection.isLocked ? vaultPath : originalPath
            guard !watchPath.isEmpty, FileManager.default.fileExists(atPath: watchPath) else { return }

            // Create bookmark
            let url = URL(fileURLWithPath: watchPath)
            let bookmark = try? url.bookmarkData()

            // Create DispatchSource
            let fd = open(watchPath, O_EVTONLY)
            var source: DispatchSourceFileSystemObject?
            if fd >= 0 {
                let src = DispatchSource.makeFileSystemObjectSource(
                    fileDescriptor: fd,
                    eventMask: [.write, .rename, .delete, .attrib],
                    queue: self.serialQueue
                )
                let trackedOriginal = originalPath
                src.setEventHandler { [weak self] in
                    self?.handleFileEvent(originalPath: trackedOriginal, watchPath: watchPath)
                }
                src.setCancelHandler { close(fd) }
                src.resume()
                source = src
            }

            // Apply deletion protection (uchg flag)
            FinderTags.protectFromDeletion(originalPath, protection: protection)

            self.trackedFiles[originalPath] = TrackedFile(
                originalPath: originalPath,
                vaultPath: vaultPath,
                protection: protection,
                bookmark: bookmark,
                dispatchSource: source,
                fileDescriptor: fd >= 0 ? fd : nil
            )

            self.updateWatchedPathsCache()
            self.logger.info("\u{1F512} Tracking: \((originalPath as NSString).lastPathComponent) [\(protection.label)]")
        }
    }

    /// Stop tracking a file completely. Cancels DispatchSource, removes bookmark, clears all state.
    func untrack(originalPath: String) {
        serialQueue.async { [weak self] in
            guard let self, let tracked = self.trackedFiles.removeValue(forKey: originalPath) else { return }

            // Cancel DispatchSource
            tracked.dispatchSource?.cancel()

            // Remove deletion protection
            FinderTags.unprotectFromDeletion(originalPath)

            // Remove from dedup
            self.alertedPaths.remove(originalPath)
            self.alertedPaths.remove(tracked.vaultPath)

            self.updateWatchedPathsCache()
            self.logger.info("\u{1F513} Untracked: \((originalPath as NSString).lastPathComponent)")
        }
    }

    /// Stop tracking all files (app quit or passphrase clear).
    func untrackAll() {
        serialQueue.async { [weak self] in
            guard let self else { return }
            for (_, tracked) in self.trackedFiles {
                tracked.dispatchSource?.cancel()
            }
            self.trackedFiles.removeAll()
            self.alertedPaths.removeAll()
            self.updateWatchedPathsCache()
        }
    }

    // MARK: - Suppress (for our own vault operations)

    func beginSuppress() {
        serialQueue.async { self.suppressCount += 1 }
    }

    func endSuppress() {
        // Delay to let filesystem events settle
        serialQueue.asyncAfter(deadline: .now() + 2.0) {
            self.suppressCount = max(0, self.suppressCount - 1)
        }
    }

    // MARK: - Sync with Manifest (called when vault opens)

    /// Reconcile tracked files with the current vault manifest entries.
    /// Adds tracking for entries not yet tracked, removes tracking for entries no longer in manifest.
    func syncWithManifest(entries: [SecurityCoreBridge.VaultEntry]) {
        serialQueue.async { [weak self] in
            guard let self else { return }

            let manifestPaths = Set(entries.map(\.originalPath))
            let trackedPaths = Set(self.trackedFiles.keys)

            // Remove tracking for entries no longer in manifest
            for path in trackedPaths.subtracting(manifestPaths) {
                if let tracked = self.trackedFiles.removeValue(forKey: path) {
                    tracked.dispatchSource?.cancel()
                    FinderTags.unprotectFromDeletion(path)
                }
            }

            // Add tracking for entries not yet tracked
            for entry in entries {
                if !trackedPaths.contains(entry.originalPath) {
                    let watchPath = entry.protection.isLocked ? entry.vaultPath : entry.originalPath
                    guard !watchPath.isEmpty, FileManager.default.fileExists(atPath: watchPath) else { continue }

                    let url = URL(fileURLWithPath: watchPath)
                    let bookmark = try? url.bookmarkData()

                    let fd = open(watchPath, O_EVTONLY)
                    var source: DispatchSourceFileSystemObject?
                    if fd >= 0 {
                        let src = DispatchSource.makeFileSystemObjectSource(
                            fileDescriptor: fd,
                            eventMask: [.write, .rename, .delete, .attrib],
                            queue: self.serialQueue
                        )
                        let trackedOriginal = entry.originalPath
                        src.setEventHandler { [weak self] in
                            self?.handleFileEvent(originalPath: trackedOriginal, watchPath: watchPath)
                        }
                        src.setCancelHandler { close(fd) }
                        src.resume()
                        source = src
                    }

                    self.trackedFiles[entry.originalPath] = TrackedFile(
                        originalPath: entry.originalPath,
                        vaultPath: entry.vaultPath,
                        protection: entry.protection,
                        bookmark: bookmark,
                        dispatchSource: source,
                        fileDescriptor: fd >= 0 ? fd : nil
                    )
                }
            }

            self.updateWatchedPathsCache()
        }
    }

    // MARK: - File Event Handler

    private func handleFileEvent(originalPath: String, watchPath: String) {
        // Already on serialQueue
        guard suppressCount == 0 else { return }
        guard !alertedPaths.contains(watchPath) else { return }

        let fm = FileManager.default
        let fileName = (watchPath as NSString).lastPathComponent

        if fm.fileExists(atPath: watchPath) {
            // File still exists — it was modified in place
            let alert = SecurityAlert(
                type: "VAULT_FILE_ACCESS",
                severity: .critical,
                message: "\u{1F6A8} Vault-protected file modified: \(fileName)",
                filePath: watchPath,
                findings: [FindingDetail(
                    label: "Protected file modified by external process",
                    category: "vault_protection",
                    severity: .critical
                )]
            )
            logger.alert(alert)
            VaultAuditLog.shared.log(.fileModified, path: watchPath,
                detail: "vault-protected file modified by external process")
            return
        }

        // File is gone — try to find where it went via bookmark
        alertedPaths.insert(watchPath)

        if let tracked = trackedFiles[originalPath], let bookmarkData = tracked.bookmark {
            var isStale = false
            if let resolvedURL = try? URL(resolvingBookmarkData: bookmarkData, options: [], relativeTo: nil, bookmarkDataIsStale: &isStale) {
                let newPath = resolvedURL.path
                if newPath != watchPath {
                    handleFileMoved(originalPath: originalPath, from: watchPath, to: newPath, fileName: fileName)
                    return
                }
            }
        }

        // Bookmark didn't resolve — search Trash, external drives, cloud storage
        let home = fm.homeDirectoryForCurrentUser.path

        // Check Trash (search for files containing the base name — macOS may rename)
        let trashDir = (home as NSString).appendingPathComponent(".Trash")
        if let trashMatch = searchForFile(named: fileName, in: trashDir) {
            handleFileMoved(originalPath: originalPath, from: watchPath, to: trashMatch, fileName: fileName)
            return
        }

        // Check external drives
        if let extMatch = searchForFile(named: fileName, in: "/Volumes", maxDepth: 2) {
            handleFileMoved(originalPath: originalPath, from: watchPath, to: extMatch, fileName: fileName)
            return
        }

        // Check cloud storage
        let cloudDir = (home as NSString).appendingPathComponent("Library/CloudStorage")
        if let cloudMatch = searchForFile(named: fileName, in: cloudDir, maxDepth: 2) {
            handleFileMoved(originalPath: originalPath, from: watchPath, to: cloudMatch, fileName: fileName)
            return
        }

        // Check iCloud Drive
        let icloudDir = (home as NSString).appendingPathComponent("Library/Mobile Documents")
        if let icloudMatch = searchForFile(named: fileName, in: icloudDir, maxDepth: 2) {
            handleFileMoved(originalPath: originalPath, from: watchPath, to: icloudMatch, fileName: fileName)
            return
        }

        logger.warn("\u{1F512} Vault file disappeared: \(fileName) (could not locate)")
        VaultAuditLog.shared.log(.unauthorizedAccess, path: watchPath,
            detail: "vault file disappeared — could not locate via bookmark, Trash, or external drives")
    }

    /// Search a directory for a file by name (shallow, max depth configurable).
    private func searchForFile(named fileName: String, in dir: String, maxDepth: Int = 1) -> String? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: dir) else { return nil }
        return searchDir(dir, for: fileName, depth: 0, maxDepth: maxDepth)
    }

    private func searchDir(_ dir: String, for fileName: String, depth: Int, maxDepth: Int) -> String? {
        guard depth <= maxDepth else { return nil }
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: dir) else { return nil }
        for entry in entries {
            let fullPath = (dir as NSString).appendingPathComponent(entry)
            if entry == fileName { return fullPath }
            // Also match Trash renames (e.g., "A5 2.png" for "A5.png")
            let baseName = (fileName as NSString).deletingPathExtension
            let ext = (fileName as NSString).pathExtension
            if entry.hasPrefix(baseName) && entry.hasSuffix(ext) { return fullPath }

            var isDir: ObjCBool = false
            if fm.fileExists(atPath: fullPath, isDirectory: &isDir), isDir.boolValue {
                if let found = searchDir(fullPath, for: fileName, depth: depth + 1, maxDepth: maxDepth) {
                    return found
                }
            }
        }
        return nil
    }

    private func handleFileMoved(originalPath: String, from: String, to newPath: String, fileName: String) {
        let isTrash = newPath.contains("/.Trash/")
        let isExternal = newPath.hasPrefix("/Volumes/")
        let isCloud = newPath.contains("CloudStorage") || newPath.contains("Mobile Documents")

        if isTrash {
            let alert = SecurityAlert(
                type: "VAULT_FILE_ACCESS",
                severity: .critical,
                message: "\u{1F6A8} Vault file moved to Trash: \(fileName)",
                filePath: newPath
            )
            logger.alert(alert)
            VaultAuditLog.shared.log(.fileMoved, path: newPath,
                detail: "moved to Trash from \(from)")

            DispatchQueue.main.async { [weak self] in
                let dialog = NSAlert()
                dialog.messageText = "\u{1F6A8} Vault File in Trash"
                dialog.informativeText = "\"\(fileName)\" is protected and was moved to Trash.\n\nTo safely delete: release protection in the Vault first."
                dialog.alertStyle = .critical
                dialog.addButton(withTitle: "Restore")
                dialog.addButton(withTitle: "Leave in Trash")
                NSApplication.shared.activate(ignoringOtherApps: true)

                if dialog.runModal() == .alertFirstButtonReturn {
                    do {
                        try FileManager.default.moveItem(atPath: newPath, toPath: from)
                        FinderTags.lockFile(from)
                        self?.logger.info("\u{2705} Vault file restored from Trash: \(fileName)")
                        VaultAuditLog.shared.log(.fileMoved, path: from,
                            detail: "restored from Trash")
                    } catch {
                        self?.logger.warn("\u{274C} Failed to restore from Trash: \(error.localizedDescription)")
                        let errAlert = NSAlert()
                        errAlert.messageText = "Restore Failed"
                        errAlert.informativeText = "Could not restore \"\(fileName)\":\n\(error.localizedDescription)\n\nYou may need to restore it manually from Trash."
                        errAlert.alertStyle = .warning
                        errAlert.addButton(withTitle: "OK")
                        errAlert.runModal()
                    }
                }
                self?.serialQueue.async { self?.alertedPaths.remove(from) }
            }
        } else if isExternal || isCloud {
            let locationType = isExternal ? "external drive" : "cloud storage"
            let alert = SecurityAlert(
                type: "VAULT_FILE_ACCESS",
                severity: .critical,
                message: "\u{1F6A8} Vault file moved to \(locationType): \(fileName)\nLocation: \(newPath)",
                filePath: newPath
            )
            logger.alert(alert)
            VaultAuditLog.shared.log(.fileMoved, path: newPath,
                detail: "moved to \(locationType) from \(from)")

            DispatchQueue.main.async { [weak self] in
                let dialog = NSAlert()
                dialog.messageText = "\u{1F6A8} Vault File on \(isExternal ? "External Drive" : "Cloud Storage")"
                dialog.informativeText = "\"\(fileName)\" was moved to:\n\(newPath)\n\nThis file is outside vault protection."
                dialog.alertStyle = .critical
                dialog.addButton(withTitle: "Move Back")
                dialog.addButton(withTitle: "Leave It")
                NSApplication.shared.activate(ignoringOtherApps: true)

                if dialog.runModal() == .alertFirstButtonReturn {
                    do {
                        try FileManager.default.moveItem(atPath: newPath, toPath: from)
                        FinderTags.lockFile(from)
                        self?.logger.info("\u{2705} Vault file moved back: \(fileName)")
                        VaultAuditLog.shared.log(.fileMoved, path: from,
                            detail: "restored from \(locationType)")
                    } catch {
                        self?.logger.warn("\u{274C} Failed to move back: \(error.localizedDescription)")
                    }
                } else {
                    // User chose to leave it — update tracking to new location
                    self?.serialQueue.async {
                        self?.updateTrackedPath(originalPath: originalPath, newPath: newPath)
                    }
                }
                self?.serialQueue.async { self?.alertedPaths.remove(from) }
            }
        } else {
            // Local move — update tracking to reflect new location
            logger.info("\u{1F4C1} Vault file moved locally: \(fileName) → \(newPath)")
            updateTrackedPath(originalPath: originalPath, newPath: newPath)
            alertedPaths.remove(from)
        }
    }

    /// Persist a file move to the sidecar and (if passphrase available) the encrypted manifest.
    /// Re-keys the tracker dictionary and recreates the DispatchSource at the new path.
    private func updateTrackedPath(originalPath: String, newPath: String) {
        // 1. Update sidecar immediately (no passphrase needed)
        VaultTrackingStore.shared.updatePath(oldPath: originalPath, newPath: newPath)

        // 2. Update encrypted manifest if passphrase available
        if let pass = VaultManager.shared.passphrase {
            let result = SecurityCoreBridge.vaultUpdatePath(
                securityDir: securityDir,
                oldPath: originalPath, newPath: newPath,
                passphrase: pass
            )
            if !result.success {
                logger.warn("\u{274C} Failed to update manifest path: \(result.message)")
            }
        } else {
            // Queue for next auth
            pendingMoves.append((old: originalPath, new: newPath))
            persistPendingOps()
        }

        // 3. Re-key tracker dictionary + recreate DispatchSource
        if let tracked = trackedFiles.removeValue(forKey: originalPath) {
            tracked.dispatchSource?.cancel()
            let newWatchPath = tracked.protection.isLocked ? newPath + ".vault" : newPath
            // Re-track at new path (creates new bookmark + DispatchSource)
            track(originalPath: newPath, vaultPath: newWatchPath, protection: tracked.protection)
        }

        // 4. Log to audit trail
        VaultAuditLog.shared.log(.fileMoved, path: newPath, detail: "from: \(originalPath)")
    }

    // MARK: - Periodic Cleanup (detect permanently deleted files)

    private func startCleanupTimer() {
        let timer = DispatchSource.makeTimerSource(queue: serialQueue)
        timer.schedule(deadline: .now() + 60, repeating: 60)
        timer.setEventHandler { [weak self] in self?.checkTrackedFilesExist() }
        timer.resume()
        cleanupTimer = timer
    }

    /// Check all tracked files for existence. Files that are gone and can't be found
    /// via bookmark are added to pendingDeletions for cleanup.
    private func checkTrackedFilesExist() {
        let fm = FileManager.default
        var toDelete: [String] = []

        for (path, tracked) in trackedFiles {
            let watchPath = tracked.protection.isLocked ? tracked.vaultPath : path
            guard !watchPath.isEmpty else { continue }

            // For locked files, also check computed vault path in case tracker is stale
            let computedVault = path + ".vault"
            let filePresent = fm.fileExists(atPath: watchPath)
                || (tracked.protection.isLocked && fm.fileExists(atPath: computedVault))
                || fm.fileExists(atPath: path)  // original might exist if temporarily unlocked

            if !filePresent {
                // Try bookmark resolution
                var resolved = false
                if let bookmarkData = tracked.bookmark {
                    var isStale = false
                    if let resolvedURL = try? URL(resolvingBookmarkData: bookmarkData,
                                                   options: [], relativeTo: nil,
                                                   bookmarkDataIsStale: &isStale) {
                        let newPath = resolvedURL.path
                        if newPath != watchPath && fm.fileExists(atPath: newPath) {
                            // File moved — handle via move tracking
                            let fileName = (watchPath as NSString).lastPathComponent
                            handleFileMoved(originalPath: path, from: watchPath, to: newPath, fileName: fileName)
                            resolved = true
                        }
                    }
                }

                if !resolved {
                    toDelete.append(path)
                }
            }
        }

        if !toDelete.isEmpty {
            processDeletions(paths: toDelete)
        }
    }

    /// Handle files detected as permanently deleted.
    /// Only removes from tracking (not from the encrypted manifest) to prevent data loss.
    /// The vault window's cleanupDeletedEntries() handles manifest cleanup with user confirmation.
    private func processDeletions(paths: [String]) {
        for path in paths {
            // Only stop monitoring — do NOT remove from vault manifest.
            // The vault window will detect missing files and ask the user.
            if let tracked = trackedFiles.removeValue(forKey: path) {
                tracked.dispatchSource?.cancel()
            }
            alertedPaths.remove(path)

            VaultAuditLog.shared.log(.fileDeleted, path: path,
                detail: "file not found on disk, stopped monitoring (vault entry preserved)")
            logger.info("\u{1F5D1} Vault file missing, stopped tracking: \((path as NSString).lastPathComponent)")
        }

        updateWatchedPathsCache()
    }

    // MARK: - Pending Operations

    /// Process queued moves and deletions that were waiting for passphrase.
    /// Called from VaultManager.syncTracker() when user authenticates.
    func processPendingOps(passphrase: String, securityDir: String) {
        serialQueue.async { [weak self] in
            guard let self else { return }

            // Process pending moves
            for move in self.pendingMoves {
                let result = SecurityCoreBridge.vaultUpdatePath(
                    securityDir: securityDir,
                    oldPath: move.old, newPath: move.new,
                    passphrase: passphrase
                )
                if result.success {
                    self.logger.info("\u{1F4C1} Pending move applied: \(move.old) → \(move.new)")
                }
            }
            self.pendingMoves.removeAll()

            // Process pending deletions
            for path in self.pendingDeletions {
                let result = SecurityCoreBridge.vaultRemove(
                    securityDir: securityDir,
                    paths: [path], passphrase: passphrase
                )
                if result.success {
                    self.logger.info("\u{1F5D1} Pending deletion applied: \(path)")
                }
            }
            self.pendingDeletions.removeAll()

            self.clearPendingOpsFile()
        }
    }

    /// Persist pending ops to disk for crash recovery.
    private func persistPendingOps() {
        let ops: [String: Any] = [
            "moves": pendingMoves.map { ["old": $0.old, "new": $0.new] },
            "deletions": pendingDeletions
        ]
        let file = (securityDir as NSString).appendingPathComponent("vault-pending-ops.json")
        if let data = try? JSONSerialization.data(withJSONObject: ops, options: .prettyPrinted) {
            try? data.write(to: URL(fileURLWithPath: file))
        }
    }

    /// Load pending ops from disk (crash recovery).
    private func loadPendingOps() {
        let file = (securityDir as NSString).appendingPathComponent("vault-pending-ops.json")
        guard let data = FileManager.default.contents(atPath: file),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        if let moves = dict["moves"] as? [[String: String]] {
            pendingMoves = moves.compactMap { m in
                guard let old = m["old"], let new = m["new"] else { return nil }
                return (old: old, new: new)
            }
        }
        if let dels = dict["deletions"] as? [String] {
            pendingDeletions = dels
        }
    }

    private func clearPendingOpsFile() {
        let file = (securityDir as NSString).appendingPathComponent("vault-pending-ops.json")
        try? FileManager.default.removeItem(atPath: file)
    }

    // MARK: - Watched Paths Cache

    private func updateWatchedPathsCache() {
        let paths = trackedFiles.values.flatMap { tracked -> [String] in
            var p = [tracked.originalPath]
            if !tracked.vaultPath.isEmpty { p.append(tracked.vaultPath) }
            return p
        }

        let cache: [String: Any] = [
            "updatedAt": ISO8601DateFormatter().string(from: Date()),
            "paths": paths
        ]

        let cacheFile = (securityDir as NSString).appendingPathComponent("vault-watched-paths.json")
        if let data = try? JSONSerialization.data(withJSONObject: cache, options: .prettyPrinted) {
            try? data.write(to: URL(fileURLWithPath: cacheFile))
        }
    }
}
