import Foundation
import AppKit

/// Monitors temporarily decrypted vault files and auto-re-encrypts them
/// when no process has them open. Polls every 10 seconds via DispatchSourceTimer.
/// Files are force-re-encrypted after 30 minutes regardless.
final class TemporaryDecryptMonitor {

    static let shared = TemporaryDecryptMonitor()

    private struct WatchedFile {
        let path: String
        let passphrase: String
        let securityDir: String
        let openedAt: Date
        var closedSince: Date?  // when we first detected file as closed
    }

    private let queue = DispatchQueue(label: "com.aisecurity.temp-decrypt-monitor")
    private var watchedFiles: [WatchedFile] = []
    private var timer: DispatchSourceTimer?

    private let pollInterval: TimeInterval = 10
    private let maxOpenDuration: TimeInterval = 1800 // 30 minutes
    private let minOpenDuration: TimeInterval = 15   // don't re-encrypt within 15s of opening
    private let closeGracePeriod: TimeInterval = 5    // wait 5s after close detected to confirm

    private init() {}

    /// Begin watching temporarily decrypted files for auto-re-encrypt.
    func watch(paths: [String], passphrase: String, securityDir: String) {
        queue.async { [weak self] in
            guard let self = self else { return }
            for path in paths {
                // Don't double-watch
                guard !self.watchedFiles.contains(where: { $0.path == path }) else { continue }
                self.watchedFiles.append(WatchedFile(
                    path: path, passphrase: passphrase,
                    securityDir: securityDir, openedAt: Date()))
            }
            self.ensureTimerRunning()
        }
    }

    /// Stop watching specific paths (e.g. if user manually re-encrypts).
    func unwatch(paths: [String]) {
        queue.async { [weak self] in
            self?.watchedFiles.removeAll { paths.contains($0.path) }
            self?.stopTimerIfEmpty()
        }
    }

    /// Stop watching all files.
    func unwatchAll() {
        queue.async { [weak self] in
            self?.watchedFiles.removeAll()
            self?.stopTimerIfEmpty()
        }
    }

    // MARK: - Timer

    private func ensureTimerRunning() {
        // Already on queue
        guard timer == nil, !watchedFiles.isEmpty else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + pollInterval, repeating: pollInterval)
        t.setEventHandler { [weak self] in self?.poll() }
        t.resume()
        timer = t
    }

    private func stopTimerIfEmpty() {
        // Already on queue
        guard watchedFiles.isEmpty else { return }
        timer?.cancel()
        timer = nil
    }

    // MARK: - Poll

    private func poll() {
        // Already on queue
        let now = Date()
        var toReencrypt: [WatchedFile] = []

        for i in watchedFiles.indices {
            let file = watchedFiles[i]
            let timedOut = now.timeIntervalSince(file.openedAt) >= maxOpenDuration
            let tooSoon = now.timeIntervalSince(file.openedAt) < minOpenDuration

            // Don't check too soon after opening — app hasn't fully opened yet
            if tooSoon { continue }

            let stillOpen = isFileOpen(file.path)

            if timedOut {
                toReencrypt.append(file)
            } else if !stillOpen {
                // Use grace period — require file to be closed for 5s to avoid race
                if let closedSince = file.closedSince {
                    if now.timeIntervalSince(closedSince) >= closeGracePeriod {
                        toReencrypt.append(file)
                    }
                } else {
                    watchedFiles[i].closedSince = now
                }
            } else {
                // File is open again, reset close detection
                watchedFiles[i].closedSince = nil
            }
        }

        guard !toReencrypt.isEmpty else { return }

        // Remove from watch list before re-encrypting
        let reencryptPaths = Set(toReencrypt.map(\.path))
        watchedFiles.removeAll { reencryptPaths.contains($0.path) }
        stopTimerIfEmpty()

        // Re-encrypt on a background thread (don't block the poll queue)
        DispatchQueue.global(qos: .utility).async {
            for file in toReencrypt {
                self.reencrypt(file)
            }
        }
    }

    // MARK: - File Open Check

    /// Check if any process has the file open using lsof.
    private func isFileOpen(_ path: String) -> Bool {
        guard FileManager.default.fileExists(atPath: path) else { return false }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        // +f -- = don't resolve names, just check file
        // -F p = output only PID fields (minimal output)
        process.arguments = ["-F", "p", path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            // lsof exit code 0 = file is open by some process
            // exit code 1 = no processes have it open
            return process.terminationStatus == 0
        } catch {
            // If lsof fails, assume file might be open (safer)
            return true
        }
    }

    // MARK: - Re-encrypt

    private func reencrypt(_ file: WatchedFile) {
        VaultOperationScope.begin()
        defer { VaultOperationScope.end() }

        // Remove immutable flags before re-encrypting
        FinderTags.unlockFile(file.path)
        FinderTags.unlockFile(file.path + ".vault")

        let result = SecurityCoreBridge.vaultLock(
            securityDir: file.securityDir,
            paths: [file.path],
            passphrase: file.passphrase)

        if result.success {
            // Unhide the .vault file
            let vaultFile = file.path + ".vault"
            if FileManager.default.fileExists(atPath: vaultFile) {
                let url = URL(fileURLWithPath: vaultFile)
                try? (url as NSURL).setResourceValue(false, forKey: .isHiddenKey)
            }

            // Update tracking
            VaultTrackingStore.shared.updateWatchPath(
                originalPath: file.path, newWatchPath: vaultFile)

            // Re-apply deletion protection
            FinderTags.lockFile(vaultFile)

            // Audit log
            VaultAuditLog.shared.log(.fileLocked, path: file.path,
                detail: "auto-re-encrypted after temporary open")

            // Sync tracker
            VaultManager.shared.syncTracker(passphrase: file.passphrase)
        } else {
            // Log failure but don't crash
            VaultAuditLog.shared.log(.fileLocked, path: file.path,
                detail: "auto-re-encrypt FAILED: \(result.message)")
        }
    }
}
