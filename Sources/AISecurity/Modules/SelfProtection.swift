import Foundation

/// Active self-protection: watches the LaunchAgent plist and the app bundle,
/// and *restores* (not just alerts on) tampering.
///
/// Threat model: a local attacker running as the user account wants to kill
/// the security agent. Standard moves:
///   1. `launchctl bootout gui/UID ~/Library/LaunchAgents/com.aisecurity.shield.plist`
///   2. `rm ~/Library/LaunchAgents/com.aisecurity.shield.plist`
///   3. `rm -rf /Applications/AISecurity.app`
///   4. `pkill -f AISecurity-bin`
///
/// This module defends against (1) and (2) by re-writing the canonical plist
/// and re-bootstrapping it. It detects and alerts loudly on (3). It cannot
/// defend (4) from inside the dying process, but the LaunchAgent's
/// `KeepAlive=true` will relaunch unless the plist itself is gone — which is
/// exactly what (1)+(2) aim to achieve, and which this module prevents.
///
/// Scope: user-level only. A determined attacker with `sudo` or SIP bypass
/// can defeat any user-level watchdog. For defense against that, we would
/// need a privileged LaunchDaemon — out of scope for now.
final class SelfProtection: @unchecked Sendable {

    // MARK: - Configuration

    /// LaunchAgent label — must match install.sh.
    private static let agentLabel = "com.aisecurity.shield"

    /// Path to the LaunchAgent plist.
    private let agentPlistPath: String
    /// Path to the app bundle (wherever the running binary lives).
    private let appBundlePath: String
    /// Directory for diagnostic logs.
    private let logsDir: String

    /// Cooldown between restoration attempts to avoid tight loops if an
    /// attacker keeps overwriting the plist.
    private let restoreCooldown: TimeInterval = 15.0
    private var lastRestoreAt: Date = .distantPast
    private let restoreLock = NSLock()

    /// Canonical plist bytes generated once at startup. We compare against
    /// this to detect content tampering (not just deletion).
    private let canonicalPlistBytes: Data

    private var plistSource: DispatchSourceFileSystemObject?
    private var bundleSource: DispatchSourceFileSystemObject?
    private var periodicTimer: DispatchSourceTimer?

    /// Fires when tampering is detected + restored. Daemon wires this to
    /// alert routing (notification + log).
    var onTamperDetected: ((String, String) -> Void)?  // (kind, detail)

    // MARK: - Init

    init(securityDir: String) {
        let home = NSHomeDirectory()
        self.agentPlistPath = "\(home)/Library/LaunchAgents/\(Self.agentLabel).plist"
        self.appBundlePath = Bundle.main.bundlePath
        self.logsDir = (securityDir as NSString).appendingPathComponent("logs")
        self.canonicalPlistBytes = Self.buildCanonicalPlist(
            bundlePath: self.appBundlePath,
            securityDir: securityDir
        )
    }

    // MARK: - Lifecycle

    func start() {
        // Verify-and-repair once synchronously so the plist is known-good
        // before we even start watching it.
        _ = verifyAndRepairPlist(reason: "startup-check")

        watchAgentPlist()
        watchAppBundle()
        startPeriodicVerification()
        note("SelfProtection active: watching \(agentPlistPath) and \(appBundlePath)")
    }

    func stop() {
        plistSource?.cancel()
        bundleSource?.cancel()
        periodicTimer?.cancel()
        plistSource = nil
        bundleSource = nil
        periodicTimer = nil
    }

    /// Periodic re-check runs every 30 seconds. Catches cases where:
    ///   - File events fired during cooldown and were dropped
    ///   - Attacker held the fd open / worked around DispatchSource
    ///   - Bundle path became invalid mid-run
    /// After two missed restorations via events, the periodic check guarantees
    /// convergence within ~30s even if every event-triggered repair was
    /// cooldown-blocked.
    private func startPeriodicVerification() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 30, repeating: 30)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            let restored = self.verifyAndRepairPlist(reason: "periodic-check")
            if restored {
                self.onTamperDetected?(
                    "LAUNCH_AGENT_TAMPER",
                    "LaunchAgent plist found tampered during periodic check — restored"
                )
            }
        }
        timer.resume()
        periodicTimer = timer
    }

    // MARK: - Plist monitoring

    private func watchAgentPlist() {
        guard FileManager.default.fileExists(atPath: agentPlistPath) else {
            // If it's already missing at startup, verifyAndRepairPlist will
            // have written it above. Re-check.
            if !FileManager.default.fileExists(atPath: agentPlistPath) {
                note("WARNING: LaunchAgent plist missing and could not be restored at startup")
                return
            }
            watchAgentPlist()   // retry once after restoration
            return
        }

        let fd = open(agentPlistPath, O_EVTONLY)
        guard fd >= 0 else {
            note("WARNING: could not open \(agentPlistPath) for monitoring")
            return
        }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .attrib],
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            let flags = source.data
            var kinds: [String] = []
            if flags.contains(.delete) { kinds.append("deleted") }
            if flags.contains(.rename) { kinds.append("renamed") }
            if flags.contains(.write)  { kinds.append("modified") }
            if flags.contains(.attrib) { kinds.append("permissions changed") }

            let kindStr = kinds.joined(separator: ", ")
            self.note("Tamper event on LaunchAgent plist: \(kindStr)")

            // Re-verify and restore if needed.
            let restored = self.verifyAndRepairPlist(reason: kindStr)
            if restored {
                self.onTamperDetected?(
                    "LAUNCH_AGENT_TAMPER",
                    "LaunchAgent plist was \(kindStr) — restored from canonical template"
                )
            }

            // If the underlying file was deleted/renamed, our fd is stale.
            // Cancel and re-watch the new inode.
            if flags.contains(.delete) || flags.contains(.rename) {
                source.cancel()
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1.0) {
                    self.watchAgentPlist()
                }
            }
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        plistSource = source
    }

    /// Check the plist on disk against the canonical version. Returns true
    /// iff a restoration was performed.
    @discardableResult
    private func verifyAndRepairPlist(reason: String) -> Bool {
        // Cooldown guard — prevents a CPU-spinning loop if an attacker is
        // holding the path open and re-writing it.
        restoreLock.lock()
        let now = Date()
        if now.timeIntervalSince(lastRestoreAt) < restoreCooldown {
            restoreLock.unlock()
            return false
        }
        restoreLock.unlock()

        let fm = FileManager.default
        // Compare semantically (parse both plists) rather than byte-for-byte
        // because install.sh writes heredoc formatting and our canonical is
        // emitted by PropertyListSerialization — they're equivalent data but
        // not byte-identical. A byte-exact check would restore on every boot.
        let onDisk = fm.contents(atPath: agentPlistPath)
        if Self.plistsEquivalent(onDisk, canonicalPlistBytes) {
            return false   // already correct
        }

        // Need to restore.
        do {
            // Ensure LaunchAgents directory exists.
            let dir = (agentPlistPath as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: nil)

            // Atomic write.
            let tmp = agentPlistPath + ".restore.tmp"
            try canonicalPlistBytes.write(to: URL(fileURLWithPath: tmp), options: .atomic)
            _ = try? fm.removeItem(atPath: agentPlistPath)
            try fm.moveItem(atPath: tmp, toPath: agentPlistPath)

            // Restrict permissions: user read/write only.
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: agentPlistPath)

            note("RESTORED LaunchAgent plist (trigger: \(reason))")

            // Re-register with launchctl so auto-start on next login works.
            reloadLaunchAgent()

            restoreLock.lock()
            lastRestoreAt = Date()
            restoreLock.unlock()

            return true
        } catch {
            note("ERROR: failed to restore LaunchAgent plist: \(error.localizedDescription)")
            return false
        }
    }

    /// Re-register the plist with launchctl. Safe to call even if already loaded.
    private func reloadLaunchAgent() {
        let uid = getuid()

        // Try modern bootstrap first; fall back to legacy load.
        // Both operations are idempotent-ish (bootout may fail silently).
        runTool("/bin/launchctl", args: ["bootout", "gui/\(uid)", agentPlistPath])
        runTool("/bin/launchctl", args: ["bootstrap", "gui/\(uid)", agentPlistPath])
    }

    private func runTool(_ path: String, args: [String]) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        proc.standardOutput = Pipe()
        proc.standardError = Pipe()
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            note("WARN: \(path) \(args.joined(separator: " ")) failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Bundle monitoring

    private func watchAppBundle() {
        guard FileManager.default.fileExists(atPath: appBundlePath) else {
            note("WARNING: app bundle missing at \(appBundlePath) — cannot watch")
            return
        }
        let fd = open(appBundlePath, O_EVTONLY)
        guard fd >= 0 else { return }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.delete, .rename],
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            let flags = source.data
            var kinds: [String] = []
            if flags.contains(.delete) { kinds.append("deleted") }
            if flags.contains(.rename) { kinds.append("renamed") }
            let kindStr = kinds.joined(separator: ", ")
            self.note("CRITICAL: app bundle was \(kindStr) — reinstall required")
            self.onTamperDetected?(
                "APP_BUNDLE_TAMPER",
                "Application bundle at \(self.appBundlePath) was \(kindStr). Reinstall AISecurity."
            )
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        bundleSource = source
    }

    /// Parse both plists and compare the fields that matter. Any difference
    /// in Label, ProgramArguments, RunAtLoad, KeepAlive, or
    /// LimitLoadToSessionType triggers a restore; stdout/stderr log path
    /// differences are tolerated (user may have customized log location).
    private static func plistsEquivalent(_ a: Data?, _ b: Data) -> Bool {
        guard let a = a else { return false }
        guard
            let da = try? PropertyListSerialization.propertyList(from: a, format: nil) as? [String: Any],
            let db = try? PropertyListSerialization.propertyList(from: b, format: nil) as? [String: Any]
        else {
            return false
        }

        let criticalKeys: [String] = [
            "Label",
            "ProgramArguments",
            "RunAtLoad",
            "KeepAlive",
            "LimitLoadToSessionType"
        ]
        for key in criticalKeys {
            let va = da[key]
            let vb = db[key]
            if !anyEqual(va, vb) {
                return false
            }
        }
        return true
    }

    /// Minimal structural equality for the plist types we emit: String, Bool,
    /// Int, and [String]. Returns false for anything more exotic so unexpected
    /// content triggers a restore (fail safe).
    private static func anyEqual(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil):
            return true
        case let (x as String, y as String):
            return x == y
        case let (x as Bool, y as Bool):
            return x == y
        case let (x as Int, y as Int):
            return x == y
        case let (x as [String], y as [String]):
            return x == y
        default:
            return false
        }
    }

    // MARK: - Canonical plist

    /// Build the canonical plist content matching install.sh exactly. Using
    /// PropertyListSerialization ensures the byte-for-byte output is stable
    /// across launches, so our equality check doesn't false-positive on
    /// formatting differences.
    private static func buildCanonicalPlist(bundlePath: String, securityDir: String) -> Data {
        let logsDir = (securityDir as NSString).appendingPathComponent("logs")
        let dict: [String: Any] = [
            "Label": agentLabel,
            "ProgramArguments": [
                "/usr/bin/open",
                "-W",
                "-a",
                bundlePath
            ],
            "RunAtLoad": true,
            "KeepAlive": true,
            "LimitLoadToSessionType": "Aqua",
            "StandardOutPath": "\(logsDir)/launchagent-stdout.log",
            "StandardErrorPath": "\(logsDir)/launchagent-stderr.log"
        ]
        do {
            return try PropertyListSerialization.data(
                fromPropertyList: dict,
                format: .xml,
                options: 0
            )
        } catch {
            // Should be unreachable with known-good input; return empty so
            // the equality check fails (no false-positive restore).
            return Data()
        }
    }

    // MARK: - Logging

    private func note(_ msg: String) {
        let line = "[\(Date())] [SelfProtection] \(msg)\n"
        let path = (logsDir as NSString).appendingPathComponent("self-protection.log")
        if let handle = FileHandle(forWritingAtPath: path) {
            handle.seekToEndOfFile()
            handle.write(line.data(using: .utf8) ?? Data())
            handle.closeFile()
        } else {
            try? line.write(toFile: path, atomically: true, encoding: .utf8)
        }
    }
}
