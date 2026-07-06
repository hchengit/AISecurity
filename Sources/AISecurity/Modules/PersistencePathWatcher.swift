import Foundation
import CryptoKit

/// Persistence-path watcher — detects *new* or *modified* files along the
/// user-level attack paths that survive a reboot.
///
/// # Design vs SelfProtection
///
/// `SelfProtection.swift` owns the **restore** story for our own LaunchAgent
/// plist — it detects tampering and rewrites the canonical plist. This
/// module is strictly **detect-only**, as the plan specifies: we watch
/// everything a malicious installer would touch to survive a reboot, alert
/// the user, and let them decide. No automatic restore / rollback — those
/// paths are user-owned.
///
/// Keeping the two modules separate:
///   1. Preserves SelfProtection's focused invariant (our own plist is
///      always canonical).
///   2. Prevents a future refactor from accidentally auto-restoring a
///      user-owned `.zshrc` or VS Code extension — which would be
///      destructive.
///
/// # What it watches
///
/// * Shell rc files — `.zshrc`, `.bashrc`, `.bash_profile`, `.zprofile`,
///   `.zshenv`, `.profile`.
/// * All LaunchAgent plists in `~/Library/LaunchAgents/` — new plist from
///   a non-installer process is CRITICAL.
/// * `~/Library/Script Libraries/`.
/// * Editor extension directories — `.vscode/extensions`, `.cursor/extensions`,
///   `.config/nvim/pack/*/start/`.
/// * `~/.gitconfig` — an attacker can set `core.hooksPath` or an alias.
/// * `.git/hooks/` under each configured `project_root` — hooks run on
///   checkout / merge / commit.
///
/// # Baseline semantics
///
/// On first run, hash the current state and save it silently. On subsequent
/// runs, diff: new file or hash change → alert. Removed file → quiet (the
/// user may have legitimately cleaned up).
final class PersistencePathWatcher: @unchecked Sendable {

    // MARK: - Config

    struct Config: Sendable {
        let enabled: Bool
        /// Project roots to scan for `.git/hooks/` (same list as
        /// dependency_drift roots in practice).
        let projectRoots: [String]
    }

    // MARK: - Types

    struct Baseline: Codable {
        let fileHashes: [String: String]     // absolute path → sha256
        let rcLineCounts: [String: Int]      // rc file → how many non-comment lines
        let knownPlists: [String]            // absolute plist paths we've seen
        let lastScan: String
    }

    typealias AlertHandler = @Sendable (SecurityAlert) -> Void

    // MARK: - State

    private let logger: SecurityLogger
    private let securityDir: String
    private let baselineFile: String
    private let cfg: Config
    private var sources: [DispatchSourceFileSystemObject] = []
    private var fileDescriptors: [Int32] = []
    private var debounceTimers: [String: DispatchWorkItem] = [:]
    private let stateLock = NSLock()

    private var fileHashes: [String: String] = [:]
    private var rcLineCounts: [String: Int] = [:]
    private var knownPlists: Set<String> = []
    private(set) var isRunning = false

    /// Path to our OWN LaunchAgent plist — SelfProtection already owns this
    /// one; suppress double-alerts here.
    private let ownPlistPath: String = "\(NSHomeDirectory())/Library/LaunchAgents/com.aisecurity.shield.plist"

    var onAlert: AlertHandler?

    // MARK: - Init

    init(logger: SecurityLogger, securityDir: String, cfg: Config) {
        self.logger = logger
        self.securityDir = securityDir
        self.baselineFile = (securityDir as NSString).appendingPathComponent("persistence-baseline.json")
        self.cfg = cfg
    }

    // MARK: - Lifecycle

    func start() {
        guard !isRunning else { return }
        guard cfg.enabled else {
            logger.info("\u{1F50C} Persistence Path Watcher: disabled in config")
            return
        }
        isRunning = true
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.discoverAndWatch()
        }
    }

    func stop() {
        for source in sources { source.cancel() }
        for fd in fileDescriptors { close(fd) }
        sources.removeAll()
        fileDescriptors.removeAll()
        stateLock.lock()
        debounceTimers.values.forEach { $0.cancel() }
        debounceTimers.removeAll()
        stateLock.unlock()
        isRunning = false
        logger.info("\u{1F50C} Persistence Path Watcher stopped")
    }

    // MARK: - Discovery

    private func discoverAndWatch() {
        let prior = loadBaseline()
        fileHashes = prior.fileHashes
        rcLineCounts = prior.rcLineCounts
        knownPlists = Set(prior.knownPlists)

        // First run primes silently; subsequent runs diff.
        let isFirstRun = prior.fileHashes.isEmpty && prior.knownPlists.isEmpty

        // 1. rc-files + single-file targets (hash-watched).
        let rcFiles = discoverRcFiles()
        for f in rcFiles {
            scanRcFile(f, firstRun: isFirstRun)
            watchFile(f)
        }

        // 2. ~/Library/LaunchAgents — watch the directory so new plists
        // trigger alerts.
        let laDir = "\(NSHomeDirectory())/Library/LaunchAgents"
        scanLaunchAgentsDir(laDir, firstRun: isFirstRun)
        watchDirectory(laDir)

        // 3. Script Libraries.
        let scriptsDir = "\(NSHomeDirectory())/Library/Script Libraries"
        if FileManager.default.fileExists(atPath: scriptsDir) {
            scanDirectoryForNewFiles(scriptsDir, category: "script_library",
                                     severity: .medium, firstRun: isFirstRun)
            watchDirectory(scriptsDir)
        }

        // 4. Editor extensions.
        for extDir in discoverExtensionDirs() {
            scanDirectoryForNewFiles(extDir, category: "editor_extension",
                                     severity: .medium, firstRun: isFirstRun)
            watchDirectory(extDir)
        }

        // 5. .gitconfig — watch for aliased hooksPath.
        let gitconfig = "\(NSHomeDirectory())/.gitconfig"
        if FileManager.default.fileExists(atPath: gitconfig) {
            scanGitconfig(gitconfig, firstRun: isFirstRun)
            watchFile(gitconfig)
        }

        // 6. .git/hooks under each project root.
        for root in cfg.projectRoots {
            let expanded = expandHome(root)
            for hooksDir in discoverGitHooks(under: expanded) {
                scanDirectoryForNewFiles(hooksDir, category: "git_hook",
                                         severity: .high, firstRun: isFirstRun)
                watchDirectory(hooksDir)
            }
        }

        saveBaseline()

        if isFirstRun {
            logger.info("\u{1F50C} Persistence Path Watcher: baseline primed (\(fileHashes.count) files, \(knownPlists.count) LaunchAgent plists)")
        } else {
            logger.info("\u{1F50C} Persistence Path Watcher started — watching \(sources.count) paths")
        }
    }

    // MARK: - Scanners

    private func discoverRcFiles() -> [String] {
        let home = NSHomeDirectory()
        let candidates = [
            ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".zshenv", ".profile",
        ]
        return candidates.compactMap { name in
            let full = "\(home)/\(name)"
            return FileManager.default.fileExists(atPath: full) ? full : nil
        }
    }

    private func discoverExtensionDirs() -> [String] {
        let home = NSHomeDirectory()
        let candidates = [
            "\(home)/.vscode/extensions",
            "\(home)/.cursor/extensions",
        ]
        var out: [String] = []
        for c in candidates {
            if FileManager.default.fileExists(atPath: c) { out.append(c) }
        }
        // Neovim: ~/.config/nvim/pack/*/start/
        let nvimPack = "\(home)/.config/nvim/pack"
        if let entries = try? FileManager.default.contentsOfDirectory(atPath: nvimPack) {
            for entry in entries {
                let start = "\(nvimPack)/\(entry)/start"
                if FileManager.default.fileExists(atPath: start) { out.append(start) }
            }
        }
        return out
    }

    private func discoverGitHooks(under root: String) -> [String] {
        var out: [String] = []
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: root) else { return out }
        for entry in entries {
            if entry.hasPrefix(".") { continue }
            let hooks = (root as NSString).appendingPathComponent(entry) + "/.git/hooks"
            if FileManager.default.fileExists(atPath: hooks) {
                out.append(hooks)
            }
        }
        return out
    }

    /// Hash + count non-comment lines. On change we look for "suspicious"
    /// additions: new `export PATH=` prefixing a user-writable dir, new
    /// alias commands.
    private func scanRcFile(_ path: String, firstRun: Bool) {
        guard let data = FileManager.default.contents(atPath: path),
              let text = String(data: data, encoding: .utf8) else { return }
        let hash = sha256hex(data)
        let lineCount = text.split(separator: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }
            .count

        if firstRun {
            fileHashes[path] = hash
            rcLineCounts[path] = lineCount
            return
        }

        let priorHash = fileHashes[path]
        let priorCount = rcLineCounts[path] ?? 0
        if priorHash == hash { return }

        // Content changed. Classify severity based on what got added.
        let sev = classifyRcChange(text: text, priorLineCount: priorCount)
        let verb = priorHash == nil ? "created" : "modified"
        emit(
            type: "SHELL_RC_MODIFIED",
            severity: sev,
            filePath: path,
            message: """
            \u{1F50C} Shell rc file \(verb): \((path as NSString).lastPathComponent)
            This file runs on every new shell session. Inspect changes before opening a new terminal.

            Check with: git diff "\(path)"  (if under git) or compare against your dotfiles backup.
            """
        )
        fileHashes[path] = hash
        rcLineCounts[path] = lineCount
    }

    /// HIGH if the change looks like PATH hijacking, MEDIUM otherwise.
    private func classifyRcChange(text: String, priorLineCount: Int) -> SeverityLevel {
        // PATH hijack: `export PATH=/tmp/...:$PATH` — user-writable dir
        // prepended to PATH.
        let lower = text.lowercased()
        if lower.contains("export path=/tmp") || lower.contains("export path=$home/.local/bin:") == false
           && lower.contains("export path=") {
            // Not all `export PATH=` is malicious, but a newly added one
            // that *prepends* an attacker-writable dir is. Without a diff
            // we can't tell for sure — default to HIGH so the user inspects.
            let currentLines = text.split(separator: "\n")
                .filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }
                .count
            if currentLines > priorLineCount {
                return .high
            }
        }
        return .medium
    }

    private func scanLaunchAgentsDir(_ dir: String, firstRun: Bool) {
        guard FileManager.default.fileExists(atPath: dir) else { return }
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }

        var currentPlists = Set<String>()
        for entry in entries where entry.hasSuffix(".plist") {
            let full = (dir as NSString).appendingPathComponent(entry)
            // Skip our own plist — SelfProtection owns its restoration.
            if full == ownPlistPath { continue }
            currentPlists.insert(full)

            if firstRun {
                if let data = FileManager.default.contents(atPath: full) {
                    fileHashes[full] = sha256hex(data)
                }
                continue
            }

            if !knownPlists.contains(full) {
                // New plist. CRITICAL — persistence install.
                emit(
                    type: "NEW_LAUNCH_AGENT",
                    severity: .critical,
                    filePath: full,
                    message: """
                    \u{1F6A8} New LaunchAgent plist: \(entry)
                    Location: \(full)
                    LaunchAgent plists run on every login. Inspect before signing off.

                    Check: defaults read "\(full)"
                    Remove (if unexpected):
                      launchctl bootout gui/$(id -u) "\(full)" && rm "\(full)"
                    """
                )
                if let data = FileManager.default.contents(atPath: full) {
                    fileHashes[full] = sha256hex(data)
                }
            } else if let data = FileManager.default.contents(atPath: full) {
                // Existing plist — hash check.
                let newHash = sha256hex(data)
                if let prior = fileHashes[full], prior != newHash {
                    emit(
                        type: "LAUNCH_AGENT_MODIFIED",
                        severity: .high,
                        filePath: full,
                        message: "\u{1F6A8} LaunchAgent plist modified: \(entry). Inspect for injected `ProgramArguments`."
                    )
                }
                fileHashes[full] = newHash
            }
        }
        knownPlists = currentPlists
    }

    /// Generic "new file" watcher for extension dirs + script libraries.
    /// We only hash the top level — extension directories have their own
    /// sub-package managers that run installers, and a new extension will
    /// appear as a new directory, not a new file.
    private func scanDirectoryForNewFiles(_ dir: String, category: String, severity: SeverityLevel, firstRun: Bool) {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return }
        for entry in entries {
            if entry.hasPrefix(".") { continue }
            let full = (dir as NSString).appendingPathComponent(entry)
            let key = "\(category):\(full)"
            if firstRun {
                fileHashes[key] = "present"
                continue
            }
            if fileHashes[key] == nil {
                emit(
                    type: "PERSISTENCE_NEW_ITEM",
                    severity: severity,
                    filePath: full,
                    message: "\u{1F50C} New \(category.replacingOccurrences(of: "_", with: " ")) added: \(entry)\nPath: \(full)\nInspect before trusting."
                )
                fileHashes[key] = "present"
            }
        }
    }

    private func scanGitconfig(_ path: String, firstRun: Bool) {
        guard let data = FileManager.default.contents(atPath: path),
              let text = String(data: data, encoding: .utf8) else { return }
        let hash = sha256hex(data)

        if firstRun {
            fileHashes[path] = hash
            return
        }

        if fileHashes[path] == hash { return }

        // Check for suspicious content that specifically enables code exec.
        let suspicious = text.contains("hooksPath") || text.contains("hookspath")
        let severity: SeverityLevel = suspicious ? .high : .medium
        var msg = "\u{1F50C} Global .gitconfig modified: \(path)"
        if suspicious {
            msg += "\n\u{26A0}\u{FE0F} Contains `hooksPath` — any `git` command now runs scripts from that directory. Confirm this was you."
        }
        emit(type: "GITCONFIG_MODIFIED", severity: severity, filePath: path, message: msg)
        fileHashes[path] = hash
    }

    // MARK: - Watching

    private func watchFile(_ path: String) {
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else { return }
        fileDescriptors.append(fd)
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete, .extend, .attrib],
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            self?.onFileEvent(path)
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        sources.append(source)
    }

    private func watchDirectory(_ dir: String) {
        guard FileManager.default.fileExists(atPath: dir) else { return }
        let fd = open(dir, O_EVTONLY)
        guard fd >= 0 else { return }
        fileDescriptors.append(fd)
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete, .extend],
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            self?.onFileEvent(dir)
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        sources.append(source)
    }

    private func onFileEvent(_ path: String) {
        let work = DispatchWorkItem { [weak self] in
            self?.rescan(path)
        }
        stateLock.lock()
        debounceTimers[path]?.cancel()
        debounceTimers[path] = work
        stateLock.unlock()
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + .milliseconds(500),
            execute: work
        )
    }

    private func rescan(_ path: String) {
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDir)
        if !exists {
            // File/dir removed — detect-only, drop from baseline silently.
            fileHashes.removeValue(forKey: path)
            saveBaseline()
            return
        }
        // Dispatch based on what kind of path this is.
        let home = NSHomeDirectory()
        if path == "\(home)/Library/LaunchAgents" {
            scanLaunchAgentsDir(path, firstRun: false)
        } else if path == "\(home)/.gitconfig" {
            scanGitconfig(path, firstRun: false)
        } else if path.hasSuffix("/hooks") {
            scanDirectoryForNewFiles(path, category: "git_hook", severity: .high, firstRun: false)
        } else if path.contains("/extensions") {
            scanDirectoryForNewFiles(path, category: "editor_extension", severity: .medium, firstRun: false)
        } else if path.contains("/Script Libraries") {
            scanDirectoryForNewFiles(path, category: "script_library", severity: .medium, firstRun: false)
        } else if !isDir.boolValue {
            // Likely an rc file.
            let basename = (path as NSString).lastPathComponent
            if basename.hasPrefix(".") && (basename.contains("rc") || basename.contains("profile") || basename == ".zshenv") {
                scanRcFile(path, firstRun: false)
            }
        }
        saveBaseline()
    }

    // MARK: - Alert

    private func emit(type: String, severity: SeverityLevel, filePath: String, message: String) {
        let alert = SecurityAlert(
            type: type,
            severity: severity,
            message: message,
            filePath: filePath
        )
        logger.alert(alert)
        onAlert?(alert)
    }

    // MARK: - Persistence

    private func loadBaseline() -> Baseline {
        guard let data = FileManager.default.contents(atPath: baselineFile),
              let baseline = try? JSONDecoder().decode(Baseline.self, from: data) else {
            return Baseline(fileHashes: [:], rcLineCounts: [:], knownPlists: [], lastScan: "")
        }
        return baseline
    }

    private func saveBaseline() {
        let baseline = Baseline(
            fileHashes: fileHashes,
            rcLineCounts: rcLineCounts,
            knownPlists: Array(knownPlists),
            lastScan: ISO8601DateFormatter().string(from: Date())
        )
        guard let data = try? JSONEncoder().encode(baseline) else { return }
        let tmp = baselineFile + ".tmp"
        do {
            try data.write(to: URL(fileURLWithPath: tmp), options: .atomic)
            _ = try? FileManager.default.removeItem(atPath: baselineFile)
            try FileManager.default.moveItem(atPath: tmp, toPath: baselineFile)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: baselineFile)
        } catch {
            logger.warn("Failed to persist persistence-path baseline: \(error.localizedDescription)")
        }
    }

    // MARK: - Helpers

    private func expandHome(_ path: String) -> String {
        if path.hasPrefix("~/") {
            return (NSHomeDirectory() as NSString).appendingPathComponent(String(path.dropFirst(2)))
        }
        return path
    }

    private func sha256hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
