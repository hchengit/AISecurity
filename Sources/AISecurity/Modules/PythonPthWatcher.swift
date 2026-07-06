import Foundation
import CryptoKit

/// Python `.pth` autorun watchdog — defends against the LiteLLM-style
/// supply-chain attack (2026) and its predecessors (ctx 2022, jeIlyfish 2019).
///
/// # Why
///
/// Every Python interpreter walks its `site-packages` directories on startup
/// and, for every `*.pth` file it finds, executes any line starting with
/// `import ` or `exec ` (see `site.py`). This runs regardless of whether
/// the owning package was imported. A malicious wheel published to PyPI can
/// drop one line into a `.pth` and hijack every subsequent `python` call on
/// the machine — including `pip`, `ansible`, `jupyter`, agent wrappers.
///
/// # What this does
///
/// 1. Discover every `site-packages` directory under `$HOME` (and a few
///    system paths) at startup, plus any `pyvenv.cfg`-marked venv down to
///    depth 4 — reuses the same skip-list pattern as ModelDirectoryWatcher.
/// 2. Baseline-hash every pre-existing `.pth` file so we don't alert on
///    setuptools-generated entry points that are legitimate autorun.
///   The baseline is persisted; subsequent startups trust it.
/// 3. Watch each `site-packages` directory via DispatchSource.
/// 4. On any write/rename/extend event, diff current `.pth` set against
///    baseline. For **new** or **modified** files, classify each line —
///    if any line is code-bearing (starts with `import`/`exec`, or contains
///    `__import__`, `;`, or `(`) raise a HIGH-severity alert with the
///    offending file and a short excerpt. Path-only lines are normal.
/// 5. Update baseline after the scan — if the user legitimately installed
///    a new package, the alert informs them and the new hash becomes the
///    trusted baseline for future diffs.
final class PythonPthWatcher: @unchecked Sendable {

    // MARK: - Config

    /// Fixed system-level candidate roots. User-scope discovery walks $HOME.
    private static let systemRoots: [String] = [
        "/usr/local/lib",
        "/opt/homebrew/lib",
        "/Library/Frameworks/Python.framework/Versions",
    ]

    /// Skip directories during discovery — same spirit as `should_track_path`
    /// in `model_verifier.rs`. Keeps the scan bounded and avoids hammering
    /// macOS-specific caches.
    private static let skipBasenames: Set<String> = [
        ".Trash", "Library", "Applications", "node_modules", ".git",
        ".npm", ".cargo", "target", "build", ".build", "Caches",
        "Logs", "Mail", "Photos", "Music", "Movies",
    ]

    /// Maximum recursion depth when hunting for site-packages under $HOME.
    private static let maxDepth = 4

    /// Per-event debounce — Python venv creation writes many `.pth` files
    /// in rapid succession.
    private static let debounceMs = 500

    // MARK: - Types

    /// JSON-serialized baseline entry.
    struct Baseline: Codable {
        let sitePackages: [String]
        let pthHashes: [String: String]    // absolute path → SHA-256 hex
        let lastScan: String
    }

    typealias AlertHandler = @Sendable (SecurityAlert) -> Void

    // MARK: - State

    private let logger: SecurityLogger
    private let securityDir: String
    private let baselineFile: String
    private let sitePackagesFile: String
    private var sources: [DispatchSourceFileSystemObject] = []
    private var fileDescriptors: [Int32] = []
    private var debounceTimers: [String: DispatchWorkItem] = [:]
    private let stateLock = NSLock()

    /// Map of `.pth` absolute path → SHA-256 hex. Mutated on every scan.
    private var pthHashes: [String: String] = [:]
    /// Directories currently under watch (recorded for diagnostics).
    private(set) var watchedSitePackages: [String] = []
    private(set) var isRunning = false

    var onAlert: AlertHandler?

    // MARK: - Init

    init(logger: SecurityLogger, securityDir: String) {
        self.logger = logger
        self.securityDir = securityDir
        self.baselineFile = (securityDir as NSString).appendingPathComponent("pth-baseline.json")
        self.sitePackagesFile = (securityDir as NSString).appendingPathComponent("python-sitepackages.json")
    }

    // MARK: - Lifecycle

    func start() {
        guard !isRunning else { return }
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
        logger.info("\u{1F40D} Python .pth Watcher stopped")
    }

    // MARK: - Discovery

    private func discoverAndWatch() {
        let sitePackages = discoverSitePackages()
        if sitePackages.isEmpty {
            logger.info("\u{1F40D} Python .pth Watcher: no site-packages found")
            return
        }

        // Load prior baseline (if any) — this is what tells us which .pth files
        // we've already vetted. Without it, every first start would alert on
        // every pre-existing setuptools entry point.
        let prior = loadBaseline()
        pthHashes = prior.pthHashes

        // Hash the current set of .pth files. Anything *new* or *changed*
        // relative to the persisted baseline is reported.
        let currentScan = scanAllPthFiles(in: sitePackages)
        if prior.pthHashes.isEmpty {
            // First run — silently trust whatever is there. Logging the count
            // makes it obvious in the log that we primed the baseline without
            // alerting.
            let codeBearing = currentScan.filter { _, info in info.hasCode }
            logger.info("\u{1F40D} Python .pth Watcher: baseline primed — \(currentScan.count) .pth files (\(codeBearing.count) with code, accepted as trusted)")
        } else {
            evaluateChanges(current: currentScan, priorHashes: prior.pthHashes)
        }

        // Persist the fresh baseline and the discovered site-packages list.
        pthHashes = currentScan.mapValues { $0.hash }
        saveBaseline(sitePackages: sitePackages)
        saveSitePackages(sitePackages)

        // Start watching each site-packages dir.
        watchedSitePackages = sitePackages
        for dir in sitePackages {
            watchDirectory(dir)
        }

        logger.info("\u{1F40D} Python .pth Watcher started — \(sitePackages.count) site-packages, \(currentScan.count) .pth files tracked")
    }

    /// Collect every `site-packages` directory a Python process on this
    /// machine could load. Deduplicated, sorted.
    private func discoverSitePackages() -> [String] {
        var dirs = Set<String>()
        let home = NSHomeDirectory()

        // Well-known user-scope roots. These are the spots where Python is
        // installed most often on macOS dev machines.
        let userRoots = [
            "\(home)/.pyenv/versions",
            "\(home)/miniconda3/envs",
            "\(home)/miniforge3/envs",
            "\(home)/anaconda3/envs",
            "\(home)/.conda/envs",
            "\(home)/Library/Python",
        ]

        for root in userRoots {
            collectSitePackages(under: root, depth: 0, into: &dirs)
        }

        // System-scope roots from outside $HOME.
        for root in Self.systemRoots {
            collectSitePackages(under: root, depth: 0, into: &dirs)
        }

        // Walk $HOME generally — catches project-local venvs like `~/code/foo/.venv`.
        // Bounded to `maxDepth` so the scan stays cheap.
        collectSitePackages(under: home, depth: 0, into: &dirs)

        return dirs.sorted()
    }

    /// Recursively scan a directory for `site-packages` folders. Also follows
    /// `pyvenv.cfg`-marked virtualenvs, which live at
    /// `<venv>/lib/python*/site-packages`.
    private func collectSitePackages(under path: String, depth: Int, into out: inout Set<String>) {
        guard depth <= Self.maxDepth else { return }
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }

        let basename = (path as NSString).lastPathComponent
        if Self.skipBasenames.contains(basename) { return }

        // Direct hit: we're standing inside a `site-packages`.
        if basename == "site-packages" {
            out.insert(path)
            return
        }

        // venv marker: `pyvenv.cfg` means the parent is a virtualenv root.
        // Python 3 venvs put the usable site-packages at
        // `<venv>/lib/python<X.Y>/site-packages`.
        if entries.contains("pyvenv.cfg") {
            let libDir = (path as NSString).appendingPathComponent("lib")
            if let versions = try? FileManager.default.contentsOfDirectory(atPath: libDir) {
                for version in versions where version.hasPrefix("python") {
                    let sp = (libDir as NSString)
                        .appendingPathComponent(version) + "/site-packages"
                    if FileManager.default.fileExists(atPath: sp) {
                        out.insert(sp)
                    }
                }
            }
            return
        }

        // Recurse into subdirs.
        for entry in entries {
            if entry.hasPrefix(".") && depth > 0 { continue }
            let child = (path as NSString).appendingPathComponent(entry)
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: child, isDirectory: &isDir),
                  isDir.boolValue else { continue }
            collectSitePackages(under: child, depth: depth + 1, into: &out)
        }
    }

    // MARK: - Scanning

    /// Information we extract per `.pth` file.
    private struct PthInfo {
        let hash: String
        let hasCode: Bool
        let codeLines: [String]     // up to 5 code-bearing lines (truncated)
    }

    /// Hash and classify every `.pth` file across the given site-packages set.
    private func scanAllPthFiles(in sitePackages: [String]) -> [String: PthInfo] {
        var out: [String: PthInfo] = [:]
        for dir in sitePackages {
            for path in findPthFiles(in: dir) {
                if let info = analyzePth(at: path) {
                    out[path] = info
                }
            }
        }
        return out
    }

    /// Non-recursive listing: Python only reads `.pth` at the top of
    /// `site-packages`, not inside packages.
    private func findPthFiles(in sitePackages: String) -> [String] {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: sitePackages) else {
            return []
        }
        return entries
            .filter { $0.hasSuffix(".pth") && !$0.hasPrefix(".") }
            .map { (sitePackages as NSString).appendingPathComponent($0) }
    }

    /// Read, hash, and classify a single `.pth`. Returns nil if unreadable
    /// or if PathGuard rejects the path (e.g. a symlink — someone dropped
    /// a link under site-packages pointing at an attacker-controlled file).
    private func analyzePth(at path: String) -> PthInfo? {
        switch PathGuard.validate(path) {
        case .ok:
            break
        case .rejectedSymlink, .rejectedSensitive, .rejectedMissing:
            return nil
        }

        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        let hash = sha256hex(data)

        guard let text = String(data: data, encoding: .utf8) else {
            // Non-UTF8 .pth is suspicious on its own — flag as code-bearing
            // so the user sees it. A legitimate .pth is always ASCII.
            return PthInfo(hash: hash, hasCode: true, codeLines: ["<non-UTF-8 content>"])
        }

        var codeLines: [String] = []
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if isCodeBearing(line) {
                if codeLines.count < 5 {
                    codeLines.append(String(line.prefix(200)))
                }
            }
        }

        return PthInfo(hash: hash, hasCode: !codeLines.isEmpty, codeLines: codeLines)
    }

    /// A `.pth` line is code-bearing iff Python's `site.py` would execute it.
    /// Python's rule: lines starting with `import ` or `exec ` are exec'd;
    /// everything else is treated as a path. We extend the match slightly to
    /// flag obfuscated variants (`__import__`, semicolons, function calls).
    private func isCodeBearing(_ line: String) -> Bool {
        let lower = line.lowercased()
        if lower.hasPrefix("import ") || lower.hasPrefix("import\t") { return true }
        if lower.hasPrefix("exec ") || lower.hasPrefix("exec\t") { return true }
        if lower.hasPrefix("exec(") { return true }
        if lower.contains("__import__") { return true }
        // Path-only lines never contain these.
        if line.contains(";") { return true }
        if line.contains("(") && line.contains(")") { return true }
        return false
    }

    // MARK: - Diff + alert

    private func evaluateChanges(current: [String: PthInfo], priorHashes: [String: String]) {
        for (path, info) in current {
            let prior = priorHashes[path]
            let isNew = (prior == nil)
            let isChanged = (prior != nil && prior != info.hash)
            guard isNew || isChanged else { continue }

            // Only alert if the file actually executes code. A new path-only
            // .pth (setuptools-generated after `pip install pkg`) is normal
            // and not worth noise.
            guard info.hasCode else { continue }

            let verb = isNew ? "new" : "modified"
            let excerpt = info.codeLines.joined(separator: " | ")
            let message = """
            \u{1F6A8} Python .pth autorun \(verb): \((path as NSString).lastPathComponent)
            Location: \(path)
            Code-bearing lines: \(info.codeLines.count)
            Excerpt: \(excerpt)

            Python executes `.pth` files automatically on every interpreter start.
            Any code-bearing line in site-packages runs without being imported.

            \u{2705} If you just installed a legitimate package, this is expected
               and the new content has been added to the trusted baseline.

            \u{26A0}\u{FE0F} If you did NOT install anything:
               1. Do NOT run python — the next invocation will execute this code.
               2. Inspect the file: cat "\(path)"
               3. Delete it and uninstall the package that dropped it.
               4. Consider rotating credentials reachable from that Python env.
            """
            let alert = SecurityAlert(
                type: "PYTHON_PTH_CODE_EXECUTION",
                severity: .high,
                message: message,
                filePath: path
            )
            logger.alert(alert)
            onAlert?(alert)
        }

        // Files that vanished from baseline are fine — user uninstalled
        // the package. No alert.
    }

    // MARK: - Watching

    private func watchDirectory(_ dir: String) {
        let fd = open(dir, O_EVTONLY)
        guard fd >= 0 else {
            logger.warn("Cannot watch site-packages \(dir): open failed")
            return
        }
        fileDescriptors.append(fd)

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete, .extend],
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            self?.onDirectoryEvent(dir)
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        sources.append(source)
    }

    private func onDirectoryEvent(_ dir: String) {
        let work = DispatchWorkItem { [weak self] in
            self?.rescan(dir)
        }
        stateLock.lock()
        debounceTimers[dir]?.cancel()
        debounceTimers[dir] = work
        stateLock.unlock()
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + .milliseconds(Self.debounceMs),
            execute: work
        )
    }

    /// Re-scan one site-packages directory and emit alerts on any new/changed
    /// code-bearing `.pth`. Updates the in-memory baseline atomically.
    private func rescan(_ sitePackages: String) {
        // Rescan just the files currently present. The baseline entries from
        // other dirs stay put.
        var updated = pthHashes
        var currentInfos: [String: PthInfo] = [:]
        for path in findPthFiles(in: sitePackages) {
            if let info = analyzePth(at: path) {
                currentInfos[path] = info
            }
        }
        let priorSubset = pthHashes.filter { key, _ in key.hasPrefix(sitePackages + "/") }

        evaluateChanges(current: currentInfos, priorHashes: priorSubset)

        // Drop any prior-subset keys that vanished, then merge in current.
        for key in priorSubset.keys { updated.removeValue(forKey: key) }
        for (k, info) in currentInfos { updated[k] = info.hash }

        pthHashes = updated
        saveBaseline(sitePackages: watchedSitePackages)
    }

    // MARK: - Baseline persistence

    private func loadBaseline() -> Baseline {
        guard let data = FileManager.default.contents(atPath: baselineFile),
              let baseline = try? JSONDecoder().decode(Baseline.self, from: data) else {
            return Baseline(sitePackages: [], pthHashes: [:], lastScan: "")
        }
        return baseline
    }

    private func saveBaseline(sitePackages: [String]) {
        let baseline = Baseline(
            sitePackages: sitePackages,
            pthHashes: pthHashes,
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
            logger.warn("Failed to persist .pth baseline: \(error.localizedDescription)")
        }
    }

    private func saveSitePackages(_ dirs: [String]) {
        let payload: [String: Any] = [
            "sitePackages": dirs,
            "lastScan": ISO8601DateFormatter().string(from: Date()),
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted]) else { return }
        try? data.write(to: URL(fileURLWithPath: sitePackagesFile), options: .atomic)
    }

    // MARK: - Helpers

    private func sha256hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
