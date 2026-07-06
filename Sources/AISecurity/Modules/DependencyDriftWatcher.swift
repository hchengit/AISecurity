import Foundation
import CryptoKit

/// Dependency-manifest drift watcher — detects new/changed pinned dependencies
/// in user-declared project roots and cross-checks new pins against OSV.
///
/// Works hand-in-hand with `PythonPthWatcher`:
///   - `.pth` watcher catches post-install autoruns in site-packages.
///   - This watcher catches the precondition — the manifest/lockfile that
///     pulled the package in — so suspicious installs surface earlier and
///     with more context (which file, which package, which version, is it
///     a known-bad pin?).
///
/// # Supported manifests (initial set)
///
///   - Python:   `requirements.txt`, `pyproject.toml` ([project].dependencies), `uv.lock`
///   - Node:     `package.json`, `package-lock.json` (name+version pairs)
///   - Rust:     `Cargo.toml` ([dependencies], [dev-dependencies]), `Cargo.lock`
///
/// Other ecosystems (Go, Ruby, PHP, Java) are watched for *hash drift* even
/// if we can't parse pins — the raw lockfile hash change still alerts.
final class DependencyDriftWatcher: @unchecked Sendable {

    // MARK: - Config

    struct Config: Sendable {
        let enabled: Bool
        /// Roots to walk for manifests (e.g. ["~/code", "~/projects"]).
        let projectRoots: [String]
        /// How deep to walk within each root. Manifests usually live at
        /// depth 0-1 (root or one subdir per project).
        let maxDepth: Int
    }

    /// Every manifest name we know how to parse OR just hash. Sorted by
    /// ecosystem for readability.
    private static let knownManifests: Set<String> = [
        // Python
        "requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock",
        // Node
        "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
        // Rust
        "Cargo.toml", "Cargo.lock",
        // Go
        "go.mod", "go.sum",
        // Ruby
        "Gemfile", "Gemfile.lock",
        // PHP
        "composer.json", "composer.lock",
    ]

    /// Directories we refuse to descend into. Same shape as model_verifier's
    /// skip list — keeps the walk cheap and avoids macOS-specific noise.
    private static let skipBasenames: Set<String> = [
        ".Trash", "node_modules", ".git", "target", "build", ".build",
        ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
        "Library", "Applications", "Caches",
    ]

    // MARK: - Types

    /// JSON-persisted baseline.
    struct Baseline: Codable {
        let manifestHashes: [String: String]           // abs path → sha256
        let manifestPackages: [String: [PinnedDep]]    // abs path → parsed deps
        let lastScan: String
    }

    struct PinnedDep: Codable, Hashable, Sendable {
        let ecosystem: String
        let name: String
        let version: String
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

    private var manifestHashes: [String: String] = [:]
    private var manifestPackages: [String: [PinnedDep]] = [:]
    private(set) var watchedManifests: [String] = []
    private(set) var isRunning = false

    var onAlert: AlertHandler?

    // MARK: - Init

    init(logger: SecurityLogger, securityDir: String, cfg: Config) {
        self.logger = logger
        self.securityDir = securityDir
        self.baselineFile = (securityDir as NSString).appendingPathComponent("dependency-baseline.json")
        self.cfg = cfg
    }

    // MARK: - Lifecycle

    func start() {
        guard !isRunning else { return }
        guard cfg.enabled else {
            logger.info("\u{1F4E6} Dependency Drift Watcher: disabled in config")
            return
        }
        guard !cfg.projectRoots.isEmpty else {
            logger.info("\u{1F4E6} Dependency Drift Watcher: no project_roots configured — skip")
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
        logger.info("\u{1F4E6} Dependency Drift Watcher stopped")
    }

    // MARK: - Discovery

    private func discoverAndWatch() {
        let manifests = discoverManifests()
        if manifests.isEmpty {
            logger.info("\u{1F4E6} Dependency Drift Watcher: no manifests found under configured roots")
            return
        }

        let prior = loadBaseline()
        manifestHashes = prior.manifestHashes
        manifestPackages = prior.manifestPackages

        // On first run prime the baseline silently. On subsequent runs diff
        // the current state against what we saved.
        var newHashes: [String: String] = [:]
        var newPackages: [String: [PinnedDep]] = [:]
        for m in manifests {
            guard let (hash, deps) = readAndParse(m) else { continue }
            newHashes[m] = hash
            newPackages[m] = deps
        }

        if prior.manifestHashes.isEmpty {
            logger.info("\u{1F4E6} Dependency Drift Watcher: baseline primed — \(manifests.count) manifest file(s)")
        } else {
            diffAndAlert(currentHashes: newHashes, currentPackages: newPackages,
                         priorHashes: prior.manifestHashes, priorPackages: prior.manifestPackages)
        }

        manifestHashes = newHashes
        manifestPackages = newPackages
        saveBaseline()

        watchedManifests = manifests
        for m in manifests {
            watchFile(m)
        }

        logger.info("\u{1F4E6} Dependency Drift Watcher started — \(manifests.count) manifest(s)")
    }

    /// Walk each configured root for recognized manifest files.
    private func discoverManifests() -> [String] {
        var found = Set<String>()
        for rawRoot in cfg.projectRoots {
            let root = expandHome(rawRoot)
            collectManifests(under: root, depth: 0, into: &found)
        }
        return found.sorted()
    }

    private func collectManifests(under path: String, depth: Int, into out: inout Set<String>) {
        guard depth <= cfg.maxDepth else { return }
        let basename = (path as NSString).lastPathComponent
        if Self.skipBasenames.contains(basename) { return }
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: path) else { return }

        for entry in entries {
            if Self.knownManifests.contains(entry) {
                let full = (path as NSString).appendingPathComponent(entry)
                if case .ok = PathGuard.validate(full) {
                    out.insert(full)
                }
            }
        }
        // Recurse into subdirs (bounded).
        for entry in entries {
            if entry.hasPrefix(".") { continue }
            let child = (path as NSString).appendingPathComponent(entry)
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: child, isDirectory: &isDir),
                  isDir.boolValue else { continue }
            collectManifests(under: child, depth: depth + 1, into: &out)
        }
    }

    // MARK: - Parsing

    /// Read the manifest, compute its hash, and (for the ecosystems we parse)
    /// extract pinned dependencies. For the rest we still return the hash so
    /// drift alerts still fire.
    private func readAndParse(_ path: String) -> (hash: String, deps: [PinnedDep])? {
        guard let data = FileManager.default.contents(atPath: path),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }
        let hash = sha256hex(data)
        let filename = (path as NSString).lastPathComponent
        let deps = parseDeps(filename: filename, content: text)
        return (hash, deps)
    }

    private func parseDeps(filename: String, content: String) -> [PinnedDep] {
        switch filename {
        case "requirements.txt":
            return parseRequirementsTxt(content)
        case "pyproject.toml":
            return parsePyproject(content)
        case "package.json":
            return parsePackageJson(content)
        case "Cargo.toml":
            return parseCargoToml(content)
        default:
            // package-lock.json / Cargo.lock / uv.lock / poetry.lock — we hash
            // but don't pin-extract yet. Drift still detected via hash change.
            return []
        }
    }

    /// `name==1.2.3` or `name>=1.0,<2.0` — we only extract exact `==` pins.
    /// Non-exact specifiers are ignored (ambiguous vulnerability range).
    private func parseRequirementsTxt(_ content: String) -> [PinnedDep] {
        var out: [PinnedDep] = []
        for rawLine in content.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("-") { continue }
            // Strip inline comment.
            let noComment = line.split(separator: "#", maxSplits: 1).first.map(String.init) ?? line
            let parts = noComment.split(separator: "=", maxSplits: 2, omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            // Only match `name==version` (three parts: "name", "", "version")
            if parts.count == 3 && parts[1].isEmpty && !parts[0].isEmpty && !parts[2].isEmpty {
                let name = normalizePackageName(parts[0])
                out.append(PinnedDep(ecosystem: "PyPI", name: name, version: parts[2]))
            }
        }
        return out
    }

    /// Minimal pyproject.toml parser — pulls `dependencies = [...]` and
    /// `[project] requires = [...]`. Full TOML parsing is overkill here since
    /// we only care about the pinned strings.
    private func parsePyproject(_ content: String) -> [PinnedDep] {
        var out: [PinnedDep] = []
        // Find all `"name==version"` tokens — this is a superset of what
        // both PEP 621 and Poetry forms produce inside dependency lists.
        let pattern = #"\"([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+]+)\""#
        guard let rx = try? NSRegularExpression(pattern: pattern) else { return out }
        let ns = content as NSString
        rx.enumerateMatches(in: content, range: NSRange(location: 0, length: ns.length)) { match, _, _ in
            guard let m = match, m.numberOfRanges == 3 else { return }
            let name = normalizePackageName(ns.substring(with: m.range(at: 1)))
            let ver = ns.substring(with: m.range(at: 2))
            out.append(PinnedDep(ecosystem: "PyPI", name: name, version: ver))
        }
        return out
    }

    private func parsePackageJson(_ content: String) -> [PinnedDep] {
        guard let data = content.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }
        var out: [PinnedDep] = []
        for key in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
            guard let deps = json[key] as? [String: Any] else { continue }
            for (name, rawVer) in deps {
                guard let verStr = rawVer as? String else { continue }
                // Strip `^` / `~` / `>=` / `>` / `=` prefixes — OSV wants a
                // concrete version. If the pin is a range we can't query
                // meaningfully so we skip it.
                let cleaned = verStr.trimmingCharacters(in: .whitespaces)
                if cleaned.hasPrefix("^") || cleaned.hasPrefix("~") || cleaned.hasPrefix(">=")
                    || cleaned.hasPrefix(">") || cleaned.hasPrefix("<") {
                    continue
                }
                let finalVer = cleaned.hasPrefix("=") ? String(cleaned.dropFirst()) : cleaned
                if !finalVer.isEmpty && !finalVer.contains("*") {
                    out.append(PinnedDep(ecosystem: "npm", name: name.lowercased(), version: finalVer))
                }
            }
        }
        return out
    }

    /// Very light Cargo.toml parser — looks for `name = "X.Y.Z"` lines inside
    /// `[dependencies]` and `[dev-dependencies]` sections. Table-form deps
    /// (`foo = { version = "X.Y.Z", features = [...] }`) also handled.
    private func parseCargoToml(_ content: String) -> [PinnedDep] {
        var out: [PinnedDep] = []
        var inDepsSection = false
        for rawLine in content.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") {
                let section = line.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                inDepsSection = section == "dependencies"
                    || section == "dev-dependencies"
                    || section == "build-dependencies"
                continue
            }
            guard inDepsSection else { continue }
            // Match `name = "1.2.3"` OR `name = { version = "1.2.3", ... }`
            guard let eqIdx = line.firstIndex(of: "=") else { continue }
            let rawName = line[..<eqIdx].trimmingCharacters(in: .whitespaces)
            let rest = line[line.index(after: eqIdx)...].trimmingCharacters(in: .whitespaces)

            let version: String?
            if rest.hasPrefix("\"") {
                // Simple form: `name = "X.Y.Z"`
                version = extractFirstQuotedValue(String(rest))
            } else if rest.hasPrefix("{") {
                // Table form — look for `version = "..."`
                if let range = rest.range(of: #"version\s*=\s*\"([^\"]+)\""#, options: .regularExpression) {
                    version = extractFirstQuotedValue(String(rest[range]))
                } else {
                    version = nil
                }
            } else {
                version = nil
            }
            if let v = version, !v.isEmpty, !v.contains("*") {
                // Strip `^` / `~` — Cargo uses caret by default.
                var v = v
                if v.hasPrefix("^") || v.hasPrefix("~") || v.hasPrefix("=") {
                    v.removeFirst()
                }
                out.append(PinnedDep(ecosystem: "crates.io", name: rawName.lowercased(), version: v))
            }
        }
        return out
    }

    private func extractFirstQuotedValue(_ s: String) -> String? {
        guard let start = s.firstIndex(of: "\"") else { return nil }
        let afterStart = s.index(after: start)
        guard let end = s[afterStart...].firstIndex(of: "\"") else { return nil }
        return String(s[afterStart..<end])
    }

    /// PyPI normalizes names to lowercase with `-` instead of `_` / `.`.
    private func normalizePackageName(_ raw: String) -> String {
        raw.lowercased()
            .replacingOccurrences(of: "_", with: "-")
            .replacingOccurrences(of: ".", with: "-")
    }

    // MARK: - Diff + alert

    private func diffAndAlert(
        currentHashes: [String: String],
        currentPackages: [String: [PinnedDep]],
        priorHashes: [String: String],
        priorPackages: [String: [PinnedDep]]
    ) {
        for (path, curHash) in currentHashes {
            let prior = priorHashes[path]
            if prior == nil {
                // Brand new manifest — alert about every pinned dep being
                // "new", and cross-check OSV.
                let deps = currentPackages[path] ?? []
                handleAddedDeps(in: path, added: Set(deps), severityForAdds: .medium)
                continue
            }
            guard curHash != prior else { continue }

            let before = Set(priorPackages[path] ?? [])
            let after = Set(currentPackages[path] ?? [])
            let added = after.subtracting(before)
            let removed = before.subtracting(after)

            // If we have any parsed deps, prefer fine-grained diff alerts.
            if !added.isEmpty || !removed.isEmpty {
                handleAddedDeps(in: path, added: added, severityForAdds: .medium)
                if !removed.isEmpty {
                    emit(
                        type: "DEPENDENCY_REMOVED",
                        severity: .low,
                        filePath: path,
                        message: "\u{1F4E6} Dependencies removed from \((path as NSString).lastPathComponent): \(removed.map { "\($0.name)@\($0.version)" }.sorted().joined(separator: ", "))"
                    )
                }
            } else {
                // Parsed-less manifest (lockfile we don't parse) — just note
                // the hash change. The plan calls this HIGH for pinned-version
                // lockfile drift.
                emit(
                    type: "DEPENDENCY_LOCKFILE_DRIFT",
                    severity: .high,
                    filePath: path,
                    message: "\u{1F4E6} Lockfile changed: \((path as NSString).lastPathComponent) — inspect `git diff` to confirm it matches an intended install."
                )
            }
        }
    }

    /// Alert on each new pinned dep; elevate to CRITICAL if OSV flags it.
    /// Does one batched OSV call for the whole set of adds.
    private func handleAddedDeps(in manifestPath: String, added: Set<PinnedDep>, severityForAdds: SeverityLevel) {
        guard !added.isEmpty else { return }
        let list = Array(added)
        let queries = list.map { SecurityCoreBridge.PackageQuery(ecosystem: $0.ecosystem, name: $0.name, version: $0.version) }
        let results = SecurityCoreBridge.checkPackageBatch(queries)

        for (i, dep) in list.enumerated() {
            let osv = i < results.count ? results[i] : nil
            let isVuln = osv?.vulnerable == true
            let severity: SeverityLevel = isVuln ? .critical : severityForAdds
            var msg = "\u{1F4E6} Dependency added in \((manifestPath as NSString).lastPathComponent): \(dep.name)@\(dep.version) (\(dep.ecosystem))"
            if isVuln, let cve = osv?.cve {
                msg += "\n\u{1F6A8} OSV flagged this pin as vulnerable: \(cve). Do NOT run this env — rotate any reachable credentials and pin to a patched version."
            }
            emit(type: isVuln ? "DEPENDENCY_KNOWN_VULNERABLE" : "DEPENDENCY_ADDED",
                 severity: severity,
                 filePath: manifestPath,
                 message: msg)
        }
    }

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

    // MARK: - Watching

    private func watchFile(_ path: String) {
        let fd = open(path, O_EVTONLY)
        guard fd >= 0 else { return }
        fileDescriptors.append(fd)

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete, .extend],
            queue: DispatchQueue.global(qos: .utility)
        )
        source.setEventHandler { [weak self] in
            self?.onFileEvent(path)
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
        // Lockfiles (pnpm, yarn) can write in bursts — 750 ms debounce
        // balances responsiveness with noise reduction.
        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + .milliseconds(750),
            execute: work
        )
    }

    private func rescan(_ path: String) {
        guard let (curHash, curDeps) = readAndParse(path) else {
            // File disappeared — drop it from baseline.
            manifestHashes.removeValue(forKey: path)
            manifestPackages.removeValue(forKey: path)
            saveBaseline()
            return
        }
        let priorHash = manifestHashes[path]
        let priorDeps = manifestPackages[path] ?? []
        let priorHashes: [String: String] = priorHash.map { [path: $0] } ?? [:]
        let priorPkgs: [String: [PinnedDep]] = [path: priorDeps]
        diffAndAlert(
            currentHashes: [path: curHash],
            currentPackages: [path: curDeps],
            priorHashes: priorHashes,
            priorPackages: priorPkgs
        )
        manifestHashes[path] = curHash
        manifestPackages[path] = curDeps
        saveBaseline()
    }

    // MARK: - Persistence

    private func loadBaseline() -> Baseline {
        guard let data = FileManager.default.contents(atPath: baselineFile),
              let baseline = try? JSONDecoder().decode(Baseline.self, from: data) else {
            return Baseline(manifestHashes: [:], manifestPackages: [:], lastScan: "")
        }
        return baseline
    }

    private func saveBaseline() {
        let baseline = Baseline(
            manifestHashes: manifestHashes,
            manifestPackages: manifestPackages,
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
            logger.warn("Failed to persist dependency baseline: \(error.localizedDescription)")
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
