import Foundation
import Combine

/// Monitors sensitive directories on macOS for unauthorized access and suspicious modifications.
/// Replaces modules/file-watcher.js — uses DispatchSource for native file system events.
final class FileWatcher: @unchecked Sendable {

    // MARK: - Types

    typealias AlertHandler = @Sendable (SecurityAlert) -> Void

    // MARK: - Properties

    private let logger: SecurityLogger
    private let detector: SensitiveDataDetector
    var sanitizer: ExternalFileSanitizer?
    private var sources: [DispatchSourceFileSystemObject] = []
    private var fileDescriptors: [Int32] = []
    private var debounceTimers: [String: DispatchWorkItem] = [:]
    private let timerLock = NSLock()  // protects debounceTimers from concurrent access
    private(set) var isRunning = false
    var onAlert: AlertHandler?

    private let config = SecurityConfig.shared
    private var vaultPaths: Set<String> = []  // cached vault-protected paths
    private var vaultObserver: NSObjectProtocol?
    /// Temporarily suppress vault alerts during our own vault operations.
    var suppressVaultAlerts = false

    /// macOS routine file patterns — silently skip (no log at all)
    private let routinePatterns: [NSRegularExpression] = {
        let pats = [
            // Keychain — all routine operations
            #"/Keychains/"#,              // everything in Keychains dir (db, wal, shm, lock, temp, prl_lock)
            #"\.keychain-db"#,            // keychain DB + journal files anywhere
            #"\.keychain$"#,              // legacy .keychain files

            // Messages — chat DB, framework files, config plists
            #"/Messages/"#,               // everything in Messages dir (chat.db, prewarm, plists, etc.)

            // Notes — routine database changes
            #"NoteStore\.sqlite"#,         // Apple Notes database + journal files

            // Contacts/AddressBook — routine database journal writes
            #"/AddressBook/.*\.(?:db-wal|db-shm|db-lock|abcddb-wal|abcddb-shm)$"#,
            #"AddressBook-v\d+\.abcddb-journal"#,

            // Calendars — routine database journal writes
            #"/Calendars/.*\.(?:db-wal|db-shm|db-lock|sqlite-wal|sqlite-shm)$"#,
            #"/Calendars/Calendar Cache"#,

            // Reminders — routine database journal writes
            #"/Reminders/.*\.(?:db-wal|db-shm|db-lock|sqlite-wal|sqlite-shm)$"#,

            // Safari — all routine operations (bookmarks, history, databases, plists, caches)
            #"/Safari/"#,

            // Spotlight/Siri — segment stores
            #"LiteSegmentStore\.db"#,

            // General macOS noise
            #"\.DS_Store$"#,
            #"\.localized$"#,
            #"COMMIT_EDITMSG$"#,
            #"\.sb-[a-f0-9]+-"#,          // sandbox temp files
        ]
        return pats.compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
    }()

    private let scannableExtensions: Set<String> = [
        ".txt", ".md", ".json", ".js", ".ts", ".py", ".sh", ".bash", ".zsh",
        ".env", ".config", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml",
        ".xml", ".html", ".htm", ".csv", ".log", ".sql", ".pem", ".key",
        ".crt", ".cert", ".asc", ".gpg", ".pub"
    ]

    // MARK: - Init

    init(logger: SecurityLogger) {
        self.logger = logger
        self.detector = SensitiveDataDetector()
    }

    // MARK: - Start / Stop

    func start() {
        guard !isRunning else { return }
        isRunning = true

        // Watch monitored directories
        for dir in config.fileWatcher.monitoredDirectories {
            watchDirectory(dir, type: "MONITORED")
        }

        // Watch protected paths
        for path in SensitiveDataDetector.protectedPaths {
            watchDirectory(path, type: "PROTECTED")
        }

        // Load vault-protected paths and watch their parent directories
        loadVaultPaths()

        // Listen for vault changes (add/remove/toggle) to update watched paths
        vaultObserver = NotificationCenter.default.addObserver(
            forName: .vaultWatchedPathsChanged, object: nil, queue: nil
        ) { [weak self] _ in
            self?.reloadVaultWatches()
        }

        // Listen for suppress/unsuppress during our own vault operations
        NotificationCenter.default.addObserver(
            forName: .vaultOperationStarted, object: nil, queue: nil
        ) { [weak self] _ in
            self?.suppressVaultAlerts = true
        }
        NotificationCenter.default.addObserver(
            forName: .vaultOperationEnded, object: nil, queue: nil
        ) { [weak self] _ in
            // Delay unsuppress to let debounce timers flush
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1.0) {
                self?.suppressVaultAlerts = false
            }
        }

        logger.info("\u{1F4C2} File Watcher started", data: [
            "monitored": "\(config.fileWatcher.monitoredDirectories.count)",
            "protected": "\(SensitiveDataDetector.protectedPaths.count)",
            "vault": "\(vaultPaths.count)"
        ])
    }

    func stop() {
        for source in sources {
            source.cancel()
        }
        for fd in fileDescriptors {
            close(fd)
        }
        sources.removeAll()
        fileDescriptors.removeAll()
        if let obs = vaultObserver {
            NotificationCenter.default.removeObserver(obs)
            vaultObserver = nil
        }
        isRunning = false
        logger.info("\u{1F4C2} File Watcher stopped")
    }

    // MARK: - Directory Watching

    private func watchDirectory(_ dirPath: String, type: String) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: dirPath) else { return }

        let fd = open(dirPath, O_EVTONLY)
        guard fd >= 0 else {
            logger.warn("Cannot watch \(dirPath): open failed")
            return
        }
        fileDescriptors.append(fd)

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete, .extend],
            queue: DispatchQueue.global(qos: .utility)
        )

        source.setEventHandler { [weak self] in
            self?.handleDirectoryEvent(dirPath, type: type)
        }

        source.setCancelHandler {
            close(fd)
        }

        source.resume()
        sources.append(source)
    }

    private func handleDirectoryEvent(_ dirPath: String, type: String) {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(atPath: dirPath) else { return }

        for entry in entries {
            guard !entry.hasPrefix(".") else { continue }  // skip hidden files
            let fullPath = (dirPath as NSString).appendingPathComponent(entry)

            // Debounce per-file (thread-safe access to debounceTimers)
            let work = DispatchWorkItem { [weak self] in
                self?.handleFileEvent(fullPath, watchType: type)
            }
            timerLock.lock()
            debounceTimers[fullPath]?.cancel()
            debounceTimers[fullPath] = work
            timerLock.unlock()

            DispatchQueue.global(qos: .utility).asyncAfter(
                deadline: .now() + .milliseconds(config.fileWatcher.debounceMs),
                execute: work
            )
        }
    }

    private func handleFileEvent(_ filePath: String, watchType: String) {
        // Use lstat to avoid following symlinks (TOCTOU-safe, single syscall)
        var statBuf = stat()
        guard lstat(filePath, &statBuf) == 0 else { return }
        // Reject symlinks — only handle regular files
        guard (statBuf.st_mode & S_IFMT) == S_IFREG else { return }

        if watchType == "PROTECTED" {
            if isMacOSRoutine(filePath) {
                return   // silently skip routine macOS file operations (keychain, chat.db, etc.)
            }

            let alert = SecurityAlert(
                type: "PROTECTED_PATH_ACCESS",
                severity: .critical,
                message: "\u{26A0}\u{FE0F} Protected file change: \(filePath)",
                filePath: filePath
            )
            logger.alert(alert)
            onAlert?(alert)
            return
        }

        // Check if file is in a protected path
        let pathCheck = detector.isProtectedPath(filePath)
        if pathCheck.isProtected {
            let alert = SecurityAlert(
                type: "SENSITIVE_FILE_DETECTED",
                severity: pathCheck.severity ?? .high,
                message: "\u{1F6A8} Sensitive file in monitored directory: \(filePath)",
                filePath: filePath
            )
            logger.alert(alert)
            onAlert?(alert)
        }

        // Run ExternalFileSanitizer on new files in monitored directories
        if let sanitizer = sanitizer {
            let result = sanitizer.scanFile(filePath)
            if !result.safe && !result.threats.isEmpty {
                let topSeverity = result.threats.map(\.severity).max() ?? .high
                let alert = SecurityAlert(
                    type: "EXTERNAL_FILE_THREAT",
                    severity: topSeverity,
                    message: "\u{1F6A8} Malicious file: \((filePath as NSString).lastPathComponent) — \(result.threats.map(\.label).joined(separator: ", "))",
                    filePath: filePath,
                    threats: result.threats.map { ThreatDetail(label: $0.label, category: $0.category, severity: $0.severity) }
                )
                logger.alert(alert)
                onAlert?(alert)
            }
        }

        // Scan file content for sensitive data
        let ext = (filePath as NSString).pathExtension.lowercased()
        let dotExt = ext.isEmpty ? "" : ".\(ext)"
        let size = UInt64(statBuf.st_size)

        if scannableExtensions.contains(dotExt) && size < UInt64(config.fileWatcher.maxScanSizeBytes) {
            scanFileContent(filePath)
        }
    }

    private func scanFileContent(_ filePath: String) {
        guard let data = FileManager.default.contents(atPath: filePath),
              let content = String(data: data, encoding: .utf8) else { return }

        let findings = detector.scanText(content, source: filePath)
        guard !findings.isEmpty else { return }

        let hasCritical = findings.contains { $0.severity == .critical }
        let alert = SecurityAlert(
            type: "SENSITIVE_DATA_IN_FILE",
            severity: hasCritical ? .critical : .high,
            message: "\u{1F50D} Sensitive data in: \((filePath as NSString).lastPathComponent)",
            filePath: filePath,
            findings: findings.map { FindingDetail(label: $0.label, category: $0.category, severity: $0.severity) }
        )
        logger.alert(alert)
        onAlert?(alert)
    }

    // MARK: - Vault Path Monitoring

    /// Load vault-protected paths from the plaintext cache (no auth needed).
    private func loadVaultPaths() {
        let paths = VaultManager.cachedVaultPaths()
        vaultPaths = Set(paths)

        // Watch each vault file individually (directory DispatchSource doesn't detect
        // modifications to existing files — only creates/deletes).
        for path in paths {
            watchVaultFile(path)
        }
    }

    /// Reload vault path set and file watches when vault entries change.
    private func reloadVaultWatches() {
        let newPaths = VaultManager.cachedVaultPaths()
        let addedPaths = Set(newPaths).subtracting(vaultPaths)
        vaultPaths = Set(newPaths)
        for path in addedPaths {
            watchVaultFile(path)
        }
        logger.info("\u{1F512} Vault watches reloaded", data: ["paths": "\(vaultPaths.count)"])
    }

    /// Watch an individual vault file for any modification.
    private func watchVaultFile(_ filePath: String) {
        guard FileManager.default.fileExists(atPath: filePath) else { return }
        let fd = open(filePath, O_EVTONLY)
        guard fd >= 0 else { return }
        fileDescriptors.append(fd)

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename, .delete, .extend, .attrib],
            queue: DispatchQueue.global(qos: .utility)
        )

        source.setEventHandler { [weak self] in
            guard let self, !self.suppressVaultAlerts else { return }
            let fileName = (filePath as NSString).lastPathComponent
            let isVaultFile = filePath.hasSuffix(".vault")
            let alert = SecurityAlert(
                type: "VAULT_FILE_ACCESS",
                severity: .critical,
                message: "\u{1F6A8} Unauthorized access to vault-protected file: \(fileName)",
                filePath: filePath,
                findings: [FindingDetail(
                    label: isVaultFile ? "Encrypted vault file modified" : "Vault-protected file modified",
                    category: "vault_protection",
                    severity: .critical
                )]
            )
            self.logger.alert(alert)
            self.onAlert?(alert)
        }

        source.setCancelHandler {
            close(fd)
        }

        source.resume()
        sources.append(source)
    }

    /// Check if a file path is a vault-protected path (.vault file or original path).
    private func isVaultProtected(_ filePath: String) -> Bool {
        vaultPaths.contains(filePath)
    }

    private func isMacOSRoutine(_ filePath: String) -> Bool {
        let nsPath = filePath as NSString
        let range = NSRange(location: 0, length: nsPath.length)
        return routinePatterns.contains { $0.firstMatch(in: filePath, range: range) != nil }
    }
}
