import Foundation

/// Watches discovered model directories for new/changed model files in real-time.
///
/// Flow:
/// 1. On first install: discovers model directories (scans home + /Volumes/)
/// 2. Watches those directories via DispatchSource for file changes
/// 3. When a new .gguf/.safetensors/etc. appears → hash it immediately
/// 4. Periodically re-discovers directories (every 6 hours) to catch new locations
/// 5. Persists discovered directories to ~/.mac-security/model-directories.json
final class ModelDirectoryWatcher: @unchecked Sendable {

    private let logger: SecurityLogger
    private let config = SecurityConfig.shared
    private var sources: [DispatchSourceFileSystemObject] = []
    private var fileDescriptors: [Int32] = []
    private var rediscoveryTimer: DispatchSourceTimer?
    private(set) var isRunning = false
    private(set) var watchedDirectories: [String] = []

    /// Model file extensions to watch for
    private static let modelExtensions: Set<String> = [
        "gguf", "ggml", "safetensors", "bin", "pth", "pt",
        "onnx", "mlmodel", "mlpackage", "npz", "npy",
    ]

    init(logger: SecurityLogger) {
        self.logger = logger
    }

    // MARK: - Start / Stop

    func start() {
        guard !isRunning else { return }
        isRunning = true

        // Discover model directories (background — may take a few seconds on first run)
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.discoverAndWatch()
        }

        // Re-discover directories every 6 hours (catches new installs, external drives)
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 6 * 3600, repeating: 6 * 3600)
        timer.setEventHandler { [weak self] in
            self?.discoverAndWatch()
        }
        timer.resume()
        rediscoveryTimer = timer

        logger.info("\u{1F4C1} Model Directory Watcher started")
    }

    func stop() {
        // Cancel all DispatchSources
        for source in sources {
            source.cancel()
        }
        sources.removeAll()
        for fd in fileDescriptors {
            close(fd)
        }
        fileDescriptors.removeAll()
        rediscoveryTimer?.cancel()
        rediscoveryTimer = nil
        isRunning = false
        logger.info("\u{1F4C1} Model Directory Watcher stopped")
    }

    // MARK: - Discovery + Watch

    private func discoverAndWatch() {
        // Ask Rust to scan home + /Volumes/ for model files
        let dirs = SecurityCoreBridge.modelDiscoverDirs(securityDir: config.securityDir)

        guard !dirs.isEmpty else {
            logger.info("\u{1F4C1} Model discovery: no model directories found")
            return
        }

        logger.info("\u{1F4C1} Model discovery: found \(dirs.count) directories with models")

        // Stop watching old directories
        for source in sources { source.cancel() }
        sources.removeAll()
        for fd in fileDescriptors { close(fd) }
        fileDescriptors.removeAll()

        watchedDirectories = dirs

        // Watch each directory for changes
        for dir in dirs {
            watchDirectory(dir)
        }

        // Also run a verification to hash any new models found
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self else { return }
            if let json = SecurityCoreBridge.modelVerify(securityDir: self.config.securityDir),
               json.contains("NewModel") {
                // Count new models
                if let data = json.data(using: .utf8),
                   let results = try? JSONDecoder().decode([ModelVerifyResult].self, from: data) {
                    let newCount = results.filter { $0.status == "NewModel" }.count
                    let tamperedCount = results.filter { $0.status == "Tampered" }.count
                    if newCount > 0 {
                        self.logger.info("\u{1F9E0} Model verification: \(newCount) new model(s) hashed")
                    }
                    if tamperedCount > 0 {
                        self.logger.alert(SecurityAlert(
                            type: "MODEL_TAMPERED",
                            severity: .critical,
                            message: "\u{1F6A8} \(tamperedCount) model file(s) have been tampered with! Hash mismatch detected.",
                            filePath: nil
                        ))
                    }
                }
            }
        }
    }

    private func watchDirectory(_ dir: String) {
        guard FileManager.default.fileExists(atPath: dir) else { return }
        let fd = open(dir, O_EVTONLY)
        guard fd >= 0 else { return }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .rename],
            queue: DispatchQueue.global(qos: .utility)
        )

        source.setEventHandler { [weak self] in
            // Directory changed — check for new model files
            self?.onDirectoryChanged(dir)
        }
        source.setCancelHandler { close(fd) }
        source.resume()
        sources.append(source)
        fileDescriptors.append(fd)
    }

    /// Called when a watched directory changes. Triggers model verification.
    private func onDirectoryChanged(_ dir: String) {
        // Debounce: wait 2 seconds for downloads to complete
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self else { return }
            self.logger.info("\u{1F4C1} Model directory changed: \(dir) — verifying...")
            if let json = SecurityCoreBridge.modelVerify(securityDir: self.config.securityDir),
               let data = json.data(using: .utf8),
               let results = try? JSONDecoder().decode([ModelVerifyResult].self, from: data) {
                let newCount = results.filter { $0.status == "NewModel" }.count
                let tamperedCount = results.filter { $0.status == "Tampered" }.count
                if newCount > 0 {
                    self.logger.info("\u{1F9E0} New model detected and hashed in \(dir): \(newCount) file(s)")
                }
                if tamperedCount > 0 {
                    self.logger.alert(SecurityAlert(
                        type: "MODEL_TAMPERED",
                        severity: .critical,
                        message: "\u{1F6A8} Model tampered in \(dir)! \(tamperedCount) file(s) have mismatched hashes.",
                        filePath: dir
                    ))
                }
            }
        }
    }

    /// JSON-decodable verification result (matches Rust VerificationResult)
    private struct ModelVerifyResult: Decodable {
        let path: String
        let status: String
        let expected_hash: String?
        let actual_hash: String?
        let size_bytes: UInt64
    }
}
