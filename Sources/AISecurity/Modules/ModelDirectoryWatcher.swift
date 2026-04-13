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

    /// Reference to process monitor for looking up active processes at modification time
    weak var processMonitor: ProcessMonitor?

    init(logger: SecurityLogger) {
        self.logger = logger
    }

    // MARK: - Start / Stop

    func start() {
        guard !isRunning else { return }
        isRunning = true

        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.discoverAndWatch()
        }

        // Re-discover every 6 hours (new installs, external drives)
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
        for source in sources { source.cancel() }
        sources.removeAll()
        for fd in fileDescriptors { close(fd) }
        fileDescriptors.removeAll()
        rediscoveryTimer?.cancel()
        rediscoveryTimer = nil
        isRunning = false
        logger.info("\u{1F4C1} Model Directory Watcher stopped")
    }

    // MARK: - Discovery + Watch

    private func discoverAndWatch() {
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

        for dir in dirs {
            watchDirectory(dir)
        }

        // Verify models
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.runVerification()
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
            self.runVerification()
        }
    }

    // MARK: - Verification + Alerts

    private func runVerification() {
        guard let json = SecurityCoreBridge.modelVerify(securityDir: config.securityDir),
              let data = json.data(using: .utf8),
              let results = try? JSONDecoder().decode([ModelVerifyResult].self, from: data) else {
            return
        }

        let newModels = results.filter { $0.status == "NewModel" }
        let tampered = results.filter { $0.status == "Tampered" }

        if !newModels.isEmpty {
            logger.info("\u{1F9E0} \(newModels.count) new model(s) discovered and hashed")
        }

        for t in tampered {
            emitTamperAlert(t)
        }
    }

    private func emitTamperAlert(_ result: ModelVerifyResult) {
        let fileName = (result.path as NSString).lastPathComponent
        let modDate = fileModDate(result.path)
        let activeProcesses = getActiveProcessNames()

        let message = """
        \u{1F6A8} MODEL CHANGED: \(fileName)
        Location: \(result.path)
        Expected hash: \(result.expected_hash?.prefix(16) ?? "?")...
        Actual hash: \(result.actual_hash?.prefix(16) ?? "?")...
        Last modified: \(modDate)
        Active processes: \(activeProcesses)

        \u{2705} If you updated, fine-tuned, or re-downloaded this model:
           No action needed — new hash has been automatically recorded.

        \u{26A0}\u{FE0F} If you did NOT modify this model:
           1. Do NOT run it — tampered weights may produce unsafe outputs
           2. Delete the file
           3. Re-download from the original source (Ollama/LM Studio/HuggingFace)

        To stop alerts for actively developed models, add the path to
        [model_verification] ignore_paths in ~/.mac-security/config.toml
        """

        logger.alert(SecurityAlert(
            type: "MODEL_TAMPERED",
            severity: .critical,
            message: message,
            filePath: result.path
        ))
    }

    // MARK: - Helpers

    /// Get human-readable modification date for a file.
    private func fileModDate(_ path: String) -> String {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let date = attrs[.modificationDate] as? Date else {
            return "unknown"
        }
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }

    /// Get names of currently active processes from ProcessMonitor.
    private func getActiveProcessNames() -> String {
        guard let monitor = processMonitor else {
            return "Process Monitor not available"
        }
        let agents = monitor.activeAgents()
        if agents.isEmpty {
            return "No AI agents running"
        }
        return agents.map { $0.name }.joined(separator: ", ")
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
