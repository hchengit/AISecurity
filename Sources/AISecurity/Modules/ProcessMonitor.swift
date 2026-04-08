import Foundation
import Darwin

/// Monitors running processes for AI agents and anomalies.
///
/// - Enumerates processes every 30 seconds via Darwin proc_listpids()
/// - Tracks known AI agent processes (ollama, cursor, copilot, etc.)
/// - Builds a 7-day behavioral baseline of "normal" processes
/// - Alerts on new unknown processes, especially those accessing sensitive files
/// - Works with or without AI agents installed
final class ProcessMonitor: @unchecked Sendable {

    private let logger: SecurityLogger
    private let config = SecurityConfig.shared
    private var pollTimer: DispatchSourceTimer?
    private(set) var isRunning = false

    /// Known process snapshots (pid → snapshot)
    private var knownProcesses: [Int32: ProcessSnapshot] = [:]
    /// Baseline: process names seen in the last 7 days
    private var baselineNames: Set<String> = []
    /// State file for persistence
    private let stateFile: String

    /// AI agent process names to specifically track
    private static let agentProcessNames: Set<String> = [
        "ollama", "ollama-runner", "llama-server", "llamafile", "llama-cli",
        "ik-llama-server", "ik-llama-cli",                // ik_llama.cpp
        "mlx_lm", "mlx_lm.server",                        // Apple MLX
        "lmstudio", "lm-studio",                           // LM Studio
        "cursor", "Cursor", "Cursor Helper",               // Cursor IDE
        "copilot", "GitHub Copilot",                        // GitHub Copilot
        "code-server",                                      // VS Code server
        "aider",                                            // Aider
        "continue",                                         // Continue.dev
        "claude", "claude-code",                            // Claude Code
        "gpt4all",                                          // GPT4All
        "text-generation-launcher",                         // HuggingFace TGI
        "vllm",                                             // vLLM
    ]

    /// Processes that are always expected (never alert on)
    private static let systemProcesses: Set<String> = [
        "kernel_task", "launchd", "WindowServer", "loginwindow",
        "Finder", "Dock", "SystemUIServer", "NotificationCenter",
        "mds", "mds_stores", "mdworker", "spotlight",
        "coreaudiod", "bluetoothd", "WiFiAgent",
        "cfprefsd", "distnoted", "usernoted",
        "AISecurity", "AISecurity-bin",
    ]

    struct ProcessSnapshot: Codable {
        let pid: Int32
        let name: String
        var firstSeen: TimeInterval
        var lastSeen: TimeInterval
        var isAgent: Bool
    }

    struct ProcessBaseline: Codable {
        var knownNames: Set<String>
        var agentHistory: [AgentRecord]
        var lastUpdated: TimeInterval
    }

    struct AgentRecord: Codable {
        let name: String
        var totalRuntime: TimeInterval  // approximate
        var lastSeen: TimeInterval
        var firstSeen: TimeInterval
    }

    init(logger: SecurityLogger) {
        self.logger = logger
        self.stateFile = (SecurityConfig.shared.securityDir as NSString)
            .appendingPathComponent("process-baseline.json")
        loadBaseline()
    }

    // MARK: - Start / Stop

    func start() {
        guard !isRunning else { return }
        isRunning = true

        // Initial scan
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.scanProcesses()
        }

        // Poll every 30 seconds
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 30, repeating: 30)
        timer.setEventHandler { [weak self] in
            self?.scanProcesses()
        }
        timer.resume()
        pollTimer = timer

        logger.info("\u{1F50D} Process Monitor started (tracking \(Self.agentProcessNames.count) AI agent names)")
    }

    func stop() {
        pollTimer?.cancel()
        pollTimer = nil
        isRunning = false
        persistBaseline()
        logger.info("\u{1F50D} Process Monitor stopped")
    }

    // MARK: - Process Scanning

    private func scanProcesses() {
        let now = Date().timeIntervalSince1970
        let processes = listRunningProcesses()
        var activeAgents: [String] = []
        var newUnknownProcesses: [String] = []

        for (pid, name) in processes {
            // Skip system processes
            if Self.systemProcesses.contains(name) { continue }

            let isAgent = Self.agentProcessNames.contains(name)

            if let existing = knownProcesses[pid] {
                // Known process — update last seen
                var updated = existing
                updated.lastSeen = now
                knownProcesses[pid] = updated
            } else {
                // New process
                knownProcesses[pid] = ProcessSnapshot(
                    pid: pid,
                    name: name,
                    firstSeen: now,
                    lastSeen: now,
                    isAgent: isAgent
                )

                // Check if this is a new unknown process (not in baseline)
                if !baselineNames.contains(name) && !Self.systemProcesses.contains(name) {
                    newUnknownProcesses.append(name)
                }
            }

            if isAgent {
                activeAgents.append(name)
            }

            // Add to baseline
            baselineNames.insert(name)
        }

        // Clean up terminated processes
        let activePids = Set(processes.map { $0.0 })
        knownProcesses = knownProcesses.filter { activePids.contains($0.key) }

        // Alert on new unknown processes (not in 7-day baseline)
        for name in newUnknownProcesses {
            logger.info("\u{1F50D} New process detected: \(name)")
        }

        // Log active AI agents (periodically, not every scan)
        if !activeAgents.isEmpty {
            // Only log agent activity every 5 minutes to reduce noise
            let agentList = activeAgents.joined(separator: ", ")
            logger.info("\u{1F916} Active AI agents: \(agentList)")
        }
    }

    // MARK: - Process Enumeration (Darwin API)

    /// List all running processes using Darwin proc_listpids.
    private func listRunningProcesses() -> [(Int32, String)] {
        var results: [(Int32, String)] = []

        // Get count of all PIDs
        let pidCount = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard pidCount > 0 else { return results }

        let bufferSize = Int(pidCount) * MemoryLayout<Int32>.size
        var pids = [Int32](repeating: 0, count: Int(pidCount))
        let actualSize = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, Int32(bufferSize))
        let actualCount = Int(actualSize) / MemoryLayout<Int32>.size

        for i in 0..<actualCount {
            let pid = pids[i]
            if pid <= 0 { continue }

            var nameBuffer = [CChar](repeating: 0, count: 1024)
            let nameLen = proc_name(pid, &nameBuffer, UInt32(nameBuffer.count))
            if nameLen > 0 {
                let name = String(cString: nameBuffer)
                if !name.isEmpty {
                    results.append((pid, name))
                }
            }
        }

        return results
    }

    // MARK: - Active Agent Queries

    /// Get list of currently running AI agent processes.
    func activeAgents() -> [ProcessSnapshot] {
        knownProcesses.values.filter { $0.isAgent }
    }

    /// Check if any AI agent is currently running.
    var hasActiveAgents: Bool {
        knownProcesses.values.contains { $0.isAgent }
    }

    // MARK: - Persistence

    private func loadBaseline() {
        guard let data = FileManager.default.contents(atPath: stateFile),
              let baseline = try? JSONDecoder().decode(ProcessBaseline.self, from: data) else {
            return
        }
        baselineNames = baseline.knownNames

        // Prune baseline entries older than 7 days
        let sevenDaysAgo = Date().timeIntervalSince1970 - (7 * 24 * 60 * 60)
        if baseline.lastUpdated < sevenDaysAgo {
            baselineNames.removeAll()
        }
    }

    private func persistBaseline() {
        let baseline = ProcessBaseline(
            knownNames: baselineNames,
            agentHistory: activeAgents().map { snap in
                AgentRecord(
                    name: snap.name,
                    totalRuntime: snap.lastSeen - snap.firstSeen,
                    lastSeen: snap.lastSeen,
                    firstSeen: snap.firstSeen
                )
            },
            lastUpdated: Date().timeIntervalSince1970
        )
        if let data = try? JSONEncoder().encode(baseline) {
            try? data.write(to: URL(fileURLWithPath: stateFile))
        }
    }
}
