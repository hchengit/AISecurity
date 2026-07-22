import Foundation
import CryptoKit

/// Scans files from external sources for malicious code, prompt injection, and sensitive data.
/// Pattern matching now backed by Rust security-core via FFI. File I/O stays in Swift.
final class ExternalFileSanitizer: @unchecked Sendable {

    // MARK: - Types

    struct ScanResult: Sendable {
        let filePath: String
        var safe: Bool
        var threats: [Threat]
        var warnings: [Warning]
        let timestamp: String
        var hash: String?
        var error: String?
        var cachedResult: Bool

        struct Threat: Sendable {
            let type: String
            let label: String
            let severity: SeverityLevel
            let category: String
        }

        struct Warning: Sendable {
            let label: String
            let severity: SeverityLevel
            let detail: String
        }
    }

    struct QuarantineResult: Sendable {
        let success: Bool
        let quarantinePath: String?
        let error: String?
    }

    // MARK: - Properties

    private let logger: SecurityLogger
    private let suspiciousFilenamePatterns: [NSRegularExpression]

    /// Extensions that are unambiguously dangerous as an **email attachment** — native executables,
    /// Windows executables/scripts, auto-run scripts, macro-enabled Office documents, and auto-mount
    /// disk images. Applied only in `strictExecCheck` mode (email-attachment provenance), so a legit
    /// installer (`.dmg`/`.pkg`) that a user downloads in a browser is NOT swept up. The content
    /// scanner can't see into a non-text binary, so this extension check is what actually catches a
    /// disguised or bare executable materialized out of an email.
    static let dangerousAttachmentExtensions: Set<String> = [
        // Windows executables / auto-run scripts (≈never legit as an unsolicited Mac email attachment)
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".jar", ".ps1", ".wsf", ".hta", ".msi", ".lnk", ".cpl", ".reg",
        // macOS-native execution + installers + shell scripts. Included even though a user CAN be
        // legitimately emailed a .dmg/.pkg — this set is applied only to email-attachment provenance
        // (Mail's attachment dir), never general browser Downloads, and quarantine is reversible.
        ".app", ".command", ".workflow", ".osascript", ".scpt",
        ".dmg", ".pkg", ".mpkg", ".sh", ".bash", ".zsh", ".zsh-theme",
        // Macro-enabled Office documents (the classic dropper)
        ".docm", ".xlsm", ".pptm", ".xlam", ".xltm", ".dotm",
        // Disk images (auto-mount + bypass mark-of-the-web)
        ".iso", ".img",
    ]
    /// Container types whose ZIP entry listing we inspect (Tier-2 inc-2): Office OOXML macro-FREE
    /// documents (macro-enabled types are in `dangerousAttachmentExtensions`) plus `.zip` archives.
    static let containerExtensions: Set<String> = [
        ".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx", ".ppsx", ".zip",
    ]
    private var safeMetaCache: [String: String] = [:] // path → "mtime:size", SAFE results only
    private let lock = NSLock()
    private(set) var filesScanned = 0
    private(set) var threatsDetected = 0
    private(set) var byCategory: [String: Int] = [:]

    // MARK: - Init

    init(logger: SecurityLogger) {
        self.logger = logger

        self.suspiciousFilenamePatterns = [
            #"\.sh\.download$"#,
            #"\.dmg\.zip$"#,
            #"\.pdf\.exe$"#,
            #"\.jpg\.sh$"#,
            #"invoice.*\.js$"#,
            #"setup.*\.sh$"#,
            #"update.*\.sh$"#,
            #"install.*\.sh$"#,
        ].compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
    }

    // MARK: - Scan File

    /// - Parameter strictExecCheck: when true (a file materialized from an email attachment), a
    ///   dangerous executable/script/macro/disk-image extension is treated as a critical threat
    ///   even though its bytes aren't readable text — this is what enables containment of a
    ///   disguised or bare executable that the content scanner can't see into.
    func scanFile(_ filePath: String, strictExecCheck: Bool = false) -> ScanResult {
        var result = ScanResult(
            filePath: filePath, safe: true, threats: [], warnings: [],
            timestamp: ISO8601DateFormatter().string(from: Date()),
            hash: nil, error: nil, cachedResult: false
        )

        let fm = FileManager.default
        guard fm.fileExists(atPath: filePath) else {
            result.error = "File not found"; return result
        }
        guard let attrs = try? fm.attributesOfItem(atPath: filePath),
              let type = attrs[.type] as? FileAttributeType, type == .typeRegular else {
            result.error = "Not a regular file"; return result
        }
        let basename = (filePath as NSString).lastPathComponent
        let mtime = (attrs[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        let size = (attrs[.size] as? UInt64) ?? 0
        let metaKey = "\(mtime):\(size)"

        // Skip re-reading a file we already scanned SAFE and that hasn't changed (mtime+size) — the
        // cheap path for the periodic tree rescan (no re-read/re-hash of large lingering files).
        // Dangerous files are deliberately NOT cached, so an un-contained threat is re-detected (and
        // quarantine retried) on every pass rather than being permanently masked by a cache entry
        // written before containment was even attempted.
        lock.lock()
        if safeMetaCache[filePath] == metaKey {
            lock.unlock()
            result.cachedResult = true
            return result
        }
        lock.unlock()

        guard let data = fm.contents(atPath: filePath) else {
            result.error = "Cannot read file"; return result
        }
        result.hash = SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        lock.lock()
        filesScanned += 1
        lock.unlock()

        // Strict executable-extension check (email-attachment provenance): extension-based, so a
        // disguised or bare executable is contained even though its bytes aren't readable text and
        // the content scanner can't see into it.
        if strictExecCheck {
            let ext = (basename as NSString).pathExtension.lowercased()
            if Self.dangerousAttachmentExtensions.contains(".\(ext)") {
                result.safe = false
                result.threats.append(.init(
                    type: "dangerous_attachment_ext",
                    label: "Dangerous attachment: \(basename)",
                    severity: .critical, category: "dangerous_attachment"
                ))
                lock.lock()
                threatsDetected += 1
                byCategory["dangerous_attachment", default: 0] += 1
                lock.unlock()
            } else {
                // Tier 2 inc-1: a benign-named file whose leading bytes are a native executable — a
                // disguised executable the extension check above can't see.
                for t in SecurityCoreBridge.analyzeAttachmentStructure(Data(data.prefix(1024)), filename: basename) {
                    result.safe = false
                    result.threats.append(.init(type: t.type, label: t.label, severity: t.severity, category: t.category))
                    lock.lock()
                    threatsDetected += 1
                    byCategory[t.category, default: 0] += 1
                    lock.unlock()
                }
                // Tier 2 inc-2: container inspection (ZIP entry listing) for an Office OOXML doc or a
                // zip — catches a disguised macro document or an archive smuggling an executable /
                // encrypted payload. Bounded prefix (the whole file if smaller).
                if Self.containerExtensions.contains(".\(ext)") {
                    for t in SecurityCoreBridge.analyzeContainer(Data(data.prefix(1024 * 1024)), filename: basename) {
                        result.safe = false
                        result.threats.append(.init(type: t.type, label: t.label, severity: t.severity, category: t.category))
                        lock.lock()
                        threatsDetected += 1
                        byCategory[t.category, default: 0] += 1
                        lock.unlock()
                    }
                }
            }
        }

        // Check suspicious filename
        let bnRange = NSRange(location: 0, length: (basename as NSString).length)
        for pattern in suspiciousFilenamePatterns {
            if pattern.firstMatch(in: basename, range: bnRange) != nil {
                result.warnings.append(.init(
                    label: "Suspicious filename", severity: .medium,
                    detail: "\"\(basename)\" matches a suspicious pattern"
                ))
            }
        }

        // Scan text content via Rust FFI
        if let text = String(data: data, encoding: .utf8) {
            let rustThreats = SecurityCoreBridge.scanFileContent(text)

            for t in rustThreats {
                result.safe = false
                result.threats.append(.init(
                    type: t.type, label: t.label,
                    severity: t.severity, category: t.category
                ))
                lock.lock()
                threatsDetected += 1
                byCategory[t.category, default: 0] += 1
                lock.unlock()
            }
        }

        // Cache ONLY safe results, keyed by mtime+size — a dangerous file is re-scanned until it's
        // contained (moved out), never permanently masked. Bounded to avoid unbounded growth from
        // ephemeral per-attachment UUID paths.
        if result.safe {
            lock.lock()
            if safeMetaCache.count > 4096 { safeMetaCache.removeAll() }
            safeMetaCache[filePath] = metaKey
            lock.unlock()
        }

        // Log result
        if !result.safe {
            logger.alert(SecurityAlert(
                type: "EXTERNAL_FILE_THREAT",
                severity: .critical,
                message: "\u{1F6A8} Malicious content in: \(basename)",
                filePath: filePath,
                threats: result.threats.map { ThreatDetail(label: $0.label, category: $0.category, severity: $0.severity) }
            ))
        } else if !result.warnings.isEmpty {
            logger.warn("\u{26A0}\u{FE0F} Suspicious file: \(basename)")
        } else {
            logger.info("\u{2705} File scan clean: \(basename)")
        }

        return result
    }

    // MARK: - Scan Directory

    func scanDirectory(_ dirPath: String, strictExecCheck: Bool = false) -> [ScanResult] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: dirPath) else { return [] }

        var results: [ScanResult] = []
        guard let entries = try? fm.contentsOfDirectory(atPath: dirPath) else { return [] }

        for entry in entries {
            let fullPath = (dirPath as NSString).appendingPathComponent(entry)
            guard let attrs = try? fm.attributesOfItem(atPath: fullPath),
                  let type = attrs[.type] as? FileAttributeType, type == .typeRegular,
                  let size = attrs[.size] as? UInt64, size < 10 * 1024 * 1024 else { continue }
            results.append(scanFile(fullPath, strictExecCheck: strictExecCheck))
        }

        return results
    }

    /// Recursively scan a directory subtree (bounded). Needed for Apple Mail's attachment dir, which
    /// materializes each opened attachment inside its own randomly-named subfolder
    /// (`Mail Downloads/<uuid>/file`) — a non-recursive scan would never see the real file.
    func scanDirectoryTree(_ dirPath: String, strictExecCheck: Bool = false, maxFiles: Int = 2000) -> [ScanResult] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: dirPath),
              let en = fm.enumerator(
                at: URL(fileURLWithPath: dirPath),
                includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                options: [.skipsHiddenFiles]) else { return [] }

        var results: [ScanResult] = []
        var count = 0
        for case let url as URL in en {
            if count >= maxFiles { break }
            guard let vals = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
                  vals.isRegularFile == true, (vals.fileSize ?? 0) < 100 * 1024 * 1024 else { continue }
            count += 1
            results.append(scanFile(url.path, strictExecCheck: strictExecCheck))
        }
        return results
    }

    // MARK: - Quarantine

    func quarantine(_ filePath: String, to quarantineDir: String? = nil) -> QuarantineResult {
        let qDir = quarantineDir ?? SecurityConfig.shared.externalFileSanitizer.quarantineDir
        let fm = FileManager.default

        try? fm.createDirectory(atPath: qDir, withIntermediateDirectories: true)

        let basename = (filePath as NSString).lastPathComponent
        // Uniquify the destination: two attachments from different emails routinely share a basename
        // (e.g. "report.pdf.exe"), and moveItem throws on an existing dest — a collision that would
        // otherwise leave the second file un-quarantined (and, with the cache, silently un-rescanned).
        let base = (qDir as NSString).appendingPathComponent("\(Int(Date().timeIntervalSince1970))_\(basename)")
        var dest = base
        var n = 1
        while fm.fileExists(atPath: dest) { dest = "\(base).\(n)"; n += 1 }

        do {
            try fm.moveItem(atPath: filePath, toPath: dest)
            logger.alert(SecurityAlert(
                type: "FILE_QUARANTINED",
                severity: .high,
                message: "\u{1F512} Quarantined: \(basename)",
                filePath: filePath
            ))
            return QuarantineResult(success: true, quarantinePath: dest, error: nil)
        } catch {
            return QuarantineResult(success: false, quarantinePath: nil, error: error.localizedDescription)
        }
    }
}
