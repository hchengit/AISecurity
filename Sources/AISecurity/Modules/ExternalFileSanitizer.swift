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
    private var scannedCache: [String: String] = [:] // path → hash
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

    func scanFile(_ filePath: String) -> ScanResult {
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
        guard let data = fm.contents(atPath: filePath) else {
            result.error = "Cannot read file"; return result
        }

        let hash = SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        result.hash = hash

        // Cache check
        lock.lock()
        if scannedCache[filePath] == hash {
            lock.unlock()
            result.cachedResult = true
            return result
        }
        filesScanned += 1
        lock.unlock()

        // Check suspicious filename
        let basename = (filePath as NSString).lastPathComponent
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

        // Update cache
        lock.lock()
        scannedCache[filePath] = hash
        lock.unlock()

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

    func scanDirectory(_ dirPath: String) -> [ScanResult] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: dirPath) else { return [] }

        var results: [ScanResult] = []
        guard let entries = try? fm.contentsOfDirectory(atPath: dirPath) else { return [] }

        for entry in entries {
            let fullPath = (dirPath as NSString).appendingPathComponent(entry)
            guard let attrs = try? fm.attributesOfItem(atPath: fullPath),
                  let type = attrs[.type] as? FileAttributeType, type == .typeRegular,
                  let size = attrs[.size] as? UInt64, size < 10 * 1024 * 1024 else { continue }
            results.append(scanFile(fullPath))
        }

        return results
    }

    // MARK: - Quarantine

    func quarantine(_ filePath: String, to quarantineDir: String? = nil) -> QuarantineResult {
        let qDir = quarantineDir ?? SecurityConfig.shared.externalFileSanitizer.quarantineDir
        let fm = FileManager.default

        try? fm.createDirectory(atPath: qDir, withIntermediateDirectories: true)

        let basename = (filePath as NSString).lastPathComponent
        let dest = (qDir as NSString).appendingPathComponent(
            "\(Int(Date().timeIntervalSince1970))_\(basename)"
        )

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
