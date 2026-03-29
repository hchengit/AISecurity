import Foundation

/// Scans text and file paths for sensitive personal, financial, and crypto data.
/// Pattern matching now backed by Rust security-core via FFI.
final class SensitiveDataDetector: @unchecked Sendable {

    // MARK: - Types

    struct Finding: Sendable {
        let type: String
        let label: String
        let severity: SeverityLevel
        let category: String
        let source: String
        let matchPreview: String
        let offset: Int
    }

    struct PathCheckResult: Sendable {
        let isProtected: Bool
        let reason: String?
        let severity: SeverityLevel?
    }

    // MARK: - Properties

    private let lock = NSLock()
    private(set) var totalScans = 0
    private(set) var totalFindings = 0
    private(set) var byCategory: [String: Int] = [:]
    private(set) var bySeverity: [SeverityLevel: Int] = [:]

    init() {}

    // MARK: - Scan Text (delegates to Rust)

    func scanText(_ text: String, source: String = "unknown") -> [Finding] {
        guard !text.isEmpty else { return [] }

        lock.lock()
        totalScans += 1
        lock.unlock()

        let rustFindings = SecurityCoreBridge.scanSensitiveData(text, source: source)

        let findings = rustFindings.map { f in
            Finding(
                type: f.type,
                label: f.label,
                severity: f.severity,
                category: f.category,
                source: f.source,
                matchPreview: f.matchPreview,
                offset: f.offset
            )
        }

        if !findings.isEmpty {
            lock.lock()
            totalFindings += findings.count
            for f in findings {
                byCategory[f.category, default: 0] += 1
                bySeverity[f.severity, default: 0] += 1
            }
            lock.unlock()
        }

        return findings
    }

    // MARK: - Protected Paths (stays in Swift — uses FileManager)

    static let protectedPaths: [String] = SecurityConfig.shared.paths.protectedPaths

    static let sensitiveExtensions: Set<String> = [
        ".key", ".pem", ".p12", ".pfx", ".cert", ".crt",
        ".wallet", ".sparrow",
        ".tax", ".tax2022", ".tax2023", ".tax2024",
        ".kdbx",
        ".env", ".envrc",
        ".keychain", ".keychain-db",
        ".asc", ".gpg",
        ".id_rsa", ".id_ed25519", ".id_ecdsa",
        ".photoslibrary",
    ]

    func isProtectedPath(_ filePath: String) -> PathCheckResult {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let normalized = filePath.hasPrefix("~")
            ? home + filePath.dropFirst()
            : filePath

        for protected in Self.protectedPaths {
            if normalized.hasPrefix(protected) {
                return PathCheckResult(
                    isProtected: true,
                    reason: "Inside protected directory: \(protected)",
                    severity: .critical
                )
            }
        }

        let ext = (filePath as NSString).pathExtension.lowercased()
        let dotExt = ext.isEmpty ? "" : ".\(ext)"
        let basename = (filePath as NSString).lastPathComponent

        if Self.sensitiveExtensions.contains(dotExt) {
            return PathCheckResult(isProtected: true, reason: "Sensitive file extension: \(dotExt)", severity: .high)
        }
        if basename.range(of: #"^\.env(\.[a-z]+)?$"#, options: .regularExpression) != nil {
            return PathCheckResult(isProtected: true, reason: ".env file detected", severity: .critical)
        }
        if basename.range(of: #"id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$"#, options: .regularExpression) != nil {
            return PathCheckResult(isProtected: true, reason: "SSH key file detected", severity: .critical)
        }
        if filePath.hasSuffix(".photoslibrary") {
            return PathCheckResult(isProtected: true, reason: "Apple Photos Library detected", severity: .high)
        }

        return PathCheckResult(isProtected: false, reason: nil, severity: nil)
    }
}
