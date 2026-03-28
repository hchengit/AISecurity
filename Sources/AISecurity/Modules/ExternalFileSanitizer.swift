import Foundation
import CryptoKit

/// Scans files from external sources for malicious code, prompt injection, and sensitive data.
/// Replaces modules/external-file-sanitizer.js — all patterns ported 1:1.
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

    private struct PatternGroup {
        let patterns: [NSRegularExpression]
        let label: String
        let severity: SeverityLevel
        let category: String
    }

    // MARK: - Properties

    private let logger: SecurityLogger
    private let maliciousPatterns: [(String, PatternGroup)]
    private let suspiciousFilenamePatterns: [NSRegularExpression]
    private var scannedCache: [String: String] = [:] // path → hash
    private let lock = NSLock()
    private(set) var filesScanned = 0
    private(set) var threatsDetected = 0
    private(set) var byCategory: [String: Int] = [:]

    // MARK: - Init

    init(logger: SecurityLogger) {
        self.logger = logger

        func compile(_ pats: [String], _ opts: NSRegularExpression.Options = .caseInsensitive) -> [NSRegularExpression] {
            pats.compactMap { try? NSRegularExpression(pattern: $0, options: opts) }
        }

        var groups: [(String, PatternGroup)] = []

        groups.append(("reverseShell", PatternGroup(
            patterns: compile([
                #"\bbash\s+-i\s+>&?\s*/dev/tcp/"#,
                #"\bnc\s+-e\s+/bin/(?:bash|sh)"#,
                #"\bpython\d*\s+-c\s+["']import socket"#,
                #"\bsocat\s+.*exec:"#,
                #"mkfifo\s+/tmp/[a-z]+\s*;\s*nc"#,
            ]),
            label: "Reverse Shell Payload", severity: .critical, category: "malicious_code"
        )))

        groups.append(("shellBombs", PatternGroup(
            patterns: compile([
                #":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;"#,
                #"rm\s+-rf\s+/(?:\s|$|\*)"#,
                #"chmod\s+-R\s+777\s+/"#,
                #"dd\s+if=/dev/zero\s+of=/dev/"#,
            ], []),
            label: "Destructive Shell Command", severity: .critical, category: "malicious_code"
        )))

        groups.append(("codeExecution", PatternGroup(
            patterns: compile([
                #"\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)"#,
                #"\beval\s*\(\s*atob\s*\("#,
                #"new\s+Function\s*\(\s*atob\s*\("#,
                #"exec\s*\(\s*['"`].*(?:wget|curl|nc|ncat)"#,
                #"os\.system\s*\(\s*['"`].*(?:wget|curl|nc)"#,
                #"\bpowershell\b.*-[Ee]nc(?:oded)?[Cc]ommand\b"#,
                #"\bIEX\s*\((?:New-Object\s+)?Net\.WebClient\)"#,
            ]),
            label: "Remote Code Execution Pattern", severity: .critical, category: "malicious_code"
        )))

        groups.append(("downloadAndExecute", PatternGroup(
            patterns: compile([
                #"curl\s+.*\|\s*(?:bash|sh|python|ruby|perl)"#,
                #"wget\s+.*-O\s*-\s*\|\s*(?:bash|sh)"#,
                #"fetch\s+.*\|\s*sh"#,
            ]),
            label: "Download-and-Execute Pattern", severity: .critical, category: "malicious_code"
        )))

        groups.append(("dataExfiltration", PatternGroup(
            patterns: compile([
                #"curl\s+.*-d\s+.*(?:\$HOME|~/\.ssh|keychain|wallet|sparrow|photos)"#,
                #"wget\s+.*--post-data.*(?:passwd|shadow|\.env|\.ssh)"#,
                #"(?:cat|cp|tar)\s+.*\.ssh.*\|\s*(?:curl|wget|nc)"#,
                #"find\s+.*(?:\.wallet|photoslibrary)\s+.*-exec\s+(?:curl|wget)"#,
                #"(?:cp|rsync|scp)\s+.*Photos Library.*(?:curl|wget|nc|sftp)"#,
            ]),
            label: "Data Exfiltration Attempt", severity: .critical, category: "exfiltration"
        )))

        groups.append(("cryptomining", PatternGroup(
            patterns: compile([
                #"\bxmrig\b"#,
                #"\bstratum\+tcp://"#,
                #"cryptonight"#,
            ]),
            label: "Cryptomining Code", severity: .high, category: "malicious_code"
        )))

        groups.append(("obfuscation", PatternGroup(
            patterns: compile([
                #"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}"#,
                #"chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+"#,
                #"String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){10,}\)"#,
            ]),
            label: "Obfuscated Code / Payload", severity: .high, category: "obfuscation"
        )))

        groups.append(("promptInjection", PatternGroup(
            patterns: compile([
                #"ignore\s+(previous|all|prior)\s+instructions?"#,
                #"forget\s+(your|all|previous)\s+instructions?"#,
                #"you\s+are\s+now\s+(a|an)\s+"#,
                #"new\s+system\s+prompt\s*:"#,
                #"override\s+(your|all|prior)\s+(rules?|instructions?)"#,
                #"jailbreak"#,
                #"reveal\s+(your|the)\s+(prompt|instructions?|system)"#,
            ]),
            label: "Prompt Injection Payload", severity: .high, category: "prompt_injection"
        )))

        groups.append(("macOSSpecific", PatternGroup(
            patterns: compile([
                #"osascript\s+-e\s+["']tell\s+application"#,
                #"launchctl\s+submit\s+-l"#,
                #"security\s+find-generic-password"#,
                #"security\s+add-generic-password"#,
                #"\bdscl\s+\.\s+-create\s+/Users\b"#,
                #"csrutil\s+disable"#,
                #"osascript.*Photos.*export"#,
                #"sqlite3.*Photos.*ZGENERICASSET"#,
            ]),
            label: "macOS-Specific Attack", severity: .critical, category: "malicious_code"
        )))

        self.maliciousPatterns = groups

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

        // Scan text content
        if let text = String(data: data, encoding: .utf8) {
            let nsText = text as NSString
            let range = NSRange(location: 0, length: nsText.length)

            for (key, group) in maliciousPatterns {
                for pattern in group.patterns {
                    if pattern.firstMatch(in: text, range: range) != nil {
                        result.safe = false
                        result.threats.append(.init(
                            type: key, label: group.label,
                            severity: group.severity, category: group.category
                        ))
                        lock.lock()
                        threatsDetected += 1
                        byCategory[group.category, default: 0] += 1
                        lock.unlock()
                        break
                    }
                }
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
