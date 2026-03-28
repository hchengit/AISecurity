import Foundation

/// Prompt Injection Guard — detects AI prompt injection attacks in text.
/// Replaces modules/prompt-injection-guard.js — all patterns ported 1:1.
final class PromptInjectionGuard: @unchecked Sendable {

    // MARK: - Types

    struct ValidationResult: Sendable {
        let safe: Bool
        let reason: String?
        let severity: SeverityLevel?
        let category: String?
        let source: String?
    }

    struct SanitizationResult: Sendable {
        let sanitized: String
        let modified: Bool
        let changes: [String]
    }

    private struct PatternGroup {
        let patterns: [NSRegularExpression]
        let label: String
        let severity: SeverityLevel
        let category: String
    }

    // MARK: - Properties

    private let logger: SecurityLogger
    private let groups: [PatternGroup]
    private let lock = NSLock()
    private(set) var totalChecks = 0
    private(set) var blocked = 0
    private(set) var byCategory: [String: Int] = [:]
    private(set) var bySeverity: [SeverityLevel: Int] = [:]

    // MARK: - Init

    init(logger: SecurityLogger) {
        self.logger = logger

        func compile(_ pats: [String]) -> [NSRegularExpression] {
            pats.compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
        }

        var g: [PatternGroup] = []

        g.append(PatternGroup(
            patterns: compile([
                #"ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|rules?|guidelines?)"#,
                #"forget\s+(your\s+|all\s+)?(previous|prior)\s+(instructions?|prompts?|rules?|training)"#,
                #"disregard\s+(your\s+|all\s+)?(previous|prior)\s+(instructions?|prompts?|rules?)"#,
                #"override\s+(your\s+|all\s+)?(previous|prior)\s+(instructions?|prompts?|rules?)"#,
                #"new\s+(system\s+)?prompt\s*[:=]"#,
                #"\[\s*system\s*\]"#,
                #"<\s*system\s*>"#,
            ]),
            label: "System Prompt Manipulation", severity: .critical, category: "system_prompt_manipulation"
        ))

        g.append(PatternGroup(
            patterns: compile([
                #"you\s+are\s+(now|henceforth)\s+(a|an)\s+"#,
                #"pretend\s+(you're|to\s+be|you\s+are)\s+"#,
                #"act\s+as\s+(if\s+you('re|\s+are)\s+)?(a|an)?\s*(admin|root|system|superuser|developer)"#,
                #"assume\s+the\s+(role|identity)\s+of"#,
                #"from\s+now\s+on,?\s+you('re|\s+are)"#,
                #"roleplay\s+as\s+(a|an)?\s*(admin|hacker|developer)"#,
            ]),
            label: "Role Hijacking", severity: .high, category: "role_hijacking"
        ))

        g.append(PatternGroup(
            patterns: compile([
                #"disregard\s+(safety|security|restrictions?|limitations?|filters?)"#,
                #"bypass\s+(filter|restriction|safety|security|guardrail)"#,
                #"disable\s+(filter|safety|security|restriction)"#,
                #"without\s+(restrictions?|limitations?|filters?)"#,
                #"remove\s+(all\s+)?(restrictions?|limitations?|filters?)"#,
            ]),
            label: "Instruction Override", severity: .critical, category: "instruction_override"
        ))

        g.append(PatternGroup(
            patterns: compile([
                #"(?:read|open|show|display|send|upload|copy|output)\s+.*(?:sparrow|\.wallet|seed\s*phrase|private\s*key|xprv|mnemonic)"#,
                #"(?:read|export|upload|share|copy|send)\s+.*(?:photos?\s*library|\.photoslibrary|PHAsset|photo\s*roll)"#,
                #"(?:access|open|extract)\s+.*(?:pictures|photos).*(?:library|album|roll)"#,
                #"(?:read|show|export|dump|extract)\s+.*(?:keychain|bitwarden|1password|aura|lastpass)"#,
                #"security\s+find-(?:generic|internet)-password"#,
                #"(?:read|show|upload|send)\s+.*(?:driver['\s]?s?\s+licen[sc]e|dl\s*#|state\s*id)"#,
                #"(?:cat|read|show|print)\s+.*\.ssh/(?:id_rsa|id_ed25519|known_hosts)"#,
                #"(?:open|read|send|upload|share)\s+.*(?:turbotax|tax\s*return|\.tax20\d{2}|1040|w-2)"#,
                #"(?:cat|read|show|print|display)\s+.*(?:\.env|\.envrc|secrets)"#,
            ]),
            label: "Mac Sensitive Data Exfiltration Attempt", severity: .critical, category: "mac_data_exfiltration"
        ))

        g.append(PatternGroup(
            patterns: compile([
                #"output\s+(your|the)\s+(prompt|instructions?|system|rules?)"#,
                #"reveal\s+(your|the)\s+(training|instructions?|prompt|rules?)"#,
                #"show\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions?)"#,
                #"dump\s+(your|the)\s+(prompt|instructions?|memory)"#,
            ]),
            label: "Data Exfiltration Attempt", severity: .high, category: "data_exfiltration"
        ))

        g.append(PatternGroup(
            patterns: compile([
                #"base64\s*(decode|encode)"#,
                #"\beval\s*\("#,
                #"atob\s*\("#,
                #"String\.fromCharCode"#,
                #"\\x[0-9a-f]{2}"#,
            ]),
            label: "Encoded Payload", severity: .critical, category: "encoded_payload"
        ))

        g.append(PatternGroup(
            patterns: compile([
                #"\bDAN\b"#,
                #"developer\s+mode"#,
                #"jailbreak"#,
                #"unrestricted\s+mode"#,
                #"god\s+mode"#,
                #"sudo\s+mode"#,
                #"no\s+limits?\s+mode"#,
            ]),
            label: "Jailbreak Attempt", severity: .high, category: "jailbreak_attempt"
        ))

        g.append(PatternGroup(
            patterns: compile([
                #"```\s*(system|instruction|prompt)"#,
                #"---\s*(system|instruction|prompt)"#,
                #"#{3,}\s*(system|instruction|new\s+rules?)"#,
                #"\[\[.*system.*\]\]"#,
            ]),
            label: "Delimiter Injection", severity: .medium, category: "delimiter_injection"
        ))

        self.groups = g
    }

    // MARK: - Validate

    func validate(_ text: String, source: String = "unknown") -> ValidationResult {
        lock.lock()
        totalChecks += 1
        lock.unlock()

        guard !text.isEmpty else {
            return ValidationResult(safe: true, reason: nil, severity: nil, category: nil, source: source)
        }

        let nsText = text as NSString
        let range = NSRange(location: 0, length: nsText.length)

        for group in groups {
            for pattern in group.patterns {
                if pattern.firstMatch(in: text, range: range) != nil {
                    lock.lock()
                    blocked += 1
                    byCategory[group.category, default: 0] += 1
                    bySeverity[group.severity, default: 0] += 1
                    lock.unlock()

                    let result = ValidationResult(
                        safe: false,
                        reason: "Prompt injection: \(group.label)",
                        severity: group.severity,
                        category: group.category,
                        source: source
                    )

                    logger.alert(SecurityAlert(
                        type: "PROMPT_INJECTION_BLOCKED",
                        severity: group.severity,
                        message: "\u{1F6E1}\u{FE0F} Blocked [\(group.severity.rawValue)]: \(group.label)",
                        preview: String(text.prefix(120)),
                        category: group.category
                    ))

                    return result
                }
            }
        }

        return heuristicCheck(text, source: source)
    }

    // MARK: - Sanitize

    func sanitize(_ text: String) -> SanitizationResult {
        guard !text.isEmpty else {
            return SanitizationResult(sanitized: "", modified: false, changes: [])
        }

        var sanitized = text
        var changes: [String] = []

        // Remove control characters
        let controlPattern = try? NSRegularExpression(pattern: #"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]"#)
        if let cp = controlPattern {
            let noControl = cp.stringByReplacingMatches(
                in: sanitized, range: NSRange(sanitized.startIndex..., in: sanitized), withTemplate: "")
            if noControl != sanitized { changes.append("Removed control characters"); sanitized = noControl }
        }

        // Neutralize code block delimiters
        let noCodeBlocks = sanitized.replacingOccurrences(of: "```", with: "` ` `")
        if noCodeBlocks != sanitized { changes.append("Neutralized code block delimiters"); sanitized = noCodeBlocks }

        // Remove HTML/XML tags
        let tagPattern = try? NSRegularExpression(pattern: #"</?[a-z][^>]*>"#, options: .caseInsensitive)
        if let tp = tagPattern {
            let noTags = tp.stringByReplacingMatches(
                in: sanitized, range: NSRange(sanitized.startIndex..., in: sanitized), withTemplate: "")
            if noTags != sanitized { changes.append("Removed HTML/XML tags"); sanitized = noTags }
        }

        // Truncate
        if sanitized.count > 10000 {
            sanitized = String(sanitized.prefix(10000))
            changes.append("Truncated to 10,000 chars")
        }

        return SanitizationResult(sanitized: sanitized, modified: !changes.isEmpty, changes: changes)
    }

    // MARK: - Private

    private func heuristicCheck(_ text: String, source: String) -> ValidationResult {
        let specialChars = text.filter { !$0.isLetter && !$0.isNumber && !$0.isWhitespace }
        let specialRatio = text.isEmpty ? 0.0 : Double(specialChars.count) / Double(text.count)

        if specialRatio > 0.5 && text.count > 50 {
            return ValidationResult(safe: false, reason: "High special char ratio (obfuscation)", severity: .medium, category: "obfuscation", source: source)
        }

        let escapePattern = try? NSRegularExpression(pattern: #"\\[nrtbf"'\\]"#)
        let escapeCount = escapePattern?.numberOfMatches(in: text, range: NSRange(text.startIndex..., in: text)) ?? 0
        if escapeCount > 10 {
            return ValidationResult(safe: false, reason: "Excessive escape sequences", severity: .medium, category: "obfuscation", source: source)
        }

        let longTokenPattern = try? NSRegularExpression(pattern: #"\b\w{100,}\b"#)
        if let ltp = longTokenPattern, ltp.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil {
            return ValidationResult(safe: false, reason: "Extremely long token (encoded payload)", severity: .medium, category: "encoded_payload", source: source)
        }

        return ValidationResult(safe: true, reason: nil, severity: nil, category: nil, source: source)
    }

    var blockRate: String {
        totalChecks > 0 ? String(format: "%.2f%%", Double(blocked) / Double(totalChecks) * 100) : "0%"
    }
}
