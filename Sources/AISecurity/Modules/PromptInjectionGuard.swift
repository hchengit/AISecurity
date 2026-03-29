import Foundation

/// Prompt Injection Guard — detects AI prompt injection attacks in text.
/// Pattern matching and heuristics now backed by Rust security-core via FFI.
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

    // MARK: - Properties

    private let logger: SecurityLogger
    private let lock = NSLock()
    private(set) var totalChecks = 0
    private(set) var blocked = 0
    private(set) var byCategory: [String: Int] = [:]
    private(set) var bySeverity: [SeverityLevel: Int] = [:]

    init(logger: SecurityLogger) {
        self.logger = logger
    }

    // MARK: - Validate (delegates to Rust)

    func validate(_ text: String, source: String = "unknown") -> ValidationResult {
        lock.lock()
        totalChecks += 1
        lock.unlock()

        guard !text.isEmpty else {
            return ValidationResult(safe: true, reason: nil, severity: nil, category: nil, source: source)
        }

        let r = SecurityCoreBridge.validatePrompt(text, source: source)

        if !r.safe {
            lock.lock()
            blocked += 1
            if let cat = r.category { byCategory[cat, default: 0] += 1 }
            if let sev = r.severity { bySeverity[sev, default: 0] += 1 }
            lock.unlock()

            logger.alert(SecurityAlert(
                type: "PROMPT_INJECTION_BLOCKED",
                severity: r.severity ?? .high,
                message: "\u{1F6E1}\u{FE0F} Blocked [\(r.severity?.rawValue ?? "high")]: \(r.reason ?? "Prompt injection")",
                preview: String(text.prefix(120)),
                category: r.category
            ))
        }

        return ValidationResult(
            safe: r.safe,
            reason: r.reason,
            severity: r.severity,
            category: r.category,
            source: source
        )
    }

    // MARK: - Sanitize (delegates to Rust)

    func sanitize(_ text: String) -> SanitizationResult {
        guard !text.isEmpty else {
            return SanitizationResult(sanitized: "", modified: false, changes: [])
        }

        let r = SecurityCoreBridge.sanitizeText(text)
        return SanitizationResult(sanitized: r.sanitized, modified: r.modified, changes: r.changes)
    }

    var blockRate: String {
        totalChecks > 0 ? String(format: "%.2f%%", Double(blocked) / Double(totalChecks) * 100) : "0%"
    }
}
