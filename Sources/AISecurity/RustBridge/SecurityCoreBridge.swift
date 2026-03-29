import Foundation
import CSecurityCore

// MARK: - SecurityCoreBridge
// Thin Swift wrapper around the Rust security-core FFI.
// Handles String↔CChar conversion and memory management.

enum SecurityCoreBridge {

    // MARK: - Init

    /// Warm up Rust lazy statics. Call once at startup.
    static func initialize() {
        sec_init(nil)
    }

    // MARK: - Intent Parser

    struct IntentResult: Sendable {
        let isThreat: Bool
        let severity: SeverityLevel?
        let layersFired: Int
        let layers: Layers
        let label: String
        let confidence: String

        struct Layers: Sendable {
            let l1, l2, l3, l4, l5, l6: Bool
        }
    }

    enum Channel: UInt8, Sendable {
        case email = 0
        case sms = 1
    }

    static func parseIntent(_ text: String, channel: Channel = .email) -> IntentResult {
        let ptr = text.withCString { sec_parse_intent($0, channel.rawValue) }
        guard let r = ptr else {
            return IntentResult(isThreat: false, severity: nil, layersFired: 0,
                                layers: .init(l1: false, l2: false, l3: false, l4: false, l5: false, l6: false),
                                label: "", confidence: "0%")
        }
        defer { sec_free_intent_result(ptr) }
        let p = r.pointee
        return IntentResult(
            isThreat: p.is_threat,
            severity: severityFromI8(p.severity),
            layersFired: Int(p.layers_fired),
            layers: .init(l1: p.l1, l2: p.l2, l3: p.l3, l4: p.l4, l5: p.l5, l6: p.l6),
            label: String(cString: p.label),
            confidence: String(cString: p.confidence)
        )
    }

    // MARK: - Sensitive Data Scanner

    struct Finding: Sendable {
        let type: String
        let label: String
        let severity: SeverityLevel
        let category: String
        let source: String
        let matchPreview: String
        let offset: Int
    }

    static func scanSensitiveData(_ text: String, source: String = "unknown") -> [Finding] {
        let ptr = text.withCString { t in
            source.withCString { s in
                sec_scan_sensitive_data(t, s)
            }
        }
        guard let arr = ptr else { return [] }
        defer { sec_free_findings(ptr) }
        let a = arr.pointee
        guard a.count > 0, a.items != nil else { return [] }
        return (0..<Int(a.count)).map { i in
            let f = a.items[i]
            return Finding(
                type: String(cString: f.finding_type),
                label: String(cString: f.label),
                severity: severityFromI8(f.severity) ?? .high,
                category: String(cString: f.category),
                source: String(cString: f.source),
                matchPreview: String(cString: f.match_preview),
                offset: Int(f.offset)
            )
        }
    }

    // MARK: - Prompt Injection

    struct ValidationResult: Sendable {
        let safe: Bool
        let reason: String?
        let severity: SeverityLevel?
        let category: String?
    }

    struct SanitizationResult: Sendable {
        let sanitized: String
        let modified: Bool
        let changes: [String]
    }

    static func validatePrompt(_ text: String, source: String = "unknown") -> ValidationResult {
        let ptr = text.withCString { t in
            source.withCString { s in
                sec_validate_prompt(t, s)
            }
        }
        guard let r = ptr else {
            return ValidationResult(safe: true, reason: nil, severity: nil, category: nil)
        }
        defer { sec_free_validation_result(ptr) }
        let p = r.pointee
        return ValidationResult(
            safe: p.safe,
            reason: optionalString(p.reason),
            severity: severityFromI8(p.severity),
            category: optionalString(p.category)
        )
    }

    static func sanitizeText(_ text: String) -> SanitizationResult {
        let ptr = text.withCString { sec_sanitize_text($0) }
        guard let r = ptr else {
            return SanitizationResult(sanitized: text, modified: false, changes: [])
        }
        defer { sec_free_sanitization_result(ptr) }
        let p = r.pointee
        let changesJSON = String(cString: p.changes_json)
        let changes = (try? JSONDecoder().decode([String].self, from: Data(changesJSON.utf8))) ?? []
        return SanitizationResult(
            sanitized: String(cString: p.sanitized),
            modified: p.modified,
            changes: changes
        )
    }

    // MARK: - File Content Scanner

    struct Threat: Sendable {
        let type: String
        let label: String
        let severity: SeverityLevel
        let category: String
    }

    static func scanFileContent(_ text: String) -> [Threat] {
        let ptr = text.withCString { sec_scan_file_content($0) }
        return threatsFromFFI(ptr)
    }

    // MARK: - Email Analyzer

    static func analyzeEmail(_ text: String) -> [Threat] {
        let ptr = text.withCString { sec_analyze_email($0) }
        return threatsFromFFI(ptr)
    }

    // MARK: - Message Analyzer

    static func analyzeMessage(_ text: String) -> [Threat] {
        let ptr = text.withCString { sec_analyze_message($0) }
        return threatsFromFFI(ptr)
    }

    // MARK: - Helpers

    private static func severityFromI8(_ val: Int8) -> SeverityLevel? {
        switch val {
        case 1: return .low
        case 2: return .medium
        case 3: return .high
        case 4: return .critical
        default: return nil
        }
    }

    private static func optionalString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr = ptr else { return nil }
        return String(cString: ptr)
    }

    private static func threatsFromFFI(_ ptr: UnsafeMutablePointer<ThreatsArrayFFI>?) -> [Threat] {
        guard let arr = ptr else { return [] }
        defer { sec_free_threats(ptr) }
        let a = arr.pointee
        guard a.count > 0, a.items != nil else { return [] }
        return (0..<Int(a.count)).map { i in
            let t = a.items[i]
            return Threat(
                type: String(cString: t.threat_type),
                label: String(cString: t.label),
                severity: severityFromI8(t.severity) ?? .high,
                category: String(cString: t.category)
            )
        }
    }
}
