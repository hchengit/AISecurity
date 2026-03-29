import Foundation

/// 7-Layer Intent Scoring Engine — now backed by Rust security-core via FFI.
///
/// Each layer asks a progressively deeper question about the text's intent.
/// Only content scoring across MULTIPLE layers is treated as a real threat.
final class ThreatIntentParser: Sendable {

    enum Channel: Sendable {
        case email
        case sms
    }

    struct IntentResult: Sendable {
        let isThreat: Bool
        let severity: SeverityLevel?
        let layersFired: Int
        let layers: Layers
        let label: String
        let confidence: String
    }

    struct Layers: Sendable {
        let l1: Bool // Entity mention
        let l2: Bool // Directed at user
        let l3: Bool // Authority claim
        let l4: Bool // Action demand
        let l5: Bool // Urgency
        let l6: Bool // Fear / consequence
    }

    init() {}

    // MARK: - Parse (delegates to Rust)

    func parse(_ text: String, channel: Channel = .email) -> IntentResult {
        let ch: SecurityCoreBridge.Channel = (channel == .sms) ? .sms : .email
        let r = SecurityCoreBridge.parseIntent(text, channel: ch)
        return IntentResult(
            isThreat: r.isThreat,
            severity: r.severity,
            layersFired: r.layersFired,
            layers: Layers(l1: r.layers.l1, l2: r.layers.l2, l3: r.layers.l3,
                           l4: r.layers.l4, l5: r.layers.l5, l6: r.layers.l6),
            label: r.label,
            confidence: r.confidence
        )
    }

    func explain(_ text: String, channel: Channel = .email) -> String {
        let result = parse(text, channel: channel)
        return """
        Intent analysis (\(result.confidence) confidence, \(result.layersFired)/6 layers):
          L1 Entity mention:    \(result.layers.l1 ? "Y" : "N")
          L2 Directed at user:  \(result.layers.l2 ? "Y" : "N")
          L3 Authority claim:   \(result.layers.l3 ? "Y" : "N")
          L4 Action demand:     \(result.layers.l4 ? "Y" : "N")
          L5 Urgency signal:    \(result.layers.l5 ? "Y" : "N")
          L6 Fear/consequence:  \(result.layers.l6 ? "Y" : "N")
          L7 Verdict:           \(result.severity?.rawValue ?? "CLEAN") — \(result.label)
        """
    }
}
