import Foundation

/// 7-Layer Weighted Intent Scoring Engine — backed by Rust security-core via FFI.
///
/// Layers are hierarchical by harm potential:
///   L1 Credential Harvest (25pt) — asks for passwords, SSN, CC, seed phrases
///   L2 Sender Deception (20pt) — typosquatted domains, free-email impersonation
///   L3 Dangerous Action (20pt) — wire transfers, gift cards, crypto payments, secrecy
///   L4 Weaponized Links (15pt) — IP-based URLs, credential-harvesting paths
///   L5 Threat/Extortion (10pt) — account suspension, arrest, legal threats
///   L6 Urgency Pressure (5pt) — deadlines, "act now"
///   L7 Impersonation Context (5pt) — claims to be IRS/FBI/SSA
///
/// Threshold: 70/100 for email, 50/100 for SMS.
/// Key insight: newsletters trigger L5-L7 (max 20pt = safe), phishers need L1-L4.
final class ThreatIntentParser: Sendable {

    enum Channel: Sendable {
        case email
        case sms
    }

    struct IntentResult: Sendable {
        let isThreat: Bool
        let severity: SeverityLevel?
        let layersFired: Int
        let score: Int  // weighted score out of 100
        let layers: Layers
        let label: String
        let confidence: String
    }

    struct Layers: Sendable {
        let l1: Bool // Credential harvest (25pt)
        let l2: Bool // Sender deception (20pt)
        let l3: Bool // Dangerous action (20pt)
        let l4: Bool // Weaponized links (15pt)
        let l5: Bool // Threat/extortion (10pt)
        let l6: Bool // Urgency pressure (5pt)
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
            score: r.score,
            layers: Layers(l1: r.layers.l1, l2: r.layers.l2, l3: r.layers.l3,
                           l4: r.layers.l4, l5: r.layers.l5, l6: r.layers.l6),
            label: r.label,
            confidence: r.confidence
        )
    }

    func explain(_ text: String, channel: Channel = .email) -> String {
        let result = parse(text, channel: channel)
        return """
        Intent analysis (score: \(result.score)/100, \(result.layersFired)/7 layers):
          L1 Credential harvest:   \(result.layers.l1 ? "YES (25pt)" : "no")
          L2 Sender deception:     \(result.layers.l2 ? "YES (20pt)" : "no")
          L3 Dangerous action:     \(result.layers.l3 ? "YES (20pt)" : "no")
          L4 Weaponized links:     \(result.layers.l4 ? "YES (15pt)" : "no")
          L5 Threat/extortion:     \(result.layers.l5 ? "YES (10pt)" : "no")
          L6 Urgency pressure:     \(result.layers.l6 ? "YES (5pt)"  : "no")
          Verdict: \(result.severity?.rawValue ?? "CLEAN") — \(result.label)
        """
    }
}
