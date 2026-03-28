import Foundation

/// 7-Layer Intent Scoring Engine — replaces modules/threat-intent-parser.js
///
/// Each layer asks a progressively deeper question about the text's intent.
/// Only content scoring across MULTIPLE layers is treated as a real threat.
///
///  L1  Entity Mention       — Does it mention a threat-relevant entity?
///  L2  Directed At User     — Is it addressed personally to the reader?
///  L3  Authority Claim      — Does it claim to BE that entity?
///  L4  Action Demand        — Does it demand the reader DO something?
///  L5  Urgency Signal       — Is there time pressure or deadline?
///  L6  Fear / Consequence   — Does it threaten a negative outcome?
///  L7  Composite Score      — How many layers fired? → final severity
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

    // MARK: - Layer Patterns

    private let l1Entities: [NSRegularExpression]
    private let l2Directed: [NSRegularExpression]
    private let l3AuthorityClaim: [NSRegularExpression]
    private let l4ActionDemand: [NSRegularExpression]
    private let l5Urgency: [NSRegularExpression]
    private let l6Consequence: [NSRegularExpression]

    init() {
        func compile(_ patterns: [String]) -> [NSRegularExpression] {
            patterns.compactMap { try? NSRegularExpression(pattern: $0, options: .caseInsensitive) }
        }

        // L1 — Entity Mention
        l1Entities = compile([
            #"\b(?:irs|internal\s+revenue|fbi|federal\s+bureau|ssa|social\s+security|doj|department\s+of\s+justice|homeland\s+security|dhs|sec\b|ftc|fdic)\b"#,
            #"\b(?:chase|wells\s+fargo|bank\s+of\s+america|citibank|capital\s+one|us\s+bank|td\s+bank|paypal|zelle|venmo|cashapp|wire\s+transfer)\b"#,
            #"\b(?:apple|icloud|apple\s+id|google|microsoft|amazon|netflix|paypal)\b"#,
            #"\b(?:fedex|ups|usps|dhl|amazon\s+delivery)\b"#,
            #"\b(?:court|warrant|subpoena|lawsuit|litigation|legal\s+action|attorney|counsel)\b"#,
        ])

        // L2 — Directed At User
        l2Directed = compile([
            #"\byour\s+(?:account|card|number|identity|information|records?|case|file|benefits?|ssn|license)\b"#,
            #"\byou\s+(?:must|need\s+to|are\s+required\s+to|have\s+been|owe|will\s+be|may\s+be)\b"#,
            #"\bwe\s+(?:are\s+contacting|have\s+flagged|have\s+detected|are\s+reaching\s+out\s+to)\s+you\b"#,
            #"\byour\s+(?:recent|last|latest)\s+(?:transaction|activity|login|sign[-\s]?in|purchase)\b"#,
            #"\bnotice\s+(?:to|for)\s+(?:you|the\s+account\s+holder)\b"#,
        ])

        // L3 — Authority Claim
        l3AuthorityClaim = compile([
            #"\bthis\s+is\s+(?:the\s+)?(?:irs|fbi|ssa|social\s+security|your\s+bank|apple|microsoft|amazon)\b"#,
            #"\b(?:official|formal)\s+(?:notice|communication|letter|warning)\s+from\b"#,
            #"\bwe\s+(?:are|represent)\s+(?:the\s+)?(?:irs|fbi|ssa|federal|your\s+financial\s+institution)\b"#,
            #"\b(?:on\s+behalf\s+of|acting\s+(?:as|for))\s+(?:the\s+)?(?:irs|fbi|ssa|department|agency|bank)\b"#,
            #"\b(?:agent|officer|investigator|representative|department)\s+(?:id|badge|number|#)\s*:?\s*\d+\b"#,
            #"\byour\s+(?:assigned|case|file)\s+(?:agent|officer|investigator)\b"#,
        ])

        // L4 — Action Demand
        l4ActionDemand = compile([
            #"\b(?:click|tap)\s+(?:here|the\s+link|below)\s+(?:to|now)\b"#,
            #"\b(?:call|contact|reach)\s+(?:us|our\s+(?:team|support|office)|immediately)\s+(?:at|on|now)?\s*(?:\+?[\d\s\-\(\)]{7,})?"#,
            #"\b(?:pay|send|transfer|wire)\s+(?:\$[\d,]+|the\s+(?:amount|balance|fee))\b"#,
            #"\b(?:verify|confirm|update|provide|submit|enter|reply\s+with)\s+your\s+(?:account|identity|information|details|card|ssn|password|pin|code)\b"#,
            #"\b(?:download|open|run|install|execute)\s+(?:the\s+)?(?:attachment|file|document|form|app)\b"#,
            #"\b(?:do\s+not\s+ignore|must\s+respond|required\s+to\s+(?:respond|act|comply))\b"#,
        ])

        // L5 — Urgency Signal
        l5Urgency = compile([
            #"\bwithin\s+(?:\d+\s+)?(?:hours?|minutes?|days?|business\s+days?)\b"#,
            #"\b(?:immediately|urgently|right\s+away|right\s+now|as\s+soon\s+as\s+possible|asap)\b"#,
            #"\b(?:final|last|urgent|immediate)\s+(?:notice|warning|reminder|chance|opportunity)\b"#,
            #"\b(?:expires?|expiring)\s+(?:today|tonight|soon|in\s+\d+\s+hours?)\b"#,
            #"\b(?:deadline|time[-\s]sensitive|time\s+is\s+running\s+out|do\s+not\s+delay)\b"#,
            #"\b(?:today\s+only|limited\s+time|act\s+now|respond\s+now|call\s+now)\b"#,
        ])

        // L6 — Fear / Consequence
        l6Consequence = compile([
            #"\b(?:arrest|arrested|detain|detained|taken\s+into\s+custody)\b"#,
            #"\b(?:suspend|suspended|termina(?:te|ted)|cancel(?:led)?|clos(?:e|ed))\s+your\s+(?:account|card|number|access|service|benefits?)\b"#,
            #"\b(?:legal|criminal|civil)\s+(?:action|charges?|proceedings?|penalty|penalties)\b"#,
            #"\b(?:lawsuit|sued|prosecution|prosecuted|indicted|indictment)\b"#,
            #"\b(?:freeze|frozen|block(?:ed)?)\s+(?:your\s+)?(?:account|funds?|assets?|card)\b"#,
            #"\bpenalt(?:y|ies)\s+(?:of|including|up\s+to)\s+\$[\d,]+\b"#,
            #"\b(?:lose|forfeit|seize|seized)\s+(?:your\s+)?(?:account|assets?|funds?|property|license)\b"#,
            #"\bfailure\s+to\s+(?:comply|respond|pay|act|verify)\s+(?:will|may|could|shall)\b"#,
        ])
    }

    // MARK: - Parse

    func parse(_ text: String, channel: Channel = .email) -> IntentResult {
        guard !text.isEmpty else { return cleanResult() }

        let lower = text.lowercased()

        let l1 = score(lower, l1Entities)
        let l2 = score(lower, l2Directed)
        let l3 = score(lower, l3AuthorityClaim)
        let l4 = score(lower, l4ActionDemand)
        let l5 = score(lower, l5Urgency)
        let l6 = score(lower, l6Consequence)

        let layers = Layers(l1: l1, l2: l2, l3: l3, l4: l4, l5: l5, l6: l6)
        let fired = [l1, l2, l3, l4, l5, l6].filter { $0 }.count

        var severity: SeverityLevel?
        var isThreat = false

        if fired >= 5 { severity = .critical; isThreat = true }
        else if fired >= 4 { severity = .high; isThreat = true }
        else if fired >= 3 { severity = .medium; isThreat = true }
        else if fired >= 2 { severity = .low; isThreat = false }

        // SMS boost — scammers use less text
        if channel == .sms && fired >= 4 { severity = .critical }

        return IntentResult(
            isThreat: isThreat,
            severity: severity,
            layersFired: fired,
            layers: layers,
            label: makeLabel(layers),
            confidence: "\(Int(round(Double(fired) / 6.0 * 100)))%"
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

    // MARK: - Private

    private func score(_ text: String, _ patterns: [NSRegularExpression]) -> Bool {
        let nsText = text as NSString
        let range = NSRange(location: 0, length: nsText.length)
        return patterns.contains { $0.firstMatch(in: text, range: range) != nil }
    }

    private func cleanResult() -> IntentResult {
        IntentResult(
            isThreat: false, severity: nil, layersFired: 0,
            layers: Layers(l1: false, l2: false, l3: false, l4: false, l5: false, l6: false),
            label: "Clean", confidence: "0%"
        )
    }

    private func makeLabel(_ layers: Layers) -> String {
        var parts: [String] = []
        if layers.l1 { parts.append("Entity") }
        if layers.l2 { parts.append("Directed-at-user") }
        if layers.l3 { parts.append("Authority-claim") }
        if layers.l4 { parts.append("Action-demand") }
        if layers.l5 { parts.append("Urgency") }
        if layers.l6 { parts.append("Fear/consequence") }
        return parts.isEmpty ? "Clean" : parts.joined(separator: " + ")
    }
}
