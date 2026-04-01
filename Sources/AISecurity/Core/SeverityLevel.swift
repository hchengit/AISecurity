import Foundation

/// Threat severity levels — matches the Node.js CRITICAL/HIGH/MEDIUM/LOW system.
enum SeverityLevel: String, Codable, Comparable, CaseIterable, Sendable {
    case critical = "CRITICAL"
    case high     = "HIGH"
    case medium   = "MEDIUM"
    case low      = "LOW"

    var rank: Int {
        switch self {
        case .critical: return 4
        case .high:     return 3
        case .medium:   return 2
        case .low:      return 1
        }
    }

    static func < (lhs: SeverityLevel, rhs: SeverityLevel) -> Bool {
        lhs.rank < rhs.rank
    }
}

/// A single security finding from any module.
struct SecurityAlert: Codable, Sendable {
    let type: String
    let severity: SeverityLevel
    let message: String
    let timestamp: String
    var filePath: String?
    var from: String?
    var to: String?
    var subject: String?
    var threats: [ThreatDetail]?
    var findings: [FindingDetail]?
    var preview: String?
    var sender: String?
    var category: String?

    init(
        type: String,
        severity: SeverityLevel,
        message: String,
        filePath: String? = nil,
        from: String? = nil,
        to: String? = nil,
        subject: String? = nil,
        threats: [ThreatDetail]? = nil,
        findings: [FindingDetail]? = nil,
        preview: String? = nil,
        sender: String? = nil,
        category: String? = nil
    ) {
        self.type = type
        self.severity = severity
        self.message = message
        let f = ISO8601DateFormatter()
        f.timeZone = .current
        self.timestamp = f.string(from: Date())
        self.filePath = filePath
        self.from = from
        self.to = to
        self.subject = subject
        self.threats = threats
        self.findings = findings
        self.preview = preview
        self.sender = sender
        self.category = category
    }
}

struct ThreatDetail: Codable, Sendable {
    let label: String
    let category: String
    let severity: SeverityLevel
}

struct FindingDetail: Codable, Sendable {
    let label: String
    let category: String
    let severity: SeverityLevel
}
