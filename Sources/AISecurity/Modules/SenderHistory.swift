import Foundation

/// Tracks sender domain frequency to distinguish trusted repeat senders from first-contact threats.
///
/// Key insight: if americanexpress.com has sent 200 clean emails, their threat score becomes
/// irrelevant. But a first-contact sender with urgency + credential request is highly suspicious.
///
/// Stored as JSON in ~/.mac-security/sender-history.json, keyed by normalized domain.
final class SenderHistory: @unchecked Sendable {

    // MARK: - Types

    enum TrustLevel: Sendable {
        /// 10+ clean emails, <5% threat rate — suppress intent-only alerts
        case trusted
        /// 3+ emails seen — normal scoring
        case known
        /// Never seen before — apply first-contact heuristics
        case unknown
        /// >20% threat rate — never suppress
        case suspicious
    }

    struct SenderRecord: Codable {
        var domain: String
        var totalSeen: Int
        var cleanCount: Int
        var threatCount: Int
        var firstSeen: TimeInterval
        var lastSeen: TimeInterval
    }

    // MARK: - Properties

    private var records: [String: SenderRecord] = [:]  // domain → record
    private let lock = NSLock()
    private let filePath: String
    private let maxDomains = 5000
    private var isDirty = false

    // MARK: - Init

    init(securityDir: String) {
        self.filePath = (securityDir as NSString).appendingPathComponent("sender-history.json")
        load()
    }

    // MARK: - Public API

    /// Record that an email was scanned from this domain.
    func recordScan(domain: String, hadThreat: Bool) {
        let normalized = domain.lowercased()
        guard !normalized.isEmpty else { return }

        lock.lock()
        defer { lock.unlock() }

        let now = Date().timeIntervalSince1970
        if var record = records[normalized] {
            record.totalSeen += 1
            if hadThreat {
                record.threatCount += 1
            } else {
                record.cleanCount += 1
            }
            record.lastSeen = now
            records[normalized] = record
        } else {
            records[normalized] = SenderRecord(
                domain: normalized,
                totalSeen: 1,
                cleanCount: hadThreat ? 0 : 1,
                threatCount: hadThreat ? 1 : 0,
                firstSeen: now,
                lastSeen: now
            )
        }
        isDirty = true
    }

    /// Get the trust level for a sender domain.
    func trustLevel(for domain: String) -> TrustLevel {
        let normalized = domain.lowercased()
        lock.lock()
        let record = records[normalized]
        lock.unlock()

        guard let r = record else { return .unknown }

        // Suspicious: >20% threat rate with enough samples
        if r.totalSeen >= 5 && r.threatCount > 0 {
            let threatRate = Double(r.threatCount) / Double(r.totalSeen)
            if threatRate > 0.20 {
                return .suspicious
            }
        }

        // Trusted: 10+ clean emails, <5% threat rate
        if r.cleanCount >= 10 {
            let threatRate = r.totalSeen > 0 ? Double(r.threatCount) / Double(r.totalSeen) : 0
            if threatRate < 0.05 {
                return .trusted
            }
        }

        // Known: 3+ emails seen
        if r.totalSeen >= 3 {
            return .known
        }

        return .unknown
    }

    /// Get record for a domain (for logging/debugging).
    func record(for domain: String) -> SenderRecord? {
        lock.lock()
        defer { lock.unlock() }
        return records[domain.lowercased()]
    }

    /// Number of tracked domains.
    var domainCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return records.count
    }

    // MARK: - Persistence

    /// Save to disk if there are pending changes. Call after each scan batch.
    func persistIfDirty() {
        lock.lock()
        guard isDirty else {
            lock.unlock()
            return
        }
        isDirty = false

        // Prune if over limit — remove oldest domains
        if records.count > maxDomains {
            let sorted = records.values.sorted { $0.lastSeen < $1.lastSeen }
            let toRemove = records.count - maxDomains
            for record in sorted.prefix(toRemove) {
                records.removeValue(forKey: record.domain)
            }
        }

        let snapshot = records
        lock.unlock()

        // Write outside lock
        if let data = try? JSONEncoder().encode(snapshot) {
            try? data.write(to: URL(fileURLWithPath: filePath))
        }
    }

    private func load() {
        guard let data = FileManager.default.contents(atPath: filePath),
              let dict = try? JSONDecoder().decode([String: SenderRecord].self, from: data) else {
            return
        }
        records = dict
    }
}
