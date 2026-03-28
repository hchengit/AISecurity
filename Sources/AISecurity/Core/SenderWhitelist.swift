import Foundation

/// Manages sender whitelist — trusted senders skip low-confidence checks
/// but ALWAYS get scanned for malicious attachments, URLs, malware, and prompt injection.
///
/// Industry standard (Gmail, Outlook, Proofpoint): whitelisting reduces noise
/// from social engineering/urgency alerts but never bypasses malware scanning.
final class SenderWhitelist: @unchecked Sendable {

    // MARK: - Types

    struct Entry: Codable, Sendable {
        let address: String           // exact address or @domain
        let source: Source
        let addedAt: String           // ISO8601
        var note: String?

        enum Source: String, Codable, Sendable {
            case userExplicit = "user"
            case contactsSync = "contacts"
        }
    }

    /// Scan policy for a sender based on whitelist status
    struct ScanPolicy: Sendable {
        let isWhitelisted: Bool

        /// Categories that should ALWAYS fire regardless of whitelist
        static let alwaysScanCategories: Set<String> = [
            "malicious_url", "dangerous_attachment", "malware_dropper",
            "prompt_injection", "crypto_scam"
        ]

        /// Categories suppressed for whitelisted senders
        static let suppressedCategories: Set<String> = [
            "social_engineering", "authority_impersonation"
        ]

        /// Categories with raised threshold for whitelisted senders
        static let reducedCategories: Set<String> = [
            "phishing", "sensitive_data_request"
        ]

        /// Should this threat category fire for this sender?
        func shouldAlert(category: String, intentLayers: Int) -> Bool {
            // Always-scan categories fire regardless
            if Self.alwaysScanCategories.contains(category) { return true }

            // Unknown senders — everything fires
            if !isWhitelisted { return true }

            // Whitelisted: suppress social engineering / authority impersonation
            if Self.suppressedCategories.contains(category) { return false }

            // Whitelisted: raise threshold for reduced categories (need 5+ layers)
            if Self.reducedCategories.contains(category) {
                return intentLayers >= 5
            }

            // All other categories: fire normally
            return true
        }
    }

    // MARK: - Properties

    private var entries: [String: Entry] = [:]   // lowercased address → entry
    private let filePath: String
    private let lock = NSLock()

    /// Freemail domains that cannot be whitelisted at domain level
    private static let freemailDomains: Set<String> = [
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
        "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com",
        "protonmail.com", "proton.me", "zoho.com", "mail.com", "gmx.com", "yandex.com"
    ]

    // MARK: - Init

    init(securityDir: String) {
        self.filePath = (securityDir as NSString).appendingPathComponent("whitelist.json")
        load()
    }

    // MARK: - Public API

    /// Check if a sender address is whitelisted
    func policy(for sender: String) -> ScanPolicy {
        let addr = extractAddress(sender).lowercased()
        lock.lock()
        defer { lock.unlock() }

        // Check exact address match
        if entries[addr] != nil {
            return ScanPolicy(isWhitelisted: true)
        }

        // Check domain match
        if let atIdx = addr.firstIndex(of: "@") {
            let domain = String(addr[addr.index(after: atIdx)...])
            if entries["@" + domain] != nil {
                return ScanPolicy(isWhitelisted: true)
            }
        }

        return ScanPolicy(isWhitelisted: false)
    }

    /// Add a sender to the whitelist
    @discardableResult
    func add(_ sender: String, source: Entry.Source = .userExplicit, note: String? = nil) -> Bool {
        let addr = extractAddress(sender).lowercased()
        guard !addr.isEmpty else { return false }

        // Block domain-level whitelist for freemail providers
        if addr.hasPrefix("@") {
            let domain = String(addr.dropFirst())
            if Self.freemailDomains.contains(domain) { return false }
        }

        let entry = Entry(
            address: addr,
            source: source,
            addedAt: ISO8601DateFormatter().string(from: Date()),
            note: note
        )

        lock.lock()
        entries[addr] = entry
        lock.unlock()
        save()
        return true
    }

    /// Remove a sender from the whitelist
    func remove(_ sender: String) {
        let addr = extractAddress(sender).lowercased()
        lock.lock()
        entries.removeValue(forKey: addr)
        lock.unlock()
        save()
    }

    /// Get all whitelist entries
    func allEntries() -> [Entry] {
        lock.lock()
        defer { lock.unlock() }
        return Array(entries.values).sorted { $0.addedAt > $1.addedAt }
    }

    /// Check if a sender is whitelisted
    func isWhitelisted(_ sender: String) -> Bool {
        policy(for: sender).isWhitelisted
    }

    // MARK: - Persistence

    private func load() {
        guard let data = FileManager.default.contents(atPath: filePath),
              let arr = try? JSONDecoder().decode([Entry].self, from: data) else { return }
        lock.lock()
        for entry in arr {
            entries[entry.address.lowercased()] = entry
        }
        lock.unlock()
    }

    private func save() {
        lock.lock()
        let arr = Array(entries.values)
        lock.unlock()
        if let data = try? JSONEncoder().encode(arr) {
            try? data.write(to: URL(fileURLWithPath: filePath))
        }
    }

    // MARK: - Helpers

    /// Extract bare email address from "Name <email@example.com>" format
    private func extractAddress(_ sender: String) -> String {
        if let start = sender.firstIndex(of: "<"),
           let end = sender.firstIndex(of: ">") {
            return String(sender[sender.index(after: start)..<end])
        }
        return sender.trimmingCharacters(in: .whitespaces)
    }
}
