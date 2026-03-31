import Foundation

/// Sends security alerts to Discord via webhook.
enum DiscordChannel {

    /// Send a security alert to Discord.
    static func send(_ alert: SecurityAlert, config: NotificationConfig.DiscordConfig,
                     completion: @escaping (Bool, String?) -> Void) {
        guard !config.webhookUrl.isEmpty else {
            completion(false, "Discord not configured")
            return
        }

        let embed = buildEmbed(alert)
        let body: [String: Any] = [
            "username": "AISecurity",
            "embeds": [embed]
        ]

        post(webhookUrl: config.webhookUrl, body: body, completion: completion)
    }

    /// Send a test message.
    static func sendTest(config: NotificationConfig.DiscordConfig,
                         completion: @escaping (Bool, String?) -> Void) {
        guard !config.webhookUrl.isEmpty else {
            completion(false, "Webhook URL is required")
            return
        }

        let embed: [String: Any] = [
            "title": "\u{1F6E1} AISecurity Test",
            "description": "This is a test notification from AISecurity.\nIf you see this, Discord is configured correctly!",
            "color": 3066993, // green
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]

        let body: [String: Any] = [
            "username": "AISecurity",
            "embeds": [embed]
        ]

        post(webhookUrl: config.webhookUrl, body: body, completion: completion)
    }

    // MARK: - Embed Builder

    private static func buildEmbed(_ alert: SecurityAlert) -> [String: Any] {
        var fields: [[String: Any]] = []

        if let filePath = alert.filePath {
            fields.append(["name": "\u{1F4C1} File", "value": "`\((filePath as NSString).lastPathComponent)`", "inline": true])
        }

        fields.append(["name": "\u{1F534} Severity", "value": alert.severity.rawValue.uppercased(), "inline": true])

        if let findings = alert.findings, !findings.isEmpty {
            let list = findings.map { "\u{2022} \($0.label)" }.joined(separator: "\n")
            fields.append(["name": "\u{1F50D} Details", "value": list, "inline": false])
        }

        if let threats = alert.threats, !threats.isEmpty {
            let list = threats.map { "\u{2022} \($0.label) (\($0.category))" }.joined(separator: "\n")
            fields.append(["name": "\u{26A0}\u{FE0F} Threats", "value": list, "inline": false])
        }

        var embed: [String: Any] = [
            "title": "\(severityEmoji(alert.severity)) \(alert.type)",
            "description": alert.message,
            "color": severityColor(alert.severity),
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "footer": ["text": "AISecurity \u{2022} \(alert.type)"]
        ]

        if !fields.isEmpty {
            embed["fields"] = fields
        }

        return embed
    }

    private static func severityEmoji(_ severity: SeverityLevel) -> String {
        switch severity {
        case .critical: return "\u{1F6A8}"
        case .high: return "\u{26A0}\u{FE0F}"
        case .medium: return "\u{2139}\u{FE0F}"
        case .low: return "\u{2705}"
        }
    }

    private static func severityColor(_ severity: SeverityLevel) -> Int {
        switch severity {
        case .critical: return 0xFF0000   // red
        case .high:     return 0xFFA500   // orange
        case .medium:   return 0xFFFF00   // yellow
        case .low:      return 0x00FF00   // green
        }
    }

    // MARK: - HTTP

    private static func post(webhookUrl: String, body: [String: Any],
                             completion: @escaping (Bool, String?) -> Void) {
        guard let url = URL(string: webhookUrl) else {
            completion(false, "Invalid webhook URL")
            return
        }

        // Security: Only allow HTTPS URLs to prevent SSRF and credential leakage
        guard url.scheme?.lowercased() == "https" else {
            completion(false, "Only HTTPS webhook URLs are allowed")
            return
        }
        // Block localhost/internal addresses
        if let host = url.host?.lowercased(),
           host == "localhost" || host.hasPrefix("127.") || host.hasPrefix("10.")
           || host.hasPrefix("192.168.") || host == "0.0.0.0" || host == "::1" {
            completion(false, "Local/internal webhook URLs are not allowed")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        guard let jsonData = try? JSONSerialization.data(withJSONObject: body) else {
            completion(false, "JSON serialization failed")
            return
        }
        request.httpBody = jsonData

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(false, error.localizedDescription)
                return
            }
            guard let http = response as? HTTPURLResponse else {
                completion(false, "No HTTP response")
                return
            }
            // Discord returns 204 No Content on success
            if http.statusCode == 204 || http.statusCode == 200 {
                completion(true, nil)
            } else {
                let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? "unknown"
                completion(false, "HTTP \(http.statusCode): \(body)")
            }
        }.resume()
    }
}
