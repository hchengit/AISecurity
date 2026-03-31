import Foundation

/// Sends security alerts to Telegram via the Bot API.
enum TelegramChannel {

    /// Send a security alert to Telegram.
    static func send(_ alert: SecurityAlert, config: NotificationConfig.TelegramConfig,
                     completion: @escaping (Bool, String?) -> Void) {
        guard !config.botToken.isEmpty, !config.chatId.isEmpty else {
            completion(false, "Telegram not configured")
            return
        }

        let text = formatMessage(alert)
        let body: [String: Any] = [
            "chat_id": config.chatId,
            "text": text,
            "parse_mode": "MarkdownV2"
        ]

        post(token: config.botToken, method: "sendMessage", body: body, completion: completion)
    }

    /// Send a test message.
    static func sendTest(config: NotificationConfig.TelegramConfig,
                         completion: @escaping (Bool, String?) -> Void) {
        guard !config.botToken.isEmpty, !config.chatId.isEmpty else {
            completion(false, "Bot Token and Chat ID are required")
            return
        }

        let text = esc("\u{1F6E1} AISecurity Test\n\nThis is a test notification from AISecurity.\nIf you see this, Telegram is configured correctly!")
        let body: [String: Any] = [
            "chat_id": config.chatId,
            "text": text,
            "parse_mode": "MarkdownV2"
        ]

        post(token: config.botToken, method: "sendMessage", body: body, completion: completion)
    }

    // MARK: - Message Formatting

    private static func formatMessage(_ alert: SecurityAlert) -> String {
        var lines: [String] = []

        lines.append("\u{1F6E1} *AISecurity Alert*")
        lines.append("\(severityEmoji(alert.severity)) *\(esc(alert.severity.rawValue.uppercased()))*")
        lines.append("")
        lines.append("\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}")
        lines.append("")
        lines.append("\u{1F4CB} *What Happened:*")
        lines.append(esc(alert.message))

        if let findings = alert.findings, !findings.isEmpty {
            lines.append("")
            lines.append("\u{1F50D} *Details:*")
            for f in findings {
                lines.append("\u{2022} \(esc(f.label))")
            }
        }

        if let threats = alert.threats, !threats.isEmpty {
            lines.append("")
            lines.append("\u{26A0}\u{FE0F} *Threats:*")
            for t in threats {
                lines.append("\u{2022} \(esc(t.label)) \\(\(esc(t.category))\\)")
            }
        }

        if let filePath = alert.filePath {
            lines.append("")
            lines.append("\u{1F4C1} *File:* `\(esc(filePath))`")
        }

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        lines.append("\u{23F0} *Time:* \(esc(formatter.string(from: Date())))")

        return lines.joined(separator: "\n")
    }

    private static func severityEmoji(_ severity: SeverityLevel) -> String {
        switch severity {
        case .critical: return "\u{1F6A8}"
        case .high: return "\u{26A0}\u{FE0F}"
        case .medium: return "\u{2139}\u{FE0F}"
        case .low: return "\u{2705}"
        }
    }

    /// Escape MarkdownV2 special characters.
    private static func esc(_ text: String) -> String {
        let specials = #"_*[]()~`>#+-=|{}.!\\"#
        var result = ""
        for ch in text {
            if specials.contains(ch) {
                result.append("\\")
            }
            result.append(ch)
        }
        return result
    }

    // MARK: - HTTP

    private static func post(token: String, method: String, body: [String: Any],
                             completion: @escaping (Bool, String?) -> Void) {
        // URL-encode token and method to prevent path traversal
        guard let safeToken = token.addingPercentEncoding(withAllowedCharacters: .alphanumerics),
              let safeMethod = method.addingPercentEncoding(withAllowedCharacters: .alphanumerics) else {
            completion(false, "Invalid token or method format")
            return
        }
        let urlString = "https://api.telegram.org/bot\(safeToken)/\(safeMethod)"
        guard let url = URL(string: urlString) else {
            completion(false, "Invalid URL")
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
            if http.statusCode == 200 {
                completion(true, nil)
            } else {
                let body = data.flatMap { String(data: $0, encoding: .utf8) } ?? "unknown"
                completion(false, "HTTP \(http.statusCode): \(body)")
            }
        }.resume()
    }
}
