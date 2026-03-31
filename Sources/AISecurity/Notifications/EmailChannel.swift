import Foundation

/// Sends security alerts via Gmail SMTP using curl.
/// Uses Gmail App Password for authentication (requires 2FA enabled on Google account).
enum EmailChannel {

    /// Send a security alert email.
    static func send(_ alert: SecurityAlert, config: NotificationConfig.EmailConfig,
                     completion: @escaping (Bool, String?) -> Void) {
        guard !config.userEmail.isEmpty, !config.appPassword.isEmpty else {
            completion(false, "Email not configured")
            return
        }

        let subject = sanitizeHeader("\(severityEmoji(alert.severity)) AISecurity: \(alert.type)")
        let htmlBody = buildHTML(alert)
        let plainBody = buildPlainText(alert)

        sendMail(to: config.userEmail, from: config.userEmail,
                 password: config.appPassword,
                 subject: subject, html: htmlBody, plain: plainBody,
                 completion: completion)
    }

    /// Send a test email.
    static func sendTest(config: NotificationConfig.EmailConfig,
                         completion: @escaping (Bool, String?) -> Void) {
        guard !config.userEmail.isEmpty, !config.appPassword.isEmpty else {
            completion(false, "Email address and App Password are required")
            return
        }

        let subject = "\u{1F6E1} AISecurity Test Notification"
        let html = """
        <html><body style="font-family: -apple-system, sans-serif; padding: 20px;">
        <h2>\u{1F6E1} AISecurity Test</h2>
        <p>This is a test notification from AISecurity.</p>
        <p>If you received this email, your notification settings are configured correctly!</p>
        <p style="color: #888; font-size: 12px;">Sent at \(Date())</p>
        </body></html>
        """
        let plain = "AISecurity Test\n\nThis is a test notification. Email is configured correctly!\n\nSent at \(Date())"

        sendMail(to: config.userEmail, from: config.userEmail,
                 password: config.appPassword,
                 subject: subject, html: html, plain: plain,
                 completion: completion)
    }

    // MARK: - Email Body Builders

    private static func buildHTML(_ alert: SecurityAlert) -> String {
        let sevColor = severityHTMLColor(alert.severity)
        let sevLabel = alert.severity.rawValue.uppercased()
        let sevEmoji = severityEmoji(alert.severity)

        var findingsHTML = ""
        if let findings = alert.findings, !findings.isEmpty {
            let items = findings.map { "<li>\($0.label)</li>" }.joined()
            findingsHTML = """
            <div style="margin: 15px 0; padding: 12px; background: #f8f9fa; border-radius: 5px;">
            <h4 style="margin:0 0 8px 0; font-size:14px;">\u{1F50D} Details</h4>
            <ul style="margin:0; padding-left:20px; color:#555;">\(items)</ul>
            </div>
            """
        }

        var threatsHTML = ""
        if let threats = alert.threats, !threats.isEmpty {
            let items = threats.map { "<li>\($0.label) (\($0.category))</li>" }.joined()
            threatsHTML = """
            <div style="margin: 15px 0; padding: 12px; background: #fff3e0; border-radius: 5px; border-left: 4px solid #ff9800;">
            <h4 style="margin:0 0 8px 0; font-size:14px;">\u{26A0}\u{FE0F} Threats</h4>
            <ul style="margin:0; padding-left:20px; color:#555;">\(items)</ul>
            </div>
            """
        }

        let fileHTML = alert.filePath.map {
            "<p style=\"font-size:14px;\"><strong>\u{1F4C1} File:</strong> <code>\($0)</code></p>"
        } ?? ""

        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium

        return """
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"></head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 0;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 25px; border-radius: 10px 10px 0 0; text-align: center;">
            <h1 style="margin: 0; color: white; font-size: 22px;">\u{1F6E1} AISecurity Alert</h1>
          </div>
          <div style="background: white; padding: 25px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <span style="display:inline-block; padding: 5px 14px; background: \(sevColor); color: white; border-radius: 20px; font-size: 12px; font-weight: bold;">
              \(sevEmoji) \(sevLabel)
            </span>
            <h2 style="margin: 15px 0 10px; font-size: 20px; color: #333;">\(escapeHTML(alert.type))</h2>
            <p style="font-size: 15px; color: #555; line-height: 1.5;">\(escapeHTML(alert.message))</p>
            \(findingsHTML)
            \(threatsHTML)
            \(fileHTML)
          </div>
          <div style="margin-top: 15px; text-align: center; color: #888; font-size: 12px;">
            <p>AISecurity \u{2022} \(formatter.string(from: Date()))</p>
          </div>
        </div>
        </body></html>
        """
    }

    private static func buildPlainText(_ alert: SecurityAlert) -> String {
        var lines = [
            "AISecurity Alert - \(alert.severity.rawValue.uppercased())",
            String(repeating: "\u{2501}", count: 40),
            alert.type,
            "",
            alert.message
        ]

        if let findings = alert.findings, !findings.isEmpty {
            lines.append("")
            lines.append("Details:")
            for f in findings { lines.append("  \u{2022} \(f.label)") }
        }

        if let threats = alert.threats, !threats.isEmpty {
            lines.append("")
            lines.append("Threats:")
            for t in threats { lines.append("  \u{2022} \(t.label) (\(t.category))") }
        }

        if let filePath = alert.filePath {
            lines.append("")
            lines.append("File: \(filePath)")
        }

        lines.append("")
        lines.append(String(repeating: "\u{2501}", count: 40))
        lines.append("Sent at \(Date())")

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

    private static func severityHTMLColor(_ severity: SeverityLevel) -> String {
        switch severity {
        case .critical: return "#dc2626"
        case .high:     return "#ea580c"
        case .medium:   return "#ca8a04"
        case .low:      return "#22c55e"
        }
    }

    // MARK: - Header Sanitization

    /// Strip CR/LF from header values to prevent email header injection.
    private static func sanitizeHeader(_ value: String) -> String {
        value.replacingOccurrences(of: "\r", with: "")
             .replacingOccurrences(of: "\n", with: " ")
    }

    /// Sanitize content for safe inclusion in email body — escape HTML entities.
    private static func escapeHTML(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }

    // MARK: - SMTP via curl

    private static func sendMail(to: String, from: String, password: String,
                                 subject: String, html: String, plain: String,
                                 completion: @escaping (Bool, String?) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            // Build RFC 2822 MIME message
            let boundary = "AISecurity-\(UUID().uuidString)"
            let safeFrom = sanitizeHeader(from)
            let safeTo = sanitizeHeader(to)
            let safeSubject = sanitizeHeader(subject)
            let message = """
            From: "AISecurity" <\(safeFrom)>
            To: \(safeTo)
            Subject: \(safeSubject)
            MIME-Version: 1.0
            Content-Type: multipart/alternative; boundary="\(boundary)"

            --\(boundary)
            Content-Type: text/plain; charset=UTF-8

            \(plain)

            --\(boundary)
            Content-Type: text/html; charset=UTF-8

            \(html)

            --\(boundary)--
            """

            // Write message to temp file for curl
            let tmpFile = NSTemporaryDirectory() + "aisec-mail-\(UUID().uuidString).eml"
            do {
                try message.write(toFile: tmpFile, atomically: true, encoding: .utf8)
            } catch {
                completion(false, "Failed to write temp file: \(error.localizedDescription)")
                return
            }
            defer { try? FileManager.default.removeItem(atPath: tmpFile) }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
            process.arguments = [
                "--silent", "--show-error",
                "--url", "smtps://smtp.gmail.com:465",
                "--ssl-reqd",
                "--mail-from", from,
                "--mail-rcpt", to,
                "--upload-file", tmpFile,
                "--user", "\(from):\(password)"
            ]

            let errPipe = Pipe()
            process.standardOutput = FileHandle.nullDevice
            process.standardError = errPipe

            do {
                try process.run()
                process.waitUntilExit()

                if process.terminationStatus == 0 {
                    completion(true, nil)
                } else {
                    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                    let errMsg = String(data: errData, encoding: .utf8) ?? "curl exit \(process.terminationStatus)"
                    completion(false, errMsg)
                }
            } catch {
                completion(false, error.localizedDescription)
            }
        }
    }
}
