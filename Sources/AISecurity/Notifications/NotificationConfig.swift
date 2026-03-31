import Foundation

/// Persists external notification channel credentials to JSON.
/// Stored at `~/.mac-security/notification-config.json`.
final class NotificationConfig {

    static let shared = NotificationConfig()

    private let configPath: String
    private(set) var telegram: TelegramConfig
    private(set) var discord: DiscordConfig
    private(set) var email: EmailConfig

    struct TelegramConfig: Codable {
        var botToken: String
        var chatId: String
        var enabled: Bool
        var updatedAt: String?
    }

    struct DiscordConfig: Codable {
        var webhookUrl: String
        var enabled: Bool
        var updatedAt: String?
    }

    struct EmailConfig: Codable {
        var userEmail: String
        var appPassword: String
        var enabled: Bool
        var updatedAt: String?
    }

    private struct ConfigFile: Codable {
        var telegram: TelegramConfig
        var discord: DiscordConfig
        var email: EmailConfig
    }

    private init() {
        configPath = (SecurityConfig.shared.securityDir as NSString)
            .appendingPathComponent("notification-config.json")
        telegram = TelegramConfig(botToken: "", chatId: "", enabled: false)
        discord = DiscordConfig(webhookUrl: "", enabled: false)
        email = EmailConfig(userEmail: "", appPassword: "", enabled: false)
        load()
    }

    // MARK: - Load / Save

    func load() {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let config = try? JSONDecoder().decode(ConfigFile.self, from: data) else { return }
        telegram = config.telegram
        discord = config.discord
        email = config.email
    }

    func save() {
        let config = ConfigFile(telegram: telegram, discord: discord, email: email)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(config) else { return }
        try? data.write(to: URL(fileURLWithPath: configPath))
    }

    // MARK: - Update helpers

    func updateTelegram(botToken: String, chatId: String, enabled: Bool) {
        telegram = TelegramConfig(
            botToken: botToken, chatId: chatId, enabled: enabled,
            updatedAt: ISO8601DateFormatter().string(from: Date()))
        save()
    }

    func updateDiscord(webhookUrl: String, enabled: Bool) {
        discord = DiscordConfig(
            webhookUrl: webhookUrl, enabled: enabled,
            updatedAt: ISO8601DateFormatter().string(from: Date()))
        save()
    }

    func updateEmail(userEmail: String, appPassword: String, enabled: Bool) {
        email = EmailConfig(
            userEmail: userEmail, appPassword: appPassword.replacingOccurrences(of: " ", with: ""),
            enabled: enabled,
            updatedAt: ISO8601DateFormatter().string(from: Date()))
        save()
    }

    var isTelegramConfigured: Bool {
        !telegram.botToken.isEmpty && !telegram.chatId.isEmpty
    }

    var isDiscordConfigured: Bool {
        !discord.webhookUrl.isEmpty
    }

    var isEmailConfigured: Bool {
        !email.userEmail.isEmpty && !email.appPassword.isEmpty
    }
}
