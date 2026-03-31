import Foundation
import Security

/// Persists external notification channel credentials securely.
/// Non-sensitive settings (enabled flags, timestamps) are stored in JSON.
/// Sensitive credentials (tokens, passwords, URLs) are stored in macOS Keychain.
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

    /// JSON file stores only non-sensitive fields (enabled, updatedAt).
    private struct ConfigFile: Codable {
        struct TelegramMeta: Codable { var enabled: Bool; var updatedAt: String? }
        struct DiscordMeta: Codable { var enabled: Bool; var updatedAt: String? }
        struct EmailMeta: Codable { var enabled: Bool; var updatedAt: String? }
        var telegram: TelegramMeta
        var discord: DiscordMeta
        var email: EmailMeta
    }

    // MARK: - Keychain Keys

    private static let keychainService = "com.aisecurity.notifications"
    private enum KeychainKey: String {
        case telegramBotToken = "telegram.botToken"
        case telegramChatId   = "telegram.chatId"
        case discordWebhook   = "discord.webhookUrl"
        case emailAddress     = "email.userEmail"
        case emailPassword    = "email.appPassword"
    }

    private init() {
        configPath = (SecurityConfig.shared.securityDir as NSString)
            .appendingPathComponent("notification-config.json")
        telegram = TelegramConfig(botToken: "", chatId: "", enabled: false)
        discord = DiscordConfig(webhookUrl: "", enabled: false)
        email = EmailConfig(userEmail: "", appPassword: "", enabled: false)
        load()
    }

    // MARK: - Keychain Helpers

    private static func keychainSave(key: KeychainKey, value: String) {
        let data = Data(value.utf8)
        // Delete existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key.rawValue,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        guard !value.isEmpty else { return }

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key.rawValue,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    private static func keychainLoad(key: KeychainKey) -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: key.rawValue,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return "" }
        return String(data: data, encoding: .utf8) ?? ""
    }

    // MARK: - Load / Save

    func load() {
        // Load non-sensitive metadata from JSON
        if let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
           let meta = try? JSONDecoder().decode(ConfigFile.self, from: data) {
            telegram.enabled = meta.telegram.enabled
            telegram.updatedAt = meta.telegram.updatedAt
            discord.enabled = meta.discord.enabled
            discord.updatedAt = meta.discord.updatedAt
            email.enabled = meta.email.enabled
            email.updatedAt = meta.email.updatedAt
        }

        // Load sensitive credentials from Keychain
        telegram.botToken = Self.keychainLoad(key: .telegramBotToken)
        telegram.chatId = Self.keychainLoad(key: .telegramChatId)
        discord.webhookUrl = Self.keychainLoad(key: .discordWebhook)
        email.userEmail = Self.keychainLoad(key: .emailAddress)
        email.appPassword = Self.keychainLoad(key: .emailPassword)

        // Migration: if old JSON has credentials, move them to Keychain
        migrateFromJSON()
    }

    func save() {
        // Save non-sensitive metadata to JSON
        let meta = ConfigFile(
            telegram: .init(enabled: telegram.enabled, updatedAt: telegram.updatedAt),
            discord: .init(enabled: discord.enabled, updatedAt: discord.updatedAt),
            email: .init(enabled: email.enabled, updatedAt: email.updatedAt)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(meta) {
            try? data.write(to: URL(fileURLWithPath: configPath))
            // Harden file permissions
            try? FileManager.default.setAttributes(
                [.posixPermissions: NSNumber(value: UInt16(0o600))],
                ofItemAtPath: configPath)
        }

        // Save sensitive credentials to Keychain
        Self.keychainSave(key: .telegramBotToken, value: telegram.botToken)
        Self.keychainSave(key: .telegramChatId, value: telegram.chatId)
        Self.keychainSave(key: .discordWebhook, value: discord.webhookUrl)
        Self.keychainSave(key: .emailAddress, value: email.userEmail)
        Self.keychainSave(key: .emailPassword, value: email.appPassword)
    }

    /// Migrate credentials from old plain-text JSON to Keychain (one-time).
    private func migrateFromJSON() {
        struct OldConfigFile: Codable {
            struct T: Codable { var botToken: String; var chatId: String; var enabled: Bool; var updatedAt: String? }
            struct D: Codable { var webhookUrl: String; var enabled: Bool; var updatedAt: String? }
            struct E: Codable { var userEmail: String; var appPassword: String; var enabled: Bool; var updatedAt: String? }
            var telegram: T; var discord: D; var email: E
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: configPath)),
              let old = try? JSONDecoder().decode(OldConfigFile.self, from: data) else { return }

        // If old JSON has credentials and Keychain is empty, migrate
        var migrated = false
        if !old.telegram.botToken.isEmpty && telegram.botToken.isEmpty {
            telegram.botToken = old.telegram.botToken
            telegram.chatId = old.telegram.chatId
            migrated = true
        }
        if !old.discord.webhookUrl.isEmpty && discord.webhookUrl.isEmpty {
            discord.webhookUrl = old.discord.webhookUrl
            migrated = true
        }
        if !old.email.appPassword.isEmpty && email.appPassword.isEmpty {
            email.userEmail = old.email.userEmail
            email.appPassword = old.email.appPassword
            migrated = true
        }
        if migrated {
            save()  // This saves to Keychain and overwrites JSON with metadata-only
            NSLog("[AISecurity] Migrated notification credentials from JSON to Keychain")
        }
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
