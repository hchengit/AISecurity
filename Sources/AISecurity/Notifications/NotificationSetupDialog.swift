import AppKit

/// Setup wizard for external notification channels (Telegram, Discord, Email).
enum NotificationSetupDialog {

    /// Show the notification settings dialog.
    static func show() {
        let config = NotificationConfig.shared

        let alert = NSAlert()
        alert.messageText = "Notification Settings"
        alert.informativeText = "Configure external notifications for CRITICAL and HIGH security alerts."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")

        // Build tabbed accessory view
        let tabView = NSTabView(frame: NSRect(x: 0, y: 0, width: 480, height: 380))
        tabView.tabViewType = .topTabsBezelBorder

        tabView.addTabViewItem(buildTelegramTab(config))
        tabView.addTabViewItem(buildDiscordTab(config))
        tabView.addTabViewItem(buildEmailTab(config))

        alert.accessoryView = tabView
        alert.layout()

        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else { return }

        // Save all tabs
        saveTelegramTab(tabView.tabViewItem(at: 0), config: config)
        saveDiscordTab(tabView.tabViewItem(at: 1), config: config)
        saveEmailTab(tabView.tabViewItem(at: 2), config: config)
    }

    // MARK: - Telegram Tab

    private static func buildTelegramTab(_ config: NotificationConfig) -> NSTabViewItem {
        let item = NSTabViewItem(identifier: "telegram")
        item.label = "Telegram"

        let view = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 340))

        let instructions = NSTextField(wrappingLabelWithString: """
        Setup: 1) Open Telegram, search @BotFather \
        2) Send /newbot, follow prompts \
        3) Copy Bot Token \
        4) Start a chat with your bot (send any message) \
        5) Open: api.telegram.org/bot<TOKEN>/getUpdates \
        6) Find "chat":{"id":NUMBERS} \u{2014} that's your Chat ID
        """)
        instructions.frame = NSRect(x: 10, y: 250, width: 440, height: 80)
        instructions.font = .systemFont(ofSize: 11)
        instructions.textColor = .secondaryLabelColor
        view.addSubview(instructions)

        let tokenLabel = NSTextField(labelWithString: "Bot Token:")
        tokenLabel.frame = NSRect(x: 10, y: 218, width: 90, height: 20)
        tokenLabel.font = .systemFont(ofSize: 13)
        view.addSubview(tokenLabel)

        let tokenField = NSTextField(frame: NSRect(x: 105, y: 218, width: 345, height: 24))
        tokenField.placeholderString = "123456789:ABCdef..."
        tokenField.stringValue = config.telegram.botToken
        tokenField.tag = 100
        view.addSubview(tokenField)

        let chatLabel = NSTextField(labelWithString: "Chat ID:")
        chatLabel.frame = NSRect(x: 10, y: 186, width: 90, height: 20)
        chatLabel.font = .systemFont(ofSize: 13)
        view.addSubview(chatLabel)

        let chatField = NSTextField(frame: NSRect(x: 105, y: 186, width: 345, height: 24))
        chatField.placeholderString = "987654321"
        chatField.stringValue = config.telegram.chatId
        chatField.tag = 101
        view.addSubview(chatField)

        let enableCheck = NSButton(checkboxWithTitle: "Enable Telegram notifications", target: nil, action: nil)
        enableCheck.frame = NSRect(x: 10, y: 150, width: 300, height: 20)
        enableCheck.state = config.telegram.enabled ? .on : .off
        enableCheck.tag = 102
        view.addSubview(enableCheck)

        let testBtn = NSButton(title: "Send Test", target: nil, action: nil)
        testBtn.frame = NSRect(x: 10, y: 110, width: 100, height: 30)
        testBtn.bezelStyle = .rounded
        let testTarget = TestButtonTarget(channel: .telegram, view: view)
        testBtn.target = testTarget
        testBtn.action = #selector(TestButtonTarget.test(_:))
        objc_setAssociatedObject(view, "testTarget", testTarget, .OBJC_ASSOCIATION_RETAIN)
        view.addSubview(testBtn)

        let statusLabel = NSTextField(labelWithString: "")
        statusLabel.frame = NSRect(x: 120, y: 114, width: 330, height: 20)
        statusLabel.font = .systemFont(ofSize: 12)
        statusLabel.tag = 199
        view.addSubview(statusLabel)

        item.view = view
        return item
    }

    private static func saveTelegramTab(_ item: NSTabViewItem, config: NotificationConfig) {
        guard let view = item.view else { return }
        let token = (view.viewWithTag(100) as? NSTextField)?.stringValue ?? ""
        let chatId = (view.viewWithTag(101) as? NSTextField)?.stringValue ?? ""
        let enabled = (view.viewWithTag(102) as? NSButton)?.state == .on
        config.updateTelegram(botToken: token, chatId: chatId, enabled: enabled)
    }

    // MARK: - Discord Tab

    private static func buildDiscordTab(_ config: NotificationConfig) -> NSTabViewItem {
        let item = NSTabViewItem(identifier: "discord")
        item.label = "Discord"

        let view = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 340))

        let instructions = NSTextField(wrappingLabelWithString: """
        Setup: 1) Open Discord, go to your server \
        2) Server Settings \u{2192} Integrations \u{2192} Webhooks \
        3) New Webhook \u{2014} name it "AISecurity", select channel \
        4) Copy Webhook URL, paste below
        """)
        instructions.frame = NSRect(x: 10, y: 260, width: 440, height: 60)
        instructions.font = .systemFont(ofSize: 11)
        instructions.textColor = .secondaryLabelColor
        view.addSubview(instructions)

        let urlLabel = NSTextField(labelWithString: "Webhook URL:")
        urlLabel.frame = NSRect(x: 10, y: 228, width: 100, height: 20)
        urlLabel.font = .systemFont(ofSize: 13)
        view.addSubview(urlLabel)

        let urlField = NSTextField(frame: NSRect(x: 115, y: 228, width: 335, height: 24))
        urlField.placeholderString = "https://discord.com/api/webhooks/..."
        urlField.stringValue = config.discord.webhookUrl
        urlField.tag = 200
        view.addSubview(urlField)

        let enableCheck = NSButton(checkboxWithTitle: "Enable Discord notifications", target: nil, action: nil)
        enableCheck.frame = NSRect(x: 10, y: 192, width: 300, height: 20)
        enableCheck.state = config.discord.enabled ? .on : .off
        enableCheck.tag = 201
        view.addSubview(enableCheck)

        let testBtn = NSButton(title: "Send Test", target: nil, action: nil)
        testBtn.frame = NSRect(x: 10, y: 152, width: 100, height: 30)
        testBtn.bezelStyle = .rounded
        let testTarget = TestButtonTarget(channel: .discord, view: view)
        testBtn.target = testTarget
        testBtn.action = #selector(TestButtonTarget.test(_:))
        objc_setAssociatedObject(view, "testTarget", testTarget, .OBJC_ASSOCIATION_RETAIN)
        view.addSubview(testBtn)

        let statusLabel = NSTextField(labelWithString: "")
        statusLabel.frame = NSRect(x: 120, y: 156, width: 330, height: 20)
        statusLabel.font = .systemFont(ofSize: 12)
        statusLabel.tag = 299
        view.addSubview(statusLabel)

        item.view = view
        return item
    }

    private static func saveDiscordTab(_ item: NSTabViewItem, config: NotificationConfig) {
        guard let view = item.view else { return }
        let url = (view.viewWithTag(200) as? NSTextField)?.stringValue ?? ""
        let enabled = (view.viewWithTag(201) as? NSButton)?.state == .on
        config.updateDiscord(webhookUrl: url, enabled: enabled)
    }

    // MARK: - Email Tab

    private static func buildEmailTab(_ config: NotificationConfig) -> NSTabViewItem {
        let item = NSTabViewItem(identifier: "email")
        item.label = "Email"

        let view = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 340))

        let instructions = NSTextField(wrappingLabelWithString: """
        Gmail setup: 1) Enable 2-Step Verification at myaccount.google.com/security \
        2) Go to myaccount.google.com/apppasswords \
        3) Generate App Password for "Mail" / "Other (AISecurity)" \
        4) Copy the 16-character password, paste below
        """)
        instructions.frame = NSRect(x: 10, y: 260, width: 440, height: 60)
        instructions.font = .systemFont(ofSize: 11)
        instructions.textColor = .secondaryLabelColor
        view.addSubview(instructions)

        let emailLabel = NSTextField(labelWithString: "Gmail Address:")
        emailLabel.frame = NSRect(x: 10, y: 228, width: 110, height: 20)
        emailLabel.font = .systemFont(ofSize: 13)
        view.addSubview(emailLabel)

        let emailField = NSTextField(frame: NSRect(x: 125, y: 228, width: 325, height: 24))
        emailField.placeholderString = "you@gmail.com"
        emailField.stringValue = config.email.userEmail
        emailField.tag = 300
        view.addSubview(emailField)

        let passLabel = NSTextField(labelWithString: "App Password:")
        passLabel.frame = NSRect(x: 10, y: 196, width: 110, height: 20)
        passLabel.font = .systemFont(ofSize: 13)
        view.addSubview(passLabel)

        let passField = NSSecureTextField(frame: NSRect(x: 125, y: 196, width: 325, height: 24))
        passField.placeholderString = "xxxx xxxx xxxx xxxx"
        passField.stringValue = config.email.appPassword
        passField.tag = 301
        view.addSubview(passField)

        let enableCheck = NSButton(checkboxWithTitle: "Enable Email notifications", target: nil, action: nil)
        enableCheck.frame = NSRect(x: 10, y: 160, width: 300, height: 20)
        enableCheck.state = config.email.enabled ? .on : .off
        enableCheck.tag = 302
        view.addSubview(enableCheck)

        let testBtn = NSButton(title: "Send Test", target: nil, action: nil)
        testBtn.frame = NSRect(x: 10, y: 120, width: 100, height: 30)
        testBtn.bezelStyle = .rounded
        let testTarget = TestButtonTarget(channel: .email, view: view)
        testBtn.target = testTarget
        testBtn.action = #selector(TestButtonTarget.test(_:))
        objc_setAssociatedObject(view, "testTarget", testTarget, .OBJC_ASSOCIATION_RETAIN)
        view.addSubview(testBtn)

        let statusLabel = NSTextField(labelWithString: "")
        statusLabel.frame = NSRect(x: 120, y: 124, width: 330, height: 20)
        statusLabel.font = .systemFont(ofSize: 12)
        statusLabel.tag = 399
        view.addSubview(statusLabel)

        item.view = view
        return item
    }

    private static func saveEmailTab(_ item: NSTabViewItem, config: NotificationConfig) {
        guard let view = item.view else { return }
        let email = (view.viewWithTag(300) as? NSTextField)?.stringValue ?? ""
        let password = (view.viewWithTag(301) as? NSTextField)?.stringValue ?? ""
        let enabled = (view.viewWithTag(302) as? NSButton)?.state == .on
        config.updateEmail(userEmail: email, appPassword: password, enabled: enabled)
    }

    // MARK: - Test Button Handler

    private enum TestChannel { case telegram, discord, email }

    private class TestButtonTarget: NSObject {
        let channel: TestChannel
        let view: NSView

        init(channel: TestChannel, view: NSView) {
            self.channel = channel
            self.view = view
        }

        @objc func test(_ sender: NSButton) {
            let statusTag: Int
            switch channel {
            case .telegram: statusTag = 199
            case .discord:  statusTag = 299
            case .email:    statusTag = 399
            }

            let statusLabel = view.viewWithTag(statusTag) as? NSTextField
            statusLabel?.stringValue = "Sending..."
            statusLabel?.textColor = .secondaryLabelColor

            switch channel {
            case .telegram:
                let token = (view.viewWithTag(100) as? NSTextField)?.stringValue ?? ""
                let chatId = (view.viewWithTag(101) as? NSTextField)?.stringValue ?? ""
                let cfg = NotificationConfig.TelegramConfig(botToken: token, chatId: chatId, enabled: true)
                TelegramChannel.sendTest(config: cfg) { ok, err in
                    DispatchQueue.main.async {
                        statusLabel?.stringValue = ok ? "\u{2705} Test sent!" : "\u{274C} \(err ?? "Failed")"
                        statusLabel?.textColor = ok ? .systemGreen : .systemRed
                    }
                }

            case .discord:
                let url = (view.viewWithTag(200) as? NSTextField)?.stringValue ?? ""
                let cfg = NotificationConfig.DiscordConfig(webhookUrl: url, enabled: true)
                DiscordChannel.sendTest(config: cfg) { ok, err in
                    DispatchQueue.main.async {
                        statusLabel?.stringValue = ok ? "\u{2705} Test sent!" : "\u{274C} \(err ?? "Failed")"
                        statusLabel?.textColor = ok ? .systemGreen : .systemRed
                    }
                }

            case .email:
                let email = (view.viewWithTag(300) as? NSTextField)?.stringValue ?? ""
                let pass = (view.viewWithTag(301) as? NSTextField)?.stringValue ?? ""
                let cfg = NotificationConfig.EmailConfig(userEmail: email, appPassword: pass.replacingOccurrences(of: " ", with: ""), enabled: true)
                EmailChannel.sendTest(config: cfg) { ok, err in
                    DispatchQueue.main.async {
                        statusLabel?.stringValue = ok ? "\u{2705} Test sent!" : "\u{274C} \(err ?? "Failed")"
                        statusLabel?.textColor = ok ? .systemGreen : .systemRed
                    }
                }
            }
        }
    }
}
