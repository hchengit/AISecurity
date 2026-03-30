import AppKit

/// Vault UI dialogs — setup wizard, confirmation prompts, and user education.
enum VaultDialogs {

    // MARK: - First-Run Setup Wizard

    /// Runs the first-time vault setup wizard. Returns the passphrase if setup completes, nil if cancelled.
    static func runSetupWizard() -> String? {
        // Step 1: Welcome
        let welcome = NSAlert()
        welcome.messageText = "Welcome to AISecurity Vault"
        welcome.informativeText = """
        AISecurity Vault encrypts your sensitive files so only you can access them \
        — even if your Mac is compromised.

        Before you start, here's what you need to know:

        \u{2022} Files you protect are encrypted with AES-256-GCM (military-grade)
        \u{2022} The original unencrypted file is securely deleted after encryption
        \u{2022} Only YOUR passphrase can decrypt these files — we never store it
        \u{2022} You can unlock files anytime with Touch ID + your vault passphrase

        You'll create a vault passphrase on the next screen.
        """
        welcome.alertStyle = .informational
        welcome.addButton(withTitle: "Continue")
        welcome.addButton(withTitle: "Cancel")
        if welcome.runModal() != .alertFirstButtonReturn { return nil }

        // Step 2: Create passphrase
        let passAlert = NSAlert()
        passAlert.messageText = "Create Your Vault Passphrase"
        passAlert.informativeText = """
        Choose a strong passphrase you'll remember. This is separate from your Mac password.

        \u{26A0} IMPORTANT: If you forget this passphrase, your encrypted files \
        CANNOT be recovered. There is no reset option.

        We recommend writing it down and storing it in a safe place.
        """
        passAlert.alertStyle = .informational
        passAlert.addButton(withTitle: "Set Passphrase")
        passAlert.addButton(withTitle: "Cancel")

        let container = NSView(frame: NSRect(x: 0, y: 0, width: 320, height: 68))

        let pass1 = NSSecureTextField(frame: NSRect(x: 0, y: 38, width: 320, height: 24))
        pass1.placeholderString = "Enter passphrase"
        container.addSubview(pass1)

        let pass2 = NSSecureTextField(frame: NSRect(x: 0, y: 6, width: 320, height: 24))
        pass2.placeholderString = "Confirm passphrase"
        container.addSubview(pass2)

        passAlert.accessoryView = container
        passAlert.window.initialFirstResponder = pass1

        while true {
            let response = passAlert.runModal()
            if response != .alertFirstButtonReturn { return nil }

            let p1 = pass1.stringValue
            let p2 = pass2.stringValue

            if p1.isEmpty {
                showError("Passphrase cannot be empty.")
                continue
            }
            if p1.count < 8 {
                showError("Passphrase must be at least 8 characters.")
                continue
            }
            if p1 != p2 {
                showError("Passphrases don't match. Please try again.")
                pass1.stringValue = ""
                pass2.stringValue = ""
                continue
            }

            // Success
            break
        }

        let passphrase = pass1.stringValue

        // Step 3: Recovery info
        let recovery = NSAlert()
        recovery.messageText = "Vault Setup Complete"
        recovery.informativeText = """
        Your vault is ready! Recovery instructions have been saved to:
        ~/.mac-security/VAULT-RECOVERY.txt

        Keep that file and your passphrase safe. If you ever need to recover \
        your encrypted files, follow the instructions in that file.

        You can now use "Protect Files..." from the menu bar to encrypt files.
        """
        recovery.alertStyle = .informational
        recovery.addButton(withTitle: "Done")
        recovery.runModal()

        return passphrase
    }

    // MARK: - Pre-Encrypt Confirmation

    /// Shows confirmation before encrypting files. Returns true if user confirms.
    static func confirmEncrypt(paths: [String], protection: SecurityCoreBridge.ProtectionLevel) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .warning

        let count = paths.count
        let fileWord = count == 1 ? "file" : "files"

        switch protection {
        case .locked:
            alert.messageText = "Encrypt \(count) \(fileWord)?"
            alert.informativeText = """
            The selected \(fileWord) will be encrypted with AES-256-GCM.
            Original files will be securely deleted (overwritten 3 times).

            You will need your vault passphrase to access them again.

            \(paths.prefix(5).joined(separator: "\n"))\(count > 5 ? "\n... and \(count - 5) more" : "")
            """
        case .readOnly:
            alert.messageText = "Set \(count) \(fileWord) to read-only?"
            alert.informativeText = """
            The selected \(fileWord) will be set to read-only (chmod 444).
            Apps can still open and read them, but cannot modify them.
            You'll be alerted if anything tries to write to them.

            \(paths.prefix(5).joined(separator: "\n"))\(count > 5 ? "\n... and \(count - 5) more" : "")
            """
        case .localOnly:
            alert.messageText = "Monitor \(count) \(fileWord) for exfiltration?"
            alert.informativeText = """
            The selected \(fileWord) will be monitored. Apps can read and write \
            them normally, but you'll be alerted if any process attempts to upload \
            or send them over the network.

            \(paths.prefix(5).joined(separator: "\n"))\(count > 5 ? "\n... and \(count - 5) more" : "")
            """
        }

        alert.addButton(withTitle: "Protect")
        alert.addButton(withTitle: "Cancel")

        return alert.runModal() == .alertFirstButtonReturn
    }

    // MARK: - Pre-Decrypt Confirmation

    /// Shows confirmation before decrypting files. Returns true if user confirms.
    static func confirmDecrypt(count: Int) -> Bool {
        let alert = NSAlert()
        alert.messageText = "Decrypt \(count) file(s)?"
        alert.informativeText = "The selected files will be decrypted to their original locations."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Decrypt")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    // MARK: - Protection Level Picker

    /// Let user choose a protection level. Returns nil if cancelled.
    static func pickProtectionLevel() -> SecurityCoreBridge.ProtectionLevel? {
        let alert = NSAlert()
        alert.messageText = "Choose Protection Level"
        alert.informativeText = """
        \u{1F512} Locked — Encrypt the file. Original securely deleted. \
        Only your passphrase can decrypt it.

        \u{1F4D6} Read-only — Apps can open but not modify. \
        Alert on write attempts.

        \u{1F310} Local-only — Normal read/write, but alert if any app \
        tries to upload or send the file over the network.
        """
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Locked (Encrypt)")
        alert.addButton(withTitle: "Read-only")
        alert.addButton(withTitle: "Local-only")
        alert.addButton(withTitle: "Cancel")

        let response = alert.runModal()
        switch response {
        case .alertFirstButtonReturn: return .locked
        case .alertSecondButtonReturn: return .readOnly
        case .alertThirdButtonReturn: return .localOnly
        default: return nil
        }
    }

    // MARK: - Change Passphrase

    /// Prompts for old and new passphrase. Returns (old, new) or nil if cancelled.
    static func promptChangePassphrase() -> (old: String, new: String)? {
        let alert = NSAlert()
        alert.messageText = "Change Vault Passphrase"
        alert.informativeText = "All encrypted files will be re-encrypted with the new passphrase."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Change")
        alert.addButton(withTitle: "Cancel")

        let container = NSView(frame: NSRect(x: 0, y: 0, width: 320, height: 102))

        let oldField = NSSecureTextField(frame: NSRect(x: 0, y: 72, width: 320, height: 24))
        oldField.placeholderString = "Current passphrase"
        container.addSubview(oldField)

        let newField = NSSecureTextField(frame: NSRect(x: 0, y: 40, width: 320, height: 24))
        newField.placeholderString = "New passphrase"
        container.addSubview(newField)

        let confirmField = NSSecureTextField(frame: NSRect(x: 0, y: 8, width: 320, height: 24))
        confirmField.placeholderString = "Confirm new passphrase"
        container.addSubview(confirmField)

        alert.accessoryView = container
        alert.window.initialFirstResponder = oldField

        while true {
            let response = alert.runModal()
            if response != .alertFirstButtonReturn { return nil }

            let oldPass = oldField.stringValue
            let newPass = newField.stringValue
            let confirm = confirmField.stringValue

            if oldPass.isEmpty || newPass.isEmpty {
                showError("All fields are required.")
                continue
            }
            if newPass.count < 8 {
                showError("New passphrase must be at least 8 characters.")
                continue
            }
            if newPass != confirm {
                showError("New passphrases don't match.")
                newField.stringValue = ""
                confirmField.stringValue = ""
                continue
            }
            return (old: oldPass, new: newPass)
        }
    }

    // MARK: - Helpers

    static func showError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Vault Error"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    static func showSuccess(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Vault"
        alert.informativeText = message
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
