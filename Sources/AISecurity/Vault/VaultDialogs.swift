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

        Aim for 90%+ on the strength meter below. We recommend writing \
        it down and storing it in a safe place.
        """
        passAlert.alertStyle = .informational
        passAlert.addButton(withTitle: "Set Passphrase")
        passAlert.addButton(withTitle: "Cancel")

        let container = NSView(frame: NSRect(x: 0, y: 0, width: 320, height: 168))

        let pass1 = NSSecureTextField(frame: NSRect(x: 0, y: 138, width: 320, height: 24))
        pass1.placeholderString = "Enter passphrase"
        container.addSubview(pass1)

        let pass2 = NSSecureTextField(frame: NSRect(x: 0, y: 106, width: 320, height: 24))
        pass2.placeholderString = "Confirm passphrase"
        container.addSubview(pass2)

        // Strength indicator
        let (strengthView, updateStrength) = makeStrengthView(width: 320)
        strengthView.frame.origin = NSPoint(x: 0, y: 46)
        container.addSubview(strengthView)

        // Educational tip
        let eduLabel = NSTextField(wrappingLabelWithString:
            "\u{1F4A1} Tip: 4 random words like \"maple anchor freight violin\" gives 90%+ strength " +
            "and would take millions of years to crack. Length beats complexity.")
        eduLabel.frame = NSRect(x: 0, y: 0, width: 320, height: 40)
        eduLabel.font = .systemFont(ofSize: 10)
        eduLabel.textColor = .tertiaryLabelColor
        container.addSubview(eduLabel)

        // Wire up real-time strength updates via a delegate
        let strengthDelegate = PassphraseStrengthDelegate(update: updateStrength)
        pass1.delegate = strengthDelegate
        objc_setAssociatedObject(passAlert, "strengthDelegate", strengthDelegate, .OBJC_ASSOCIATION_RETAIN)

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

        // Step 3: Recovery key — show numbered words
        let recoveryKey = VaultManager.shared.generateRecoveryKey()
        let words = recoveryKey.split(separator: " ").map(String.init)
        VaultManager.shared.storeRecoveryKeyHash(recoveryKey)

        let keyAlert = NSAlert()
        keyAlert.messageText = "Your Recovery Key"
        keyAlert.informativeText = """
        Write down these 12 words IN ORDER and store them in a safe place. \
        This is the ONLY way to reset your passphrase if you forget it.

        DO NOT store this digitally on this computer.
        """
        keyAlert.alertStyle = .critical
        keyAlert.addButton(withTitle: "I've Written It Down")
        keyAlert.addButton(withTitle: "Copy to Clipboard")

        // Show numbered words in a two-column grid
        let keyContainer = NSView(frame: NSRect(x: 0, y: 0, width: 440, height: 170))

        // Two columns of 6 words each
        for i in 0..<12 {
            let col = i < 6 ? 0 : 1
            let row = i < 6 ? i : i - 6
            let x = col == 0 ? 10 : 230
            let y = 140 - row * 22

            let numLabel = NSTextField(labelWithString: "\(i + 1).")
            numLabel.frame = NSRect(x: x, y: y, width: 25, height: 18)
            numLabel.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            numLabel.textColor = .secondaryLabelColor
            numLabel.alignment = .right
            keyContainer.addSubview(numLabel)

            let wordLabel = NSTextField(labelWithString: words[i])
            wordLabel.frame = NSRect(x: x + 30, y: y, width: 160, height: 18)
            wordLabel.font = .monospacedSystemFont(ofSize: 14, weight: .medium)
            wordLabel.isSelectable = true
            keyContainer.addSubview(wordLabel)
        }

        let hint = NSTextField(labelWithString: "Write all 12 words on paper \u{2014} you'll be quizzed next")
        hint.frame = NSRect(x: 10, y: 2, width: 420, height: 16)
        hint.font = .systemFont(ofSize: 11)
        hint.textColor = .tertiaryLabelColor
        hint.alignment = .center
        keyContainer.addSubview(hint)

        keyAlert.accessoryView = keyContainer
        keyAlert.layout()

        let keyResponse = keyAlert.runModal()
        if keyResponse == .alertSecondButtonReturn {
            NSPasteboard.general.clearContents()
            let numberedKey = words.enumerated().map { "\($0.offset + 1). \($0.element)" }.joined(separator: "  ")
            NSPasteboard.general.setString(numberedKey, forType: .string)
            let clipWarn = NSAlert()
            clipWarn.messageText = "Recovery Key Copied"
            clipWarn.informativeText = "Write it down on paper, then clear your clipboard.\n\nDO NOT leave it in your clipboard or save it digitally on this Mac."
            clipWarn.alertStyle = .warning
            clipWarn.addButton(withTitle: "OK")
            clipWarn.runModal()
        }

        // Step 4: Verify — quiz all 12 words in random order
        var shuffledIndices = Array(0..<12)
        shuffledIndices.shuffle()

        let verifyAlert = NSAlert()
        verifyAlert.messageText = "Verify Your Recovery Key"
        verifyAlert.informativeText = "Enter each word by its number to confirm you wrote them down correctly."
        verifyAlert.alertStyle = .informational
        verifyAlert.addButton(withTitle: "Verify")
        verifyAlert.addButton(withTitle: "Show Key Again")

        let verifyContainer = NSView(frame: NSRect(x: 0, y: 0, width: 440, height: 310))
        var verifyFields: [Int: NSTextField] = [:]

        for (pos, wordIndex) in shuffledIndices.enumerated() {
            let col = pos < 6 ? 0 : 1
            let row = pos < 6 ? pos : pos - 6
            let x = col == 0 ? 10 : 230
            let y = 270 - row * 44

            let numLabel = NSTextField(labelWithString: "\(wordIndex + 1).")
            numLabel.frame = NSRect(x: x, y: y + 2, width: 25, height: 20)
            numLabel.font = .monospacedSystemFont(ofSize: 13, weight: .bold)
            numLabel.alignment = .right
            verifyContainer.addSubview(numLabel)

            let field = NSTextField(frame: NSRect(x: x + 30, y: y, width: 160, height: 24))
            field.placeholderString = "word \(wordIndex + 1)"
            field.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
            field.tag = wordIndex
            verifyContainer.addSubview(field)
            verifyFields[wordIndex] = field
        }

        verifyAlert.accessoryView = verifyContainer
        // Set focus to the first field shown
        verifyAlert.window.initialFirstResponder = verifyFields[shuffledIndices[0]]
        verifyAlert.layout()

        while true {
            let verifyResponse = verifyAlert.runModal()

            if verifyResponse == .alertSecondButtonReturn {
                // Show key again — loop back to display
                let reshow = NSAlert()
                reshow.messageText = "Your Recovery Key"
                reshow.informativeText = "Here are your 12 words again. Write them down carefully."
                reshow.alertStyle = .informational
                reshow.addButton(withTitle: "OK, I've Written It Down")

                let reshowContainer = NSView(frame: NSRect(x: 0, y: 0, width: 440, height: 160))
                for i in 0..<12 {
                    let col = i < 6 ? 0 : 1
                    let row = i < 6 ? i : i - 6
                    let x = col == 0 ? 10 : 230
                    let y = 130 - row * 22

                    let numL = NSTextField(labelWithString: "\(i + 1).")
                    numL.frame = NSRect(x: x, y: y, width: 25, height: 18)
                    numL.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
                    numL.textColor = .secondaryLabelColor
                    numL.alignment = .right
                    reshowContainer.addSubview(numL)

                    let wL = NSTextField(labelWithString: words[i])
                    wL.frame = NSRect(x: x + 30, y: y, width: 160, height: 18)
                    wL.font = .monospacedSystemFont(ofSize: 14, weight: .medium)
                    wL.isSelectable = true
                    reshowContainer.addSubview(wL)
                }
                reshow.accessoryView = reshowContainer
                reshow.layout()
                reshow.runModal()

                // Clear fields for re-attempt
                for (_, field) in verifyFields { field.stringValue = "" }
                continue
            }

            // Check all 12 words
            var wrong: [Int] = []
            for i in 0..<12 {
                let entered = verifyFields[i]?.stringValue.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
                if entered != words[i].lowercased() {
                    wrong.append(i + 1)
                }
            }

            if wrong.isEmpty {
                let success = NSAlert()
                success.messageText = "Recovery Key Verified!"
                success.informativeText = "All 12 words are correct. Your recovery key is safely stored.\n\nKeep your written copy in a secure location."
                success.alertStyle = .informational
                success.addButton(withTitle: "Continue")
                success.runModal()
                break
            } else {
                let wrongStr = wrong.map { "#\($0)" }.joined(separator: ", ")
                showError("Incorrect words: \(wrongStr)\n\nPlease check your written copy and try again.")
                // Clear wrong fields
                for idx in wrong {
                    verifyFields[idx - 1]?.stringValue = ""
                }
                continue
            }
        }

        // Step 5: Setup complete
        let recovery = NSAlert()
        recovery.messageText = "Vault Setup Complete"
        recovery.informativeText = """
        Your vault is ready!

        Remember:
        \u{2022} Your passphrase unlocks your vault
        \u{2022} Your 12-word recovery key resets your passphrase if forgotten
        \u{2022} Without both, encrypted files CANNOT be recovered

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

        let pathList = paths.prefix(5).joined(separator: "\n")
            + (count > 5 ? "\n... and \(count - 5) more" : "")

        switch protection {
        case .locked:
            alert.messageText = "Encrypt \(count) \(fileWord)?"
            alert.informativeText = """
            The selected \(fileWord) will be encrypted with AES-256-GCM.
            Original files will be securely deleted (overwritten 3 times).

            You will need your vault passphrase to access them again.

            \(pathList)
            """
        case .readOnly:
            alert.messageText = "Set \(count) \(fileWord) to read-only?"
            alert.informativeText = """
            The selected \(fileWord) will be set to read-only (chmod 444).
            Apps can still open and read them, but cannot modify them.
            You'll be alerted if anything tries to write to them.

            \(pathList)
            """
        case .localOnly:
            alert.messageText = "Monitor \(count) \(fileWord) for exfiltration?"
            alert.informativeText = """
            The selected \(fileWord) will be monitored. Apps can read and write \
            them normally, but you'll be alerted if any process attempts to upload \
            or send them over the network.

            \(pathList)
            """
        case .readOnlyLocal:
            alert.messageText = "Set \(count) \(fileWord) to read-only + local-only?"
            alert.informativeText = """
            The selected \(fileWord) will be set to read-only (chmod 444) AND \
            monitored for network exfiltration.
            Apps can open but not modify them, and you'll be alerted if any \
            process attempts to send them over the network.

            \(pathList)
            """
        case .lockedLocal:
            alert.messageText = "Encrypt \(count) \(fileWord) + monitor?"
            alert.informativeText = """
            The selected \(fileWord) will be encrypted with AES-256-GCM AND \
            monitored for network exfiltration.
            Original files will be securely deleted. When temporarily unlocked, \
            you'll be alerted if any process tries to send them over the network.

            \(pathList)
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

    /// Delegate for real-time passphrase strength updates as user types.
    private class PassphraseStrengthDelegate: NSObject, NSTextFieldDelegate {
        let update: (String) -> Void

        init(update: @escaping (String) -> Void) {
            self.update = update
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let field = obj.object as? NSTextField else { return }
            update(field.stringValue)
        }
    }

    /// Helper that enforces mutual exclusivity between Locked and Read-only checkboxes.
    private class ProtectionPickerDelegate: NSObject {
        let lockedBox: NSButton
        let readOnlyBox: NSButton

        init(locked: NSButton, readOnly: NSButton) {
            self.lockedBox = locked
            self.readOnlyBox = readOnly
        }

        @objc func lockedToggled(_ sender: NSButton) {
            if sender.state == .on {
                readOnlyBox.state = .off
            }
        }

        @objc func readOnlyToggled(_ sender: NSButton) {
            if sender.state == .on {
                lockedBox.state = .off
            }
        }
    }

    /// Let user choose protection levels. Locked/Read-only are mutually exclusive; Local-only combines with either.
    static func pickProtectionLevel() -> SecurityCoreBridge.ProtectionLevel? {
        let alert = NSAlert()
        alert.messageText = "Choose Protection Level"
        alert.informativeText = "Locked and Read-only are mutually exclusive.\nLocal-only can be added to either, or used alone."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Protect")
        alert.addButton(withTitle: "Cancel")

        // Use NSStackView for reliable auto-layout
        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.edgeInsets = NSEdgeInsets(top: 4, left: 0, bottom: 4, right: 0)

        // Locked checkbox
        let lockedBox = NSButton(checkboxWithTitle: "Locked (Encrypt) \u{2014} original securely deleted, passphrase to decrypt",
                                 target: nil, action: nil)
        lockedBox.font = .systemFont(ofSize: 13)
        lockedBox.state = .on
        stack.addArrangedSubview(lockedBox)

        // Read-only checkbox (mutually exclusive with Locked)
        let readOnlyBox = NSButton(checkboxWithTitle: "Read-only \u{2014} apps can open but not modify, alert on writes",
                                   target: nil, action: nil)
        readOnlyBox.font = .systemFont(ofSize: 13)
        stack.addArrangedSubview(readOnlyBox)

        // Separator
        let sep = NSBox()
        sep.boxType = .separator
        sep.translatesAutoresizingMaskIntoConstraints = false
        sep.heightAnchor.constraint(equalToConstant: 1).isActive = true
        sep.widthAnchor.constraint(equalToConstant: 400).isActive = true
        stack.addArrangedSubview(sep)

        // Local-only checkbox (independent, can combine)
        let localOnlyBox = NSButton(checkboxWithTitle: "Local-only \u{2014} alert on network exfiltration (can combine with above)",
                                    target: nil, action: nil)
        localOnlyBox.font = .systemFont(ofSize: 13)
        stack.addArrangedSubview(localOnlyBox)

        // Wire up mutual exclusivity between Locked and Read-only
        let delegate = ProtectionPickerDelegate(locked: lockedBox, readOnly: readOnlyBox)
        lockedBox.target = delegate
        lockedBox.action = #selector(ProtectionPickerDelegate.lockedToggled(_:))
        readOnlyBox.target = delegate
        readOnlyBox.action = #selector(ProtectionPickerDelegate.readOnlyToggled(_:))

        // Set explicit frame size so NSAlert respects it
        stack.translatesAutoresizingMaskIntoConstraints = false
        let wrapper = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 120))
        wrapper.addSubview(stack)
        stack.topAnchor.constraint(equalTo: wrapper.topAnchor).isActive = true
        stack.leadingAnchor.constraint(equalTo: wrapper.leadingAnchor).isActive = true
        stack.trailingAnchor.constraint(equalTo: wrapper.trailingAnchor).isActive = true

        alert.accessoryView = wrapper
        alert.layout()

        // Keep delegate alive while alert is showing
        objc_setAssociatedObject(alert, "protectionDelegate", delegate, .OBJC_ASSOCIATION_RETAIN)

        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else { return nil }

        let isLocked = lockedBox.state == .on
        let isReadOnly = readOnlyBox.state == .on
        let isLocalOnly = localOnlyBox.state == .on

        // Must select at least one
        guard isLocked || isReadOnly || isLocalOnly else {
            showError("Please select at least one protection level.")
            return nil
        }

        // Determine combined protection
        if isLocked && isLocalOnly { return .lockedLocal }
        if isLocked { return .locked }
        if isReadOnly && isLocalOnly { return .readOnlyLocal }
        if isReadOnly { return .readOnly }
        return .localOnly
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

        let container = NSView(frame: NSRect(x: 0, y: 0, width: 320, height: 162))

        let oldField = NSSecureTextField(frame: NSRect(x: 0, y: 132, width: 320, height: 24))
        oldField.placeholderString = "Current passphrase"
        container.addSubview(oldField)

        let newField = NSSecureTextField(frame: NSRect(x: 0, y: 100, width: 320, height: 24))
        newField.placeholderString = "New passphrase"
        container.addSubview(newField)

        let confirmField = NSSecureTextField(frame: NSRect(x: 0, y: 68, width: 320, height: 24))
        confirmField.placeholderString = "Confirm new passphrase"
        container.addSubview(confirmField)

        // Strength indicator for new passphrase
        let (strengthView, updateStrength) = makeStrengthView(width: 320)
        strengthView.frame.origin = NSPoint(x: 0, y: 8)
        container.addSubview(strengthView)

        let strengthDelegate = PassphraseStrengthDelegate(update: updateStrength)
        newField.delegate = strengthDelegate
        objc_setAssociatedObject(alert, "strengthDelegate", strengthDelegate, .OBJC_ASSOCIATION_RETAIN)

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

    // MARK: - Passphrase Strength

    /// Estimate passphrase strength as a percentage (0–100).
    /// 8 chars ≈ 20%, 12 chars ≈ 45%, 16 chars ≈ 70%, 20+ chars or 4+ words ≈ 90%+.
    static func passphraseStrength(_ passphrase: String) -> Int {
        let len = passphrase.count
        guard len > 0 else { return 0 }

        var score: Double = 0

        // Length is the dominant factor
        score += min(Double(len), 30) * 2.5  // up to 75 points from length

        // Character variety adds modest bonus
        let hasLower = passphrase.rangeOfCharacter(from: .lowercaseLetters) != nil
        let hasUpper = passphrase.rangeOfCharacter(from: .uppercaseLetters) != nil
        let hasDigit = passphrase.rangeOfCharacter(from: .decimalDigits) != nil
        let hasSymbol = passphrase.rangeOfCharacter(from: CharacterSet.alphanumerics.inverted) != nil
        let variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter { $0 }.count
        score += Double(variety) * 3  // up to 12 points

        // Word-based bonus: spaces indicate multi-word passphrase
        let wordCount = passphrase.split(separator: " ").filter { $0.count >= 3 }.count
        if wordCount >= 4 { score += 20 }       // 4+ words is excellent
        else if wordCount >= 3 { score += 12 }   // 3 words is good

        // Penalize common patterns
        let lower = passphrase.lowercased()
        let commonPatterns = ["password", "123456", "qwerty", "abc123", "letmein", "admin", "welcome"]
        if commonPatterns.contains(where: { lower.contains($0) }) {
            score = min(score, 15)
        }

        return min(100, max(0, Int(score)))
    }

    /// Human-readable strength label + color.
    static func strengthLabel(_ score: Int) -> (text: String, color: NSColor) {
        switch score {
        case 0..<25:   return ("Weak",       NSColor.systemRed)
        case 25..<50:  return ("Fair",       NSColor.systemOrange)
        case 50..<75:  return ("Good",       NSColor.systemYellow)
        case 75..<90:  return ("Strong",     NSColor.systemGreen)
        default:       return ("Excellent",  NSColor.systemGreen)
        }
    }

    /// Build the strength bar view (progress bar + label + educational tip).
    static func makeStrengthView(width: CGFloat) -> (view: NSView, update: (String) -> Void) {
        let container = NSView(frame: NSRect(x: 0, y: 0, width: width, height: 52))

        // Progress bar background
        let barBg = NSView(frame: NSRect(x: 0, y: 36, width: width, height: 6))
        barBg.wantsLayer = true
        barBg.layer?.backgroundColor = NSColor.separatorColor.cgColor
        barBg.layer?.cornerRadius = 3
        container.addSubview(barBg)

        // Progress bar fill
        let barFill = NSView(frame: NSRect(x: 0, y: 36, width: 0, height: 6))
        barFill.wantsLayer = true
        barFill.layer?.cornerRadius = 3
        container.addSubview(barFill)

        // Strength label
        let label = NSTextField(labelWithString: "")
        label.frame = NSRect(x: 0, y: 18, width: width, height: 14)
        label.font = .systemFont(ofSize: 11, weight: .medium)
        container.addSubview(label)

        // Tip text
        let tip = NSTextField(wrappingLabelWithString: "")
        tip.frame = NSRect(x: 0, y: 0, width: width, height: 14)
        tip.font = .systemFont(ofSize: 10)
        tip.textColor = .secondaryLabelColor
        container.addSubview(tip)

        let update: (String) -> Void = { passphrase in
            let score = passphraseStrength(passphrase)
            let (text, color) = strengthLabel(score)

            barFill.frame.size.width = width * CGFloat(score) / 100.0
            barFill.layer?.backgroundColor = color.cgColor

            label.stringValue = "Strength: \(text) (\(score)%)"
            label.textColor = color

            if score < 25 {
                tip.stringValue = "Too short — try 4 random words like: maple anchor freight violin"
            } else if score < 50 {
                tip.stringValue = "Getting there — longer is better. Try adding more words."
            } else if score < 75 {
                tip.stringValue = "Good length. 4+ random words reaches 90%+ (would take millions of years to crack)."
            } else if score < 90 {
                tip.stringValue = "Strong passphrase. Very difficult to brute-force even with modern hardware."
            } else {
                tip.stringValue = "Excellent — this would take millions of years to crack."
            }
        }

        return (container, update)
    }

    // MARK: - Helpers

    // MARK: - Forgot Passphrase Recovery

    /// Prompts user to enter their 12-word recovery key and set a new passphrase.
    /// Returns the new passphrase if recovery succeeds, nil if cancelled or failed.
    static func promptForgotPassphrase() -> String? {
        guard VaultManager.shared.hasRecoveryKey else {
            showError("No recovery key was set up for this vault.\n\nWithout a recovery key, your encrypted files cannot be recovered.")
            return nil
        }

        let alert = NSAlert()
        alert.messageText = "Reset Vault Passphrase"
        alert.informativeText = """
        Enter your 12-word recovery key to reset your passphrase.

        \u{26A0} WARNING: This will reset the vault. Any currently encrypted \
        files (.vault) from the old vault will become unrecoverable.
        """
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Reset Passphrase")
        alert.addButton(withTitle: "Cancel")

        let container = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: 110))

        let keyLabel = NSTextField(labelWithString: "Recovery Key (12 words):")
        keyLabel.frame = NSRect(x: 0, y: 86, width: 400, height: 18)
        keyLabel.font = .systemFont(ofSize: 12)
        container.addSubview(keyLabel)

        let keyField = NSTextField(frame: NSRect(x: 0, y: 58, width: 400, height: 24))
        keyField.placeholderString = "word1 word2 word3 ... word12"
        keyField.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        container.addSubview(keyField)

        let newPass = NSSecureTextField(frame: NSRect(x: 0, y: 28, width: 400, height: 24))
        newPass.placeholderString = "New passphrase (min 8 characters)"
        container.addSubview(newPass)

        let confirmPass = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 400, height: 24))
        confirmPass.placeholderString = "Confirm new passphrase"
        container.addSubview(confirmPass)

        alert.accessoryView = container
        alert.window.initialFirstResponder = keyField

        while true {
            let response = alert.runModal()
            guard response == .alertFirstButtonReturn else { return nil }

            let key = keyField.stringValue.trimmingCharacters(in: .whitespaces)
            let pass = newPass.stringValue
            let confirm = confirmPass.stringValue

            // Validate recovery key format
            let words = key.split(separator: " ")
            if words.count != 12 {
                showError("Recovery key must be exactly 12 words separated by spaces.\nYou entered \(words.count) word\(words.count == 1 ? "" : "s").")
                continue
            }

            // Validate new passphrase
            if pass.isEmpty {
                showError("New passphrase cannot be empty.")
                continue
            }
            if pass.count < 8 {
                showError("New passphrase must be at least 8 characters.")
                continue
            }
            if pass != confirm {
                showError("Passphrases don't match.")
                newPass.stringValue = ""
                confirmPass.stringValue = ""
                continue
            }

            // Verify recovery key
            if !VaultManager.shared.verifyRecoveryKey(key) {
                showError("Recovery key is incorrect.\n\nMake sure you entered all 12 words in the correct order.")
                keyField.stringValue = ""
                continue
            }

            // Reset passphrase
            if VaultManager.shared.resetPassphraseWithRecoveryKey(recoveryKey: key, newPassphrase: pass) {
                // Generate and show new recovery key for the new vault
                let newRecoveryKey = VaultManager.shared.generateRecoveryKey()
                VaultManager.shared.storeRecoveryKeyHash(newRecoveryKey)

                let successAlert = NSAlert()
                successAlert.messageText = "Passphrase Reset Successful"
                successAlert.informativeText = """
                Your vault has been reset with a new passphrase.

                Here is your NEW recovery key — write it down:
                """
                successAlert.alertStyle = .informational
                successAlert.addButton(withTitle: "Done")

                let keyView = NSTextField(frame: NSRect(x: 0, y: 0, width: 400, height: 28))
                keyView.stringValue = newRecoveryKey
                keyView.isEditable = false
                keyView.isSelectable = true
                keyView.font = .monospacedSystemFont(ofSize: 13, weight: .medium)
                keyView.alignment = .center
                keyView.backgroundColor = .controlBackgroundColor
                keyView.isBordered = true
                successAlert.accessoryView = keyView
                successAlert.runModal()

                return pass
            } else {
                showError("Vault reset failed. Please try again.")
                return nil
            }
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
