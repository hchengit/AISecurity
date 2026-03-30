import Foundation
import AppKit

/// Manages vault lifecycle — coordinates between AuthGate, Rust bridge, and UI.
final class VaultManager {

    static let shared = VaultManager()

    let authGate = AuthGate()
    private let securityDir: String
    private(set) var passphrase: String? // held in memory during session only

    private init() {
        self.securityDir = SecurityConfig.shared.securityDir
    }

    /// Whether vault has been set up (salt + manifest exist).
    var isSetup: Bool {
        SecurityCoreBridge.vaultIsSetup(securityDir: securityDir)
    }

    /// First-time setup. Call before any vault operations.
    func setup() -> SecurityCoreBridge.VaultResult {
        SecurityCoreBridge.vaultSetup(securityDir: securityDir)
    }

    /// Set the initial passphrase during first-time setup.
    func setInitialPassphrase(_ passphrase: String) -> Bool {
        let ok = SecurityCoreBridge.vaultSetPassphrase(securityDir: securityDir, passphrase: passphrase)
        if ok { self.passphrase = passphrase }
        return ok
    }

    /// Verify a passphrase is correct.
    func verifyPassphrase(_ passphrase: String) -> Bool {
        SecurityCoreBridge.vaultVerifyPassphrase(securityDir: securityDir, passphrase: passphrase)
    }

    /// Authenticate + prompt for passphrase, then call action.
    func withAuth(reason: String, passphrasePrompt: String,
                  onPassphrase: @escaping (String) -> Void,
                  onCancel: @escaping () -> Void,
                  onError: @escaping (String) -> Void) {
        authGate.authenticate(reason: reason) { [weak self] success, error in
            guard success else {
                onError(error ?? "Authentication failed")
                return
            }

            // If we have a cached passphrase, use it
            if let cached = self?.passphrase {
                onPassphrase(cached)
                return
            }

            // Otherwise, prompt for passphrase via UI
            DispatchQueue.main.async {
                self?.promptForPassphrase(title: passphrasePrompt) { pass in
                    if let pass = pass {
                        guard let self = self else { return }
                        if self.verifyPassphrase(pass) {
                            self.passphrase = pass
                            onPassphrase(pass)
                        } else {
                            onError("Incorrect vault passphrase")
                        }
                    } else {
                        onCancel()
                    }
                }
            }
        }
    }

    /// Add files to vault.
    func addFiles(_ paths: [String], protection: SecurityCoreBridge.ProtectionLevel,
                  passphrase: String) -> SecurityCoreBridge.VaultResult {
        SecurityCoreBridge.vaultAdd(securityDir: securityDir, paths: paths,
                                    protection: protection, passphrase: passphrase)
    }

    /// Unlock files.
    func unlockFiles(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        SecurityCoreBridge.vaultUnlock(securityDir: securityDir, paths: paths, passphrase: passphrase)
    }

    /// Lock files.
    func lockFiles(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        SecurityCoreBridge.vaultLock(securityDir: securityDir, paths: paths, passphrase: passphrase)
    }

    /// Remove files from vault.
    func removeFiles(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        SecurityCoreBridge.vaultRemove(securityDir: securityDir, paths: paths, passphrase: passphrase)
    }

    /// List vault entries.
    func listEntries(passphrase: String) -> [SecurityCoreBridge.VaultEntry] {
        SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
    }

    /// Change passphrase.
    func changePassphrase(old: String, new: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultChangePassphrase(
            securityDir: securityDir, oldPassphrase: old, newPassphrase: new)
        if result.success { passphrase = new }
        return result
    }

    /// Clear cached passphrase (on app quit or timeout).
    func clearPassphrase() {
        passphrase = nil
        authGate.invalidateSession()
    }

    // MARK: - Passphrase Prompt

    private func promptForPassphrase(title: String, completion: @escaping (String?) -> Void) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "Enter your vault passphrase to continue."
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")

        let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
        input.placeholderString = "Vault passphrase"
        alert.accessoryView = input
        alert.window.initialFirstResponder = input

        let response = alert.runModal()
        if response == .alertFirstButtonReturn && !input.stringValue.isEmpty {
            completion(input.stringValue)
        } else {
            completion(nil)
        }
    }
}
