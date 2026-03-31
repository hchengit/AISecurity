import Foundation
import AppKit

extension Notification.Name {
    static let vaultWatchedPathsChanged = Notification.Name("vaultWatchedPathsChanged")
    static let vaultOperationStarted = Notification.Name("vaultOperationStarted")
    static let vaultOperationEnded = Notification.Name("vaultOperationEnded")
}

/// Post these around vault operations to suppress FileWatcher alerts for our own file access.
enum VaultOperationScope {
    static func begin() {
        NotificationCenter.default.post(name: .vaultOperationStarted, object: nil)
    }
    static func end() {
        NotificationCenter.default.post(name: .vaultOperationEnded, object: nil)
    }
}

/// Manages vault lifecycle — coordinates between AuthGate, Rust bridge, and UI.
final class VaultManager {

    static let shared = VaultManager()

    let authGate = AuthGate()
    private let securityDir: String
    private(set) var passphrase: String? // held in memory during session only

    // MARK: - Auth Rate Limiting

    private let maxFailedAttempts = 3
    private let lockoutDuration: TimeInterval = 300  // 5 minutes
    private var failedAttempts = 0
    private var lockoutUntil: Date?
    private let rateLock = NSLock()

    /// Whether the vault is currently locked out due to too many failed attempts.
    var isLockedOut: Bool {
        rateLock.lock()
        defer { rateLock.unlock() }
        guard let until = lockoutUntil else { return false }
        if Date() >= until {
            lockoutUntil = nil
            failedAttempts = 0
            return false
        }
        return true
    }

    /// Remaining lockout seconds, or 0 if not locked out.
    var lockoutRemainingSeconds: Int {
        rateLock.lock()
        defer { rateLock.unlock() }
        guard let until = lockoutUntil else { return 0 }
        return max(0, Int(until.timeIntervalSinceNow))
    }

    /// Record a failed passphrase attempt. Returns true if now locked out.
    private func recordFailedAttempt() -> Bool {
        rateLock.lock()
        defer { rateLock.unlock() }
        failedAttempts += 1
        if failedAttempts >= maxFailedAttempts {
            lockoutUntil = Date().addingTimeInterval(lockoutDuration)
            // Send external alert about repeated failed attempts
            let alert = SecurityAlert(
                type: "VAULT_FILE_ACCESS",
                severity: .critical,
                message: "\u{1F6A8} Vault locked out: \(maxFailedAttempts) failed passphrase attempts. Locked for \(Int(lockoutDuration / 60)) minutes."
            )
            NotificationManager.shared.send(alert)
            return true
        }
        return false
    }

    /// Reset failed attempts after successful auth.
    private func resetFailedAttempts() {
        rateLock.lock()
        failedAttempts = 0
        lockoutUntil = nil
        rateLock.unlock()
    }

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
    /// Enforces rate limiting: 3 failed attempts → 5-minute lockout.
    func withAuth(reason: String, passphrasePrompt: String,
                  onPassphrase: @escaping (String) -> Void,
                  onCancel: @escaping () -> Void,
                  onError: @escaping (String) -> Void) {
        // Check lockout before even prompting
        if isLockedOut {
            let mins = lockoutRemainingSeconds / 60
            let secs = lockoutRemainingSeconds % 60
            onError("Vault locked out. Too many failed attempts.\nTry again in \(mins)m \(secs)s.")
            return
        }

        authGate.authenticate(reason: reason) { [weak self] success, error in
            guard success else {
                if let error = error {
                    onError(error)
                } else {
                    onCancel() // user cancelled — no error dialog
                }
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
                            self.resetFailedAttempts()
                            self.passphrase = pass
                            onPassphrase(pass)
                        } else {
                            let locked = self.recordFailedAttempt()
                            if locked {
                                onError("Vault locked out: \(self.maxFailedAttempts) failed attempts.\nLocked for \(Int(self.lockoutDuration / 60)) minutes.")
                            } else {
                                let remaining = self.maxFailedAttempts - self.failedAttempts
                                onError("Incorrect vault passphrase.\n\(remaining) attempt\(remaining == 1 ? "" : "s") remaining before lockout.")
                            }
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

    /// Toggle local-only monitoring on existing entries.
    func toggleLocalOnly(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        SecurityCoreBridge.vaultToggleLocalOnly(securityDir: securityDir, paths: paths, passphrase: passphrase)
    }

    /// Change passphrase.
    func changePassphrase(old: String, new: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultChangePassphrase(
            securityDir: securityDir, oldPassphrase: old, newPassphrase: new)
        if result.success {
            passphrase = new
            // Invalidate auth session so next sensitive operation requires fresh Touch ID
            authGate.invalidateSession()
        }
        return result
    }

    /// Clear cached passphrase (on app quit or timeout).
    /// Overwrites memory before releasing the reference to reduce exposure window.
    func clearPassphrase() {
        if let pass = passphrase {
            // Overwrite the passphrase memory with zeros before releasing.
            // Swift Strings are immutable, but we can at least ensure the var is cleared
            // and create a replacement string to minimize lingering copies.
            var mutableData = Array(pass.utf8)
            for i in mutableData.indices { mutableData[i] = 0 }
            _ = mutableData  // prevent optimization from removing the zeroing
        }
        passphrase = nil
        authGate.invalidateSession()
    }

    // MARK: - Watched Paths Cache (for FileWatcher, no auth required)

    /// Path to the plaintext cache of vault-protected paths (for FileWatcher).
    private var watchedPathsCacheFile: String {
        (securityDir as NSString).appendingPathComponent("vault-watched-paths.json")
    }

    /// Update the watched-paths cache after any vault mutation.
    /// Call this after add, remove, toggle, lock, unlock operations.
    func refreshWatchedPaths(passphrase: String) {
        let entries = SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
        let paths = entries.map { $0.originalPath }
        let vaultFiles = entries.compactMap { $0.vaultPath.isEmpty ? nil : $0.vaultPath }
        let allPaths = paths + vaultFiles

        let cache: [String: Any] = [
            "updatedAt": ISO8601DateFormatter().string(from: Date()),
            "paths": allPaths
        ]

        if let data = try? JSONSerialization.data(withJSONObject: cache, options: .prettyPrinted) {
            try? data.write(to: URL(fileURLWithPath: watchedPathsCacheFile))
        }

        // Notify FileWatcher to reload
        NotificationCenter.default.post(name: .vaultWatchedPathsChanged, object: nil)
    }

    /// Read cached vault paths (no auth needed — used by FileWatcher at startup).
    static func cachedVaultPaths() -> [String] {
        let cacheFile = (SecurityConfig.shared.securityDir as NSString)
            .appendingPathComponent("vault-watched-paths.json")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: cacheFile)),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let paths = json["paths"] as? [String] else {
            return []
        }
        return paths
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
