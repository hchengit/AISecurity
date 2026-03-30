import Foundation
import LocalAuthentication

/// Authentication gate for vault operations.
/// Uses Touch ID, Apple Watch, or system password via LocalAuthentication framework.
/// Auth sessions are cached for a configurable window to avoid repeated prompts.
final class AuthGate {

    /// How long an auth session remains valid (seconds).
    private let sessionTimeout: TimeInterval
    private var lastAuthTime: Date?
    private let lock = NSLock()

    init(sessionTimeoutSeconds: TimeInterval = 300) { // 5 minutes default
        self.sessionTimeout = sessionTimeoutSeconds
    }

    /// Check if there's a valid cached auth session.
    var isSessionValid: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let last = lastAuthTime else { return false }
        return Date().timeIntervalSince(last) < sessionTimeout
    }

    /// Authenticate the user. Uses cached session if still valid.
    /// Calls completion on main thread: true = authenticated, false = denied/failed.
    func authenticate(reason: String, completion: @escaping (Bool, String?) -> Void) {
        // Check cached session first
        if isSessionValid {
            completion(true, nil)
            return
        }

        let context = LAContext()
        context.localizedCancelTitle = "Cancel"

        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            completion(false, error?.localizedDescription ?? "Authentication not available")
            return
        }

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, authError in
            DispatchQueue.main.async {
                if success {
                    self?.lock.lock()
                    self?.lastAuthTime = Date()
                    self?.lock.unlock()
                    completion(true, nil)
                } else {
                    let msg = authError?.localizedDescription ?? "Authentication failed"
                    completion(false, msg)
                }
            }
        }
    }

    /// Invalidate the current auth session.
    func invalidateSession() {
        lock.lock()
        lastAuthTime = nil
        lock.unlock()
    }
}
