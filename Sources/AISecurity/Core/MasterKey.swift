import Foundation
import Security

/// Manages the process-wide 32-byte master key used by the Rust crypto core
/// to encrypt app-internal data (whitelist, model manifest, etc.).
///
/// The key is stored in the macOS login Keychain as a generic password item,
/// pinned to this device only and readable only when the Keychain is unlocked.
/// On first run it is generated from `SecRandomCopyBytes`. There is no
/// fallback to a default passphrase — if the key cannot be read or created,
/// callers must fail closed.
enum MasterKey {

    /// Keychain service identifier — must match the app bundle ID.
    private static let service = "com.aisecurity.shield"
    /// Account identifier for the master key record.
    private static let account = "master-key-v1"

    /// Result of installing the master key.
    enum InstallResult {
        case installedExisting     // key was already in Keychain
        case installedGenerated    // key was freshly generated and stored
        case failed(String)        // something went wrong
    }

    /// Ensure a 32-byte key exists in the Keychain and push it into the Rust
    /// crypto core via `sec_set_master_key`. Call this exactly once, as early
    /// as possible in `AISecurityApp.applicationDidFinishLaunching`, BEFORE
    /// any code that triggers whitelist/manifest load.
    static func install() -> InstallResult {
        // If we already installed in this process (hot reload, etc.), don't redo.
        if SecurityCoreBridge.hasMasterKey() {
            return .installedExisting
        }

        let (keyBytes, wasGenerated): (Data, Bool)
        switch loadFromKeychain() {
        case .success(let data):
            keyBytes = data
            wasGenerated = false
        case .notFound:
            guard let fresh = generate() else {
                return .failed("SecRandomCopyBytes failed")
            }
            if case .failure(let msg) = storeInKeychain(fresh) {
                return .failed("Keychain store failed: \(msg)")
            }
            keyBytes = fresh
            wasGenerated = true
        case .failure(let msg):
            return .failed("Keychain read failed: \(msg)")
        }

        guard keyBytes.count == 32 else {
            return .failed("Master key wrong size: \(keyBytes.count) bytes")
        }

        let hex = keyBytes.map { String(format: "%02x", $0) }.joined()
        guard SecurityCoreBridge.setMasterKey(hex) else {
            return .failed("sec_set_master_key rejected the key")
        }

        return wasGenerated ? .installedGenerated : .installedExisting
    }

    // MARK: - Keychain I/O

    private enum LoadResult {
        case success(Data)
        case notFound
        case failure(String)
    }

    private static func loadFromKeychain() -> LoadResult {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     account,
            kSecReturnData as String:      true,
            kSecMatchLimit as String:      kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                return .failure("Keychain returned non-Data type")
            }
            return .success(data)
        case errSecItemNotFound:
            return .notFound
        default:
            return .failure("OSStatus \(status)")
        }
    }

    private enum StoreResult { case success; case failure(String) }

    private static func storeInKeychain(_ data: Data) -> StoreResult {
        // Delete any stale entry first (shouldn't exist, but be defensive).
        let deleteQuery: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     account
        ]
        _ = SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     account,
            kSecValueData as String:       data,
            // Device-bound, requires unlock. Not synced to iCloud.
            kSecAttrAccessible as String:  kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        return status == errSecSuccess ? .success : .failure("OSStatus \(status)")
    }

    private static func generate() -> Data? {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { return nil }
        return Data(bytes)
    }
}
