import Foundation
import CSecurityCore

// MARK: - SecurityCoreBridge
// Thin Swift wrapper around the Rust security-core FFI.
// Handles String↔CChar conversion and memory management.

enum SecurityCoreBridge {

    // MARK: - Init

    /// Warm up Rust lazy statics. Call once at startup.
    static func initialize() {
        sec_init(nil)
    }

    // MARK: - Intent Parser

    struct IntentResult: Sendable {
        let isThreat: Bool
        let severity: SeverityLevel?
        let layersFired: Int
        let score: Int  // weighted score out of 100
        let layers: Layers
        let label: String
        let confidence: String

        struct Layers: Sendable {
            let l1, l2, l3, l4, l5, l6: Bool
        }
    }

    enum Channel: UInt8, Sendable {
        case email = 0
        case sms = 1
    }

    static func parseIntent(_ text: String, channel: Channel = .email) -> IntentResult {
        let ptr = text.withCString { sec_parse_intent($0, channel.rawValue) }
        guard let r = ptr else {
            return IntentResult(isThreat: false, severity: nil, layersFired: 0, score: 0,
                                layers: .init(l1: false, l2: false, l3: false, l4: false, l5: false, l6: false),
                                label: "", confidence: "0%")
        }
        defer { sec_free_intent_result(ptr) }
        let p = r.pointee
        return IntentResult(
            isThreat: p.is_threat,
            severity: severityFromI8(p.severity),
            layersFired: Int(p.layers_fired),
            score: Int(p.score),
            layers: .init(l1: p.l1, l2: p.l2, l3: p.l3, l4: p.l4, l5: p.l5, l6: p.l6),
            label: safeString(p.label),
            confidence: safeString(p.confidence)
        )
    }

    // MARK: - Sensitive Data Scanner

    struct Finding: Sendable {
        let type: String
        let label: String
        let severity: SeverityLevel
        let category: String
        let source: String
        let matchPreview: String
        let offset: Int
    }

    static func scanSensitiveData(_ text: String, source: String = "unknown") -> [Finding] {
        let ptr = text.withCString { t in
            source.withCString { s in
                sec_scan_sensitive_data(t, s)
            }
        }
        guard let arr = ptr else { return [] }
        defer { sec_free_findings(ptr) }
        let a = arr.pointee
        guard a.count > 0, a.items != nil else { return [] }
        return (0..<Int(a.count)).map { i in
            let f = a.items[i]
            return Finding(
                type: safeString(f.finding_type),
                label: safeString(f.label),
                severity: severityFromI8(f.severity) ?? .high,
                category: safeString(f.category),
                source: safeString(f.source),
                matchPreview: safeString(f.match_preview),
                offset: Int(f.offset)
            )
        }
    }

    // MARK: - Prompt Injection

    struct ValidationResult: Sendable {
        let safe: Bool
        let reason: String?
        let severity: SeverityLevel?
        let category: String?
    }

    struct SanitizationResult: Sendable {
        let sanitized: String
        let modified: Bool
        let changes: [String]
    }

    static func validatePrompt(_ text: String, source: String = "unknown") -> ValidationResult {
        let ptr = text.withCString { t in
            source.withCString { s in
                sec_validate_prompt(t, s)
            }
        }
        guard let r = ptr else {
            return ValidationResult(safe: true, reason: nil, severity: nil, category: nil)
        }
        defer { sec_free_validation_result(ptr) }
        let p = r.pointee
        return ValidationResult(
            safe: p.safe,
            reason: optionalString(p.reason),
            severity: severityFromI8(p.severity),
            category: optionalString(p.category)
        )
    }

    static func sanitizeText(_ text: String) -> SanitizationResult {
        let ptr = text.withCString { sec_sanitize_text($0) }
        guard let r = ptr else {
            return SanitizationResult(sanitized: text, modified: false, changes: [])
        }
        defer { sec_free_sanitization_result(ptr) }
        let p = r.pointee
        let changesJSON = safeString(p.changes_json)
        let changes = (try? JSONDecoder().decode([String].self, from: Data(changesJSON.utf8))) ?? []
        return SanitizationResult(
            sanitized: safeString(p.sanitized),
            modified: p.modified,
            changes: changes
        )
    }

    // MARK: - File Content Scanner

    struct Threat: Sendable {
        let type: String
        let label: String
        let severity: SeverityLevel
        let category: String
    }

    static func scanFileContent(_ text: String) -> [Threat] {
        let ptr = text.withCString { sec_scan_file_content($0) }
        return threatsFromFFI(ptr)
    }

    // MARK: - Email Analyzer

    static func analyzeEmail(_ text: String) -> [Threat] {
        let ptr = text.withCString { sec_analyze_email($0) }
        return threatsFromFFI(ptr)
    }

    // MARK: - Message Analyzer

    static func analyzeMessage(_ text: String) -> [Threat] {
        let ptr = text.withCString { sec_analyze_message($0) }
        return threatsFromFFI(ptr)
    }

    // MARK: - Helpers

    private static func severityFromI8(_ val: Int8) -> SeverityLevel? {
        switch val {
        case 1: return .low
        case 2: return .medium
        case 3: return .high
        case 4: return .critical
        default: return nil
        }
    }

    private static func optionalString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr = ptr else { return nil }
        return String(cString: ptr)
    }

    /// Safe C string conversion — returns empty string instead of crashing on null.
    private static func safeString(_ ptr: UnsafePointer<CChar>?) -> String {
        guard let ptr = ptr else { return "" }
        return String(cString: ptr)
    }

    /// Run a closure with a C-string view of an optional Swift String.
    /// A nil input is forwarded to the closure as a null `const char *`.
    private static func withOptionalCString<R>(
        _ s: String?,
        _ body: (UnsafePointer<CChar>?) -> R
    ) -> R {
        if let s = s {
            return s.withCString { body($0) }
        } else {
            return body(nil)
        }
    }

    /// Safe C string conversion for mutable pointers.
    private static func safeString(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
        guard let ptr = ptr else { return "" }
        return String(cString: ptr)
    }

    // MARK: - Vault

    enum ProtectionLevel: UInt8, Sendable {
        case locked = 0
        case readOnly = 1
        case localOnly = 2
        case readOnlyLocal = 3
        case lockedLocal = 4

        var label: String {
            switch self {
            case .locked: return "Locked (encrypted)"
            case .readOnly: return "Read-only"
            case .localOnly: return "Local-only"
            case .readOnlyLocal: return "Read-only + Local-only"
            case .lockedLocal: return "Locked + Local-only"
            }
        }

        /// Whether this protection includes encryption.
        var isLocked: Bool {
            self == .locked || self == .lockedLocal
        }

        /// Whether this protection includes read-only.
        var isReadOnly: Bool {
            self == .readOnly || self == .readOnlyLocal
        }

        /// Whether this protection includes local-only monitoring.
        var isLocalOnly: Bool {
            self == .localOnly || self == .readOnlyLocal || self == .lockedLocal
        }
    }

    struct VaultResult: Sendable {
        let success: Bool
        let message: String
        let entriesAffected: Int
    }

    struct VaultEntry: Sendable {
        let originalPath: String
        let vaultPath: String
        let protection: ProtectionLevel
        let encryptedAt: String
        let sizeBytes: UInt64
        let isDirectory: Bool
        let isUnlocked: Bool
    }

    static func vaultIsSetup(securityDir: String) -> Bool {
        securityDir.withCString { sec_vault_is_setup($0) }
    }

    static func vaultSetup(securityDir: String) -> VaultResult {
        let ptr = securityDir.withCString { sec_vault_setup($0) }
        return vaultResultFromFFI(ptr)
    }

    static func vaultSetPassphrase(securityDir: String, passphrase: String) -> Bool {
        securityDir.withCString { d in
            passphrase.withCString { p in
                sec_vault_set_passphrase(d, p)
            }
        }
    }

    static func vaultVerifyPassphrase(securityDir: String, passphrase: String) -> Bool {
        securityDir.withCString { d in
            passphrase.withCString { p in
                sec_vault_verify_passphrase(d, p)
            }
        }
    }

    static func vaultAdd(securityDir: String, paths: [String], protection: ProtectionLevel, passphrase: String) -> VaultResult {
        let joined = paths.joined(separator: "\n")
        let ptr = securityDir.withCString { d in
            joined.withCString { p in
                passphrase.withCString { pass in
                    sec_vault_add(d, p, protection.rawValue, pass)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    static func vaultUnlock(securityDir: String, paths: [String], passphrase: String) -> VaultResult {
        let joined = paths.joined(separator: "\n")
        let ptr = securityDir.withCString { d in
            joined.withCString { p in
                passphrase.withCString { pass in
                    sec_vault_unlock(d, p, pass)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    static func vaultLock(securityDir: String, paths: [String], passphrase: String) -> VaultResult {
        let joined = paths.joined(separator: "\n")
        let ptr = securityDir.withCString { d in
            joined.withCString { p in
                passphrase.withCString { pass in
                    sec_vault_lock(d, p, pass)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    static func vaultRemove(securityDir: String, paths: [String], passphrase: String) -> VaultResult {
        let joined = paths.joined(separator: "\n")
        let ptr = securityDir.withCString { d in
            joined.withCString { p in
                passphrase.withCString { pass in
                    sec_vault_remove(d, p, pass)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    static func vaultList(securityDir: String, passphrase: String) -> [VaultEntry] {
        let ptr = securityDir.withCString { d in
            passphrase.withCString { p in
                sec_vault_list(d, p)
            }
        }
        guard let arr = ptr else { return [] }
        defer { sec_free_vault_entries(ptr) }
        let a = arr.pointee
        guard a.count > 0, a.items != nil else { return [] }
        return (0..<Int(a.count)).map { i in
            let e = a.items[i]
            return VaultEntry(
                originalPath: safeString(e.original_path),
                vaultPath: safeString(e.vault_path),
                protection: ProtectionLevel(rawValue: e.protection) ?? .locked,
                encryptedAt: safeString(e.encrypted_at),
                sizeBytes: e.size_bytes,
                isDirectory: e.is_directory,
                isUnlocked: e.is_unlocked
            )
        }
    }

    static func vaultChangePassphrase(securityDir: String, oldPassphrase: String, newPassphrase: String) -> VaultResult {
        let ptr = securityDir.withCString { d in
            oldPassphrase.withCString { old in
                newPassphrase.withCString { new in
                    sec_vault_change_passphrase(d, old, new)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    static func vaultChangeProtection(securityDir: String, paths: [String],
                                       newProtection: ProtectionLevel, passphrase: String) -> VaultResult {
        let joined = paths.joined(separator: "\n")
        let ptr = securityDir.withCString { d in
            joined.withCString { p in
                passphrase.withCString { pass in
                    sec_vault_change_protection(d, p, newProtection.rawValue, pass)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    static func vaultToggleLocalOnly(securityDir: String, paths: [String], passphrase: String) -> VaultResult {
        let joined = paths.joined(separator: "\n")
        let ptr = securityDir.withCString { d in
            joined.withCString { p in
                passphrase.withCString { pass in
                    sec_vault_toggle_local_only(d, p, pass)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    /// Add files with progress callback. The callback returns false to cancel.
    static func vaultAddWithProgress(
        securityDir: String, paths: [String],
        protection: ProtectionLevel, passphrase: String,
        callback: @escaping @convention(c) (UInt32, UInt32, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Bool,
        userData: UnsafeMutableRawPointer?
    ) -> VaultResult {
        let joined = paths.joined(separator: "\n")
        let ptr = securityDir.withCString { d in
            joined.withCString { p in
                passphrase.withCString { pass in
                    sec_vault_add_with_progress(d, p, protection.rawValue, pass, callback, userData)
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    static func vaultUpdatePath(securityDir: String, oldPath: String, newPath: String, passphrase: String) -> VaultResult {
        let ptr = securityDir.withCString { d in
            oldPath.withCString { o in
                newPath.withCString { n in
                    passphrase.withCString { pass in
                        sec_vault_update_path(d, o, n, pass)
                    }
                }
            }
        }
        return vaultResultFromFFI(ptr)
    }

    private static func vaultResultFromFFI(_ ptr: UnsafeMutablePointer<VaultResultFFI>?) -> VaultResult {
        guard let r = ptr else {
            return VaultResult(success: false, message: "FFI call failed", entriesAffected: 0)
        }
        defer { sec_free_vault_result(ptr) }
        let p = r.pointee
        return VaultResult(
            success: p.success,
            message: safeString(p.message),
            entriesAffected: Int(p.entries_affected)
        )
    }

    // MARK: - Protection Tier

    /// Get the current protection tier from config.toml.
    static func getProtectionTier(configPath: String? = nil) -> ProtectionTier {
        let path = configPath ?? SecurityConfig.shared.configFilePath
        let raw = path.withCString { sec_get_protection_tier($0) }
        return ProtectionTier.from(rawValue: Int(raw))
    }

    /// Set the protection tier in config.toml. Returns true on success.
    static func setProtectionTier(_ tier: ProtectionTier, configPath: String? = nil) -> Bool {
        let path = configPath ?? SecurityConfig.shared.configFilePath
        return path.withCString { sec_set_protection_tier($0, Int8(tier.rustValue)) }
    }

    /// Get the fully resolved effective security config from Rust.
    static func getEffectiveConfig(configPath: String? = nil) -> EffectiveSecurityConfig? {
        let path = configPath ?? SecurityConfig.shared.configFilePath
        let ptr = path.withCString { sec_get_effective_config($0) }
        guard ptr != nil else { return nil }
        defer { sec_free_string(ptr) }
        let json = String(cString: ptr!)
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(EffectiveSecurityConfig.self, from: data)
    }

    // MARK: - Encryption Helpers

    /// Install the process-global master key (32 bytes, hex-encoded = 64 chars)
    /// into the Rust crypto core. Called once at startup by MasterKey.install().
    static func setMasterKey(_ hex: String) -> Bool {
        return hex.withCString { sec_set_master_key($0) }
    }

    /// True iff the Rust core has a master key installed.
    static func hasMasterKey() -> Bool {
        return sec_has_master_key()
    }

    /// Encrypt a JSON string for whitelist storage (AES-256-GCM with WHITELIST AAD).
    /// Returns nil if the master key is not installed — callers MUST NOT fall
    /// back to plaintext storage.
    static func encryptWhitelist(_ json: String) -> String? {
        let ptr = json.withCString { sec_encrypt_whitelist($0) }
        guard ptr != nil else { return nil }
        defer { sec_free_string(ptr) }
        return String(cString: ptr!)
    }

    /// Decrypt a hex string from whitelist storage.
    static func decryptWhitelist(_ hex: String) -> String? {
        let ptr = hex.withCString { sec_decrypt_whitelist($0) }
        guard ptr != nil else { return nil }
        defer { sec_free_string(ptr) }
        return String(cString: ptr!)
    }

    /// MIGRATION ONLY: try decrypting a whitelist blob that was encrypted with
    /// the pre-master-key legacy default passphrase. Returns the plaintext JSON
    /// on success so the caller can re-encrypt with the current master key.
    static func decryptWhitelistLegacy(_ hex: String) -> String? {
        let ptr = hex.withCString { sec_decrypt_whitelist_legacy($0) }
        guard ptr != nil else { return nil }
        defer { sec_free_string(ptr) }
        return String(cString: ptr!)
    }

    // MARK: - Command Policy Engine

    enum CommandDecision: Int8, Sendable {
        case allow = 0
        case deny = 1
        case ask = 2
    }

    struct CommandCheckResult: Sendable {
        let decision: CommandDecision
        let reason: String
        let matchedRule: String
    }

    /// Check a command against the policy engine.
    static func commandCheck(_ command: String, configPath: String? = nil) -> CommandCheckResult {
        let path = configPath ?? SecurityConfig.shared.configFilePath
        let ptr = command.withCString { cmd in
            path.withCString { cfg in
                sec_command_check(cmd, cfg)
            }
        }
        guard let r = ptr else {
            return CommandCheckResult(decision: .ask, reason: "FFI call failed", matchedRule: "error")
        }
        defer { sec_free_command_check(ptr) }
        let p = r.pointee
        return CommandCheckResult(
            decision: CommandDecision(rawValue: p.decision) ?? .ask,
            reason: safeString(p.reason),
            matchedRule: safeString(p.matched_rule)
        )
    }

    // MARK: - Model Weight Verifier

    /// Verify all tracked model files. Returns JSON string of verification results.
    static func modelVerify(securityDir: String? = nil) -> String? {
        let dir = securityDir ?? SecurityConfig.shared.securityDir
        let ptr = dir.withCString { sec_model_verify($0) }
        guard ptr != nil else { return nil }
        defer { sec_free_string(ptr) }
        return String(cString: ptr!)
    }

    /// Discover model directories by scanning home + /Volumes/.
    /// Persists results to model-directories.json. Returns JSON array of directory paths.
    static func modelDiscoverDirs(securityDir: String? = nil) -> [String] {
        let dir = securityDir ?? SecurityConfig.shared.securityDir
        let ptr = dir.withCString { sec_model_discover_dirs($0) }
        guard ptr != nil else { return [] }
        defer { sec_free_string(ptr) }
        let json = String(cString: ptr!)
        guard let data = json.data(using: .utf8),
              let dirs = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return dirs
    }

    /// Scan for model files. Returns JSON string of discovered paths.
    static func modelScan(securityDir: String? = nil) -> String? {
        let dir = securityDir ?? SecurityConfig.shared.securityDir
        let ptr = dir.withCString { sec_model_scan($0) }
        guard ptr != nil else { return nil }
        defer { sec_free_string(ptr) }
        return String(cString: ptr!)
    }

    // MARK: - Threat Intelligence Feeds

    struct FeedCheckResult: Sendable {
        let threatLevel: Int8   // -1 = no match, 1-4 = Low..Critical
        let feedName: String?
        let indicator: String?
        var isMatch: Bool { threatLevel > 0 }
    }

    /// Initialize threat feeds database.
    static func feedInit(securityDir: String? = nil) -> Bool {
        let dir = securityDir ?? SecurityConfig.shared.securityDir
        return dir.withCString { sec_feed_init($0) }
    }

    /// Check a URL against threat feeds.
    static func feedCheckUrl(_ url: String) -> FeedCheckResult {
        let ptr = url.withCString { sec_feed_check_url($0) }
        guard let r = ptr else {
            return FeedCheckResult(threatLevel: -1, feedName: nil, indicator: nil)
        }
        defer { sec_free_feed_check(ptr) }
        let p = r.pointee
        return FeedCheckResult(
            threatLevel: p.threat_level,
            feedName: optionalString(p.feed_name),
            indicator: optionalString(p.indicator)
        )
    }

    /// Check a domain against threat feeds.
    static func feedCheckDomain(_ domain: String) -> FeedCheckResult {
        let ptr = domain.withCString { sec_feed_check_domain($0) }
        guard let r = ptr else {
            return FeedCheckResult(threatLevel: -1, feedName: nil, indicator: nil)
        }
        defer { sec_free_feed_check(ptr) }
        let p = r.pointee
        return FeedCheckResult(
            threatLevel: p.threat_level,
            feedName: optionalString(p.feed_name),
            indicator: optionalString(p.indicator)
        )
    }

    /// Refresh all threat feeds (BLOCKING — call from background thread).
    static func feedRefresh() -> Int32 {
        sec_feed_refresh()
    }

    /// Get total entries across all feeds.
    static func feedTotalEntries() -> UInt32 {
        sec_feed_total_entries()
    }

    // MARK: - Local HTTP Services (privacy_router + intent_verifier)

    struct LocalServicesStart: Sendable {
        let ok: Bool
        let boundAddr: String?
    }

    /// Start the in-process HTTP listener serving POST /privacy/evaluate,
    /// POST /intent/verify, and GET /health on a detached thread. Idempotent
    /// — calling more than once returns the prior bound address.
    ///
    /// - Parameters:
    ///   - bindAddr: e.g. "127.0.0.1:7459". Use "127.0.0.1:0" to let the OS
    ///     pick a free port (mainly for tests).
    ///   - configPath: optional; nil uses the default config location.
    ///   - auditLogPath: optional; nil disables audit logging.
    @discardableResult
    static func localServicesStart(
        bindAddr: String = "127.0.0.1:7459",
        configPath: String? = nil,
        auditLogPath: String? = nil
    ) -> LocalServicesStart {
        let ptr: UnsafeMutablePointer<LocalServicesStartResult>? = bindAddr.withCString { ba in
            withOptionalCString(configPath) { cp in
                withOptionalCString(auditLogPath) { al in
                    sec_local_services_start(ba, cp, al)
                }
            }
        }
        guard let r = ptr else {
            return LocalServicesStart(ok: false, boundAddr: nil)
        }
        defer { sec_free_local_services_start_result(ptr) }
        let p = r.pointee
        return LocalServicesStart(ok: p.ok, boundAddr: optionalString(p.bound_addr))
    }

    /// True iff the listener is running in this process.
    static func localServicesIsRunning() -> Bool {
        sec_local_services_is_running()
    }

    // MARK: - Policy Audit Log

    /// Log a policy decision to the audit log.
    static func auditLog(securityDir: String? = nil, entryJson: String) -> Bool {
        let dir = securityDir ?? SecurityConfig.shared.securityDir
        return dir.withCString { d in
            entryJson.withCString { j in
                sec_audit_log(d, j)
            }
        }
    }

    // MARK: - Helpers

    private static func threatsFromFFI(_ ptr: UnsafeMutablePointer<ThreatsArrayFFI>?) -> [Threat] {
        guard let arr = ptr else { return [] }
        defer { sec_free_threats(ptr) }
        let a = arr.pointee
        guard a.count > 0, a.items != nil else { return [] }
        return (0..<Int(a.count)).map { i in
            let t = a.items[i]
            return Threat(
                type: safeString(t.threat_type),
                label: safeString(t.label),
                severity: severityFromI8(t.severity) ?? .high,
                category: safeString(t.category)
            )
        }
    }
}
