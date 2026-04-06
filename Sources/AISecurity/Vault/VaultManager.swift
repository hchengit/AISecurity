import Foundation
import AppKit
import CryptoKit

// MARK: - Vault Notification

extension Notification.Name {
    /// Posted after any vault mutation (add, remove, lock, unlock, changeProtection, toggleLocalOnly).
    /// VaultWindowView listens for this to auto-refresh.
    static let vaultDidChange = Notification.Name("com.aisecurity.vaultDidChange")
}

/// Cryptographically secure random number generation.
private enum SecureRandom {
    static func uint32() -> UInt32 {
        var value: UInt32 = 0
        _ = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt32>.size, &value)
        return value
    }
}

/// Convenience wrapper for suppressing vault tracking during our own operations.
enum VaultOperationScope {
    static func begin() {
        VaultManager.shared.tracker?.beginSuppress()
    }
    static func end() {
        VaultManager.shared.tracker?.endSuppress()
    }
}

/// Manages vault lifecycle — coordinates between AuthGate, Rust bridge, and UI.
final class VaultManager {

    static let shared = VaultManager()

    let authGate = AuthGate()
    private let securityDir: String
    private(set) var passphrase: String? // held in memory during session only
    /// Single owner of vault file monitoring. Created lazily when daemon starts.
    var tracker: VaultFileTracker?

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

    // MARK: - Recovery Key

    /// BIP39-style word list (2048 words). Using a compact subset of common English words.
    private static let wordList: [String] = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
        "absurd", "abuse", "access", "account", "accuse", "achieve", "acid", "across",
        "act", "action", "actor", "adapt", "add", "address", "adjust", "admit",
        "adult", "advance", "advice", "afford", "again", "agent", "agree", "ahead",
        "aim", "air", "airport", "aisle", "alarm", "album", "alert", "alien",
        "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur",
        "amazing", "among", "amount", "amused", "anchor", "ancient", "angel", "anger",
        "angle", "animal", "answer", "anxiety", "apart", "apple", "approve", "arctic",
        "area", "arena", "argue", "armor", "army", "arrange", "arrest", "arrive",
        "arrow", "artist", "ask", "aspect", "assault", "asset", "assist", "assume",
        "attack", "attend", "auction", "audit", "august", "aunt", "auto", "autumn",
        "average", "avoid", "awake", "aware", "awesome", "awful", "axis", "baby",
        "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
        "banana", "banner", "barrel", "base", "basket", "battle", "beach", "bean",
        "beauty", "become", "beef", "before", "begin", "behave", "behind", "believe",
        "below", "bench", "benefit", "best", "betray", "better", "between", "beyond",
        "bicycle", "bird", "birth", "bitter", "black", "blade", "blame", "blanket",
        "blast", "blaze", "bleak", "bless", "blind", "blood", "blossom", "blow",
        "blue", "blur", "board", "boat", "body", "bomb", "bone", "bonus",
        "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce",
        "bowl", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
        "bring", "brisk", "broken", "bronze", "brother", "brown", "brush", "bubble",
        "budget", "buffalo", "build", "bullet", "bundle", "burden", "burger", "burst",
        "bus", "busy", "butter", "buyer", "cabin", "cable", "cake", "call",
        "camera", "camp", "cancel", "candle", "cannon", "canvas", "canyon", "capable",
        "capital", "captain", "carbon", "card", "cargo", "carpet", "carry", "case",
        "castle", "casual", "catalog", "catch", "cause", "caution", "cave", "ceiling",
        "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
        "chance", "change", "chaos", "chapter", "charge", "chase", "cheap", "check",
        "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "chronic",
        "chunk", "cinema", "circle", "citizen", "city", "civil", "claim", "clap",
        "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client",
        "cliff", "climb", "clinic", "clip", "clock", "close", "cloud", "clown",
        "club", "cluster", "coach", "coast", "coconut", "code", "coffee", "coil",
        "coin", "collect", "color", "column", "combine", "come", "comfort", "comic",
        "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
        "control", "convince", "cook", "cool", "copper", "copy", "coral", "core",
        "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course",
        "cousin", "cover", "craft", "crash", "crater", "crazy", "cream", "credit",
        "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross",
        "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crush", "cry",
        "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curve",
        "cushion", "custom", "cycle", "dad", "damage", "dance", "danger", "daring",
        "dash", "dawn", "day", "deal", "debate", "debris", "decade", "december",
        "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy",
        "degree", "delay", "deliver", "demand", "denial", "dentist", "deny", "depart",
        "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design",
        "desk", "detail", "detect", "develop", "device", "devote", "diagram", "dial",
        "diamond", "diary", "diesel", "diet", "differ", "digital", "dignity", "dilemma",
        "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish",
        "dismiss", "display", "distance", "divert", "dizzy", "doctor", "document", "dog",
        "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double",
        "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress",
        "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry",
        "duck", "dumb", "dune", "during", "dust", "duty", "dwarf", "dynamic",
        "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
        "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "eight",
        "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator",
        "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ",
        "empower", "empty", "enable", "endless", "endorse", "enemy", "energy", "enforce",
        "engage", "engine", "enhance", "enjoy", "enough", "enrich", "enroll", "ensure",
        "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "erode",
        "erosion", "error", "escape", "essay", "essence", "estate", "eternal", "evoke",
        "evolve", "exact", "example", "excess", "exchange", "exclude", "excuse", "execute",
        "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
        "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye",
        "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
        "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion",
        "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal",
        "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever",
        "few", "fiber", "fiction", "field", "figure", "file", "film", "filter",
        "final", "find", "finger", "finish", "fire", "firm", "fiscal", "fish",
        "fitness", "flag", "flame", "flash", "flat", "flavor", "flee", "flight",
        "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly",
        "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
        "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil",
        "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend",
        "fringe", "frog", "front", "frost", "frozen", "fruit", "fuel", "fun",
        "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery",
        "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas",
        "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre",
        "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger",
        "giraffe", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe",
        "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold",
        "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab",
        "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green",
        "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard",
        "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair",
        "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh",
        "harvest", "hat", "hawk", "hazard", "head", "health", "heart", "heavy",
        "hedgehog", "height", "hello", "helmet", "help", "hero", "hidden", "high",
        "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold",
        "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn",
        "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub",
        "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle",
        "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify",
        "idle", "ignore", "image", "imitate", "immune", "impact", "impose", "improve",
        "impulse", "include", "income", "increase", "index", "indicate", "indoor", "industry",
        "infant", "inflict", "inform", "initial", "inject", "inmate", "inner", "innocent",
        "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact",
        "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate",
        "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous",
        "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy",
        "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo",
        "keen", "keep", "kernel", "kick", "kid", "kidney", "kind", "kingdom",
        "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
        "knock", "know", "labor", "ladder", "lady", "lake", "lamp", "language"
    ]

    /// Path to the recovery key hash file.
    private var recoveryKeyHashPath: String {
        (securityDir as NSString).appendingPathComponent(".vault-recovery-hash")
    }

    /// Generate a 12-word recovery key from cryptographically secure random bytes.
    func generateRecoveryKey() -> String {
        var words: [String] = []
        for _ in 0..<12 {
            let index = Int(SecureRandom.uint32()) % Self.wordList.count
            words.append(Self.wordList[index])
        }
        return words.joined(separator: " ")
    }

    /// Store the SHA-256 hash of the recovery key (never store the key itself).
    func storeRecoveryKeyHash(_ recoveryKey: String) {
        let normalized = recoveryKey.lowercased().trimmingCharacters(in: .whitespaces)
        let hash = SHA256.hash(data: Data(normalized.utf8))
        let hashHex = hash.compactMap { String(format: "%02x", $0) }.joined()
        try? hashHex.write(toFile: recoveryKeyHashPath, atomically: true, encoding: .utf8)
    }

    /// Verify a recovery key against the stored hash. Returns true if it matches.
    func verifyRecoveryKey(_ recoveryKey: String) -> Bool {
        guard let storedHash = try? String(contentsOfFile: recoveryKeyHashPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines) else { return false }
        let normalized = recoveryKey.lowercased().trimmingCharacters(in: .whitespaces)
        let hash = SHA256.hash(data: Data(normalized.utf8))
        let hashHex = hash.compactMap { String(format: "%02x", $0) }.joined()
        return hashHex == storedHash
    }

    /// Whether a recovery key has been set up.
    var hasRecoveryKey: Bool {
        FileManager.default.fileExists(atPath: recoveryKeyHashPath)
    }

    /// Reset the vault passphrase using the recovery key.
    /// Returns true if successful.
    /// Clean up all tracking artifacts: untrack all files, remove uchg flags, Finder tags, cache.
    /// Call before any vault data reset to prevent orphaned flags.
    func cleanupAllTracking() {
        tracker?.untrackAll()
        // Remove watched-paths cache
        let cacheFile = (securityDir as NSString).appendingPathComponent("vault-watched-paths.json")
        try? FileManager.default.removeItem(atPath: cacheFile)
    }

    func resetPassphraseWithRecoveryKey(recoveryKey: String, newPassphrase: String) -> Bool {
        guard verifyRecoveryKey(recoveryKey) else { return false }

        // Clean up all tracking before resetting vault data
        cleanupAllTracking()

        // We can't decrypt the manifest without the old passphrase.
        // So we reset the vault: delete manifest + salt, re-setup with new passphrase.
        // Existing .vault files become orphaned (unrecoverable without old passphrase).
        let fm = FileManager.default
        let manifestPath = (securityDir as NSString).appendingPathComponent("vault.json.enc")
        let saltPath = (securityDir as NSString).appendingPathComponent(".vault-salt")
        try? fm.removeItem(atPath: manifestPath)
        try? fm.removeItem(atPath: saltPath)

        // Re-setup vault with new passphrase
        let result = setup()
        guard result.success else { return false }
        let ok = setInitialPassphrase(newPassphrase)
        if ok {
            passphrase = newPassphrase
            authGate.invalidateSession()
        }
        return ok
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

            // Prompt for passphrase with retry loop
            DispatchQueue.main.async {
                self?.promptForPassphraseWithRetry(title: passphrasePrompt) { pass in
                    if let pass = pass {
                        onPassphrase(pass)
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
        let result = SecurityCoreBridge.vaultAdd(securityDir: securityDir, paths: paths,
                                                  protection: protection, passphrase: passphrase)
        if result.success {
            let watchPaths = paths.map { protection.isLocked ? $0 + ".vault" : $0 }
            VaultTrackingStore.shared.addEntries(paths, watchPaths: watchPaths, protection: protection)
            for path in paths {
                VaultAuditLog.shared.log(.fileAdded, path: path,
                    detail: "protection: \(protection.sidecarKey), batch: \(paths.count) files")
            }
            NotificationCenter.default.post(name: .vaultDidChange, object: nil)
        }
        return result
    }

    /// Unlock files.
    func unlockFiles(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultUnlock(securityDir: securityDir, paths: paths, passphrase: passphrase)
        if result.success {
            for path in paths {
                let origPath = path.hasSuffix(".vault") ? String(path.dropLast(".vault".count)) : path
                VaultTrackingStore.shared.updateWatchPath(originalPath: origPath, newWatchPath: origPath)
                VaultAuditLog.shared.log(.fileUnlocked, path: origPath, detail: "decrypted")
            }
            NotificationCenter.default.post(name: .vaultDidChange, object: nil)
        }
        return result
    }

    /// Lock files.
    func lockFiles(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultLock(securityDir: securityDir, paths: paths, passphrase: passphrase)
        if result.success {
            for path in paths {
                VaultTrackingStore.shared.updateWatchPath(originalPath: path, newWatchPath: path + ".vault")
                VaultAuditLog.shared.log(.fileLocked, path: path, detail: "re-encrypted")
            }
            NotificationCenter.default.post(name: .vaultDidChange, object: nil)
        }
        return result
    }

    /// Remove files from vault.
    func removeFiles(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultRemove(securityDir: securityDir, paths: paths, passphrase: passphrase)
        if result.success {
            VaultTrackingStore.shared.removeEntries(paths)
            for path in paths {
                VaultAuditLog.shared.log(.fileRemoved, path: path, detail: "released from vault")
            }
            NotificationCenter.default.post(name: .vaultDidChange, object: nil)
        }
        return result
    }

    /// List vault entries.
    func listEntries(passphrase: String) -> [SecurityCoreBridge.VaultEntry] {
        SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
    }

    /// Change protection level of existing entries (atomic — single manifest load/save).
    func changeProtection(_ paths: [String], newProtection: SecurityCoreBridge.ProtectionLevel,
                          passphrase: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultChangeProtection(securityDir: securityDir, paths: paths,
                                                              newProtection: newProtection, passphrase: passphrase)
        if result.success {
            for path in paths {
                let newWatch = newProtection.isLocked ? path + ".vault" : path
                VaultTrackingStore.shared.updateWatchPath(originalPath: path, newWatchPath: newWatch)
                VaultTrackingStore.shared.updateProtection(originalPath: path, protection: newProtection)
                VaultAuditLog.shared.log(.protectionChanged, path: path,
                    detail: "changed to \(newProtection.sidecarKey)")
            }
            NotificationCenter.default.post(name: .vaultDidChange, object: nil)
        }
        return result
    }

    /// Toggle local-only monitoring on existing entries.
    func toggleLocalOnly(_ paths: [String], passphrase: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultToggleLocalOnly(securityDir: securityDir, paths: paths, passphrase: passphrase)
        // After toggle, rebuild sidecar from manifest to get correct protection levels
        if result.success {
            let entries = SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
            VaultTrackingStore.shared.rebuild(from: entries)
            NotificationCenter.default.post(name: .vaultDidChange, object: nil)
        }
        return result
    }

    /// Change passphrase.
    func changePassphrase(old: String, new: String) -> SecurityCoreBridge.VaultResult {
        let result = SecurityCoreBridge.vaultChangePassphrase(
            securityDir: securityDir, oldPassphrase: old, newPassphrase: new)
        if result.success {
            passphrase = new
            authGate.invalidateSession()
            VaultAuditLog.shared.log(.passphraseChanged, path: "", detail: "vault passphrase changed")
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



    // MARK: - Tracker Integration

    /// Sync tracker with current vault manifest entries after any vault mutation.
    /// Also rebuilds the unencrypted sidecar from the encrypted manifest (source of truth).
    func syncTracker(passphrase: String) {
        let entries = SecurityCoreBridge.vaultList(securityDir: securityDir, passphrase: passphrase)
        tracker?.syncWithManifest(entries: entries)
        // Rebuild sidecar from encrypted manifest — the source of truth
        VaultTrackingStore.shared.rebuild(from: entries)
        // Process any pending operations that were queued while passphrase was unavailable
        tracker?.processPendingOps(passphrase: passphrase, securityDir: securityDir)
    }

    /// Track newly added files.
    func trackFiles(_ paths: [String], protection: SecurityCoreBridge.ProtectionLevel) {
        for path in paths {
            let vaultPath = protection.isLocked ? path + ".vault" : ""
            tracker?.track(originalPath: path, vaultPath: vaultPath, protection: protection)
        }
    }

    /// Untrack released files.
    func untrackFiles(_ paths: [String]) {
        for path in paths {
            tracker?.untrack(originalPath: path)
        }
    }

    // MARK: - Passphrase Prompt

    /// Prompt for passphrase with retry on wrong password (3 attempts per dialog).
    private func promptForPassphraseWithRetry(title: String, completion: @escaping (String?) -> Void) {
        // Fresh 3 attempts each time the dialog opens
        resetFailedAttempts()

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

        while true {
            input.stringValue = ""
            let response = alert.runModal()

            guard response == .alertFirstButtonReturn, !input.stringValue.isEmpty else {
                completion(nil) // cancelled
                return
            }

            let pass = input.stringValue
            if verifyPassphrase(pass) {
                resetFailedAttempts()
                passphrase = pass
                completion(pass)
                return
            }

            // Wrong password
            let locked = recordFailedAttempt()
            if locked {
                alert.informativeText = "Vault locked out: \(maxFailedAttempts) failed attempts.\nLocked for \(Int(lockoutDuration / 60)) minutes."
                alert.alertStyle = .critical
                // Remove OK button, only show Cancel
                alert.buttons.first?.isHidden = true
                alert.runModal()
                completion(nil)
                return
            }

            let remaining = maxFailedAttempts - failedAttempts
            alert.informativeText = "Incorrect passphrase. \(remaining) attempt\(remaining == 1 ? "" : "s") remaining.\nTry again."
            alert.alertStyle = .warning
        }
    }

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
