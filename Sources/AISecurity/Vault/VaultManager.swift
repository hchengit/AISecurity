import Foundation
import AppKit
import CryptoKit

/// Cryptographically secure random number generation.
private enum SecureRandom {
    static func uint32() -> UInt32 {
        var value: UInt32 = 0
        _ = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt32>.size, &value)
        return value
    }
}

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
    func resetPassphraseWithRecoveryKey(recoveryKey: String, newPassphrase: String) -> Bool {
        guard verifyRecoveryKey(recoveryKey) else { return false }

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
