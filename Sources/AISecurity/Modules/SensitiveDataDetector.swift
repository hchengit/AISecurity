import Foundation

/// Scans text and file paths for sensitive personal, financial, and crypto data.
/// Replaces modules/sensitive-data-detector.js — all patterns ported 1:1.
final class SensitiveDataDetector: @unchecked Sendable {

    // MARK: - Types

    struct Finding: Sendable {
        let type: String
        let label: String
        let severity: SeverityLevel
        let category: String
        let source: String
        let matchPreview: String
        let offset: Int
    }

    struct PathCheckResult: Sendable {
        let isProtected: Bool
        let reason: String?
        let severity: SeverityLevel?
    }

    private struct PatternDef {
        let pattern: NSRegularExpression
        let label: String
        let severity: SeverityLevel
        let category: String
    }

    // MARK: - Properties

    private let patterns: [(String, PatternDef)]
    private let lock = NSLock()
    private(set) var totalScans = 0
    private(set) var totalFindings = 0
    private(set) var byCategory: [String: Int] = [:]
    private(set) var bySeverity: [SeverityLevel: Int] = [:]

    // MARK: - Init

    init() {
        var defs: [(String, PatternDef)] = []

        func add(_ key: String, _ pat: String, _ opts: NSRegularExpression.Options = [.caseInsensitive], _ label: String, _ sev: SeverityLevel, _ cat: String) {
            if let regex = try? NSRegularExpression(pattern: pat, options: opts) {
                defs.append((key, PatternDef(pattern: regex, label: label, severity: sev, category: cat)))
            }
        }

        // ── Financial ──────────────────────────────────────────────────
        add("creditCard",
            #"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"#,
            [], "Credit Card Number", .critical, "financial")
        add("bankRoutingNumber",
            #"\b(?:routing|aba|transit)[\s\w]*?:?\s*(\d{9})\b"#,
            [.caseInsensitive], "Bank Routing Number", .critical, "financial")
        add("bankAccountNumber",
            #"\b(?:account|acct|bank acct)[\s\w]*?:?\s*(\d{10,17})\b"#,
            [.caseInsensitive], "Bank Account Number", .critical, "financial")
        add("cvv",
            #"\b(?:cvv|cvc|cvv2|csc|security code)[\s:]*(\d{3,4})\b"#,
            [.caseInsensitive], "Card CVV/CVC", .critical, "financial")

        // ── Personal Identifiers ───────────────────────────────────────
        add("ssn",
            #"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0{4})\d{4}\b"#,
            [], "Social Security Number (SSN)", .critical, "pii")
        add("birthday",
            #"\b(?:dob|date of birth|born|birthday|birth date)[\s:]*(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\w+ \d{1,2},? \d{4})\b"#,
            [.caseInsensitive], "Date of Birth", .high, "pii")
        add("passport",
            #"\b(?:passport(?:\s*(?:no|number|#))?[\s:]*[A-Z]{1,2}\d{6,9})\b"#,
            [.caseInsensitive], "Passport Number", .high, "pii")

        // ── Driver's License ───────────────────────────────────────────
        add("driversLicenseGeneric",
            #"\b(?:driver[''\s]?s?\s+licen[sc]e|drivers?\s+id|dl\s*#?|dmv\s*#?|license\s*(?:no|number|#))[\s:]*([A-Z]{0,2}\d{4,9}[A-Z]{0,2}|\d{3}[-\s]\d{3}[-\s]\d{3})\b"#,
            [.caseInsensitive], "Driver's License Number", .critical, "pii")
        add("driversLicenseCA",
            #"\b(?:ca|california)\s*(?:dl|license|id)[\s:#]*([A-Z]\d{7})\b"#,
            [.caseInsensitive], "Driver's License (California)", .critical, "pii")
        add("driversLicenseNY",
            #"\b(?:ny|new york)\s*(?:dl|license|id)[\s:#]*(\d{9}|\d{3}[-\s]\d{3}[-\s]\d{3})\b"#,
            [.caseInsensitive], "Driver's License (New York)", .critical, "pii")
        add("driversLicenseTX",
            #"\b(?:tx|texas)\s*(?:dl|license|id)[\s:#]*(\d{8})\b"#,
            [.caseInsensitive], "Driver's License (Texas)", .critical, "pii")
        add("driversLicenseFL",
            #"\b(?:fl|florida)\s*(?:dl|license|id)[\s:#]*([A-Z]\d{12})\b"#,
            [.caseInsensitive], "Driver's License (Florida)", .critical, "pii")
        add("driversLicenseWA",
            #"\b(?:wa|washington)\s*(?:dl|license|id)[\s:#]*([A-Z]{2,7}\d{3}[A-Z0-9]{2,5})\b"#,
            [.caseInsensitive], "Driver's License (Washington)", .critical, "pii")

        // ── Crypto / Wallet ────────────────────────────────────────────
        add("bitcoinPrivateKeyWIF",
            #"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"#,
            [], "Bitcoin Private Key (WIF)", .critical, "crypto")
        add("bitcoinXprv",
            #"\bxprv[a-zA-Z0-9]{107}\b"#,
            [], "Bitcoin Extended Private Key (xprv)", .critical, "crypto")
        add("bitcoinZprv",
            #"\bzprv[a-zA-Z0-9]{107}\b"#,
            [], "Bitcoin Segwit Extended Private Key (zprv)", .critical, "crypto")
        add("ethereumPrivateKey",
            #"\b(?:0x)?[0-9a-fA-F]{64}\b"#,
            [], "Ethereum/Crypto Private Key", .critical, "crypto")
        add("seedPhraseMnemonic",
            #"\b(?:seed(?:\s+phrase)?|mnemonic|recovery(?:\s+phrase)?|backup(?:\s+phrase)?|secret(?:\s+phrase)?)[\s:]+([a-z]+(?:\s+[a-z]+){11,23})\b"#,
            [.caseInsensitive], "Cryptocurrency Seed Phrase / Mnemonic", .critical, "crypto")
        add("sparrowWalletKeyword",
            #"\b(?:sparrow[\s._\-]?wallet|\.sparrow|sparrow\.wallet)\b"#,
            [.caseInsensitive], "Sparrow Wallet Reference", .high, "crypto")

        // ── API Keys & Secrets ─────────────────────────────────────────
        add("openAiKey",
            #"\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,}\b"#,
            [], "OpenAI API Key", .critical, "api_key")
        add("anthropicKey",
            #"\bsk-ant-[a-zA-Z0-9\-_]{32,}\b"#,
            [], "Anthropic API Key", .critical, "api_key")
        add("githubToken",
            #"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"#,
            [], "GitHub Personal Access Token", .critical, "api_key")
        add("genericApiKey",
            #"(?:^|[\s;,]|_)(?:API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|CLIENT_SECRET)\s*[=:]\s*["']?([A-Za-z0-9/\+_\-\.]{16,})["']?"#,
            [.caseInsensitive], "API Key / Secret", .critical, "api_key")
        add("password",
            #"\b(?:PASSWORD|PASSWD|PWD|PASS)\s*[=:]\s*["']?([^\s"']{8,})["']?\b"#,
            [.caseInsensitive], "Password in Config/Env", .critical, "credential")
        add("bearerToken",
            #"\bBearer\s+[A-Za-z0-9\-_\.~\+/]+=*\b"#,
            [], "Bearer Token", .high, "api_key")
        add("awsKey",
            #"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b"#,
            [], "AWS Access Key", .critical, "api_key")

        // ── Tax & Financial Documents ──────────────────────────────────
        add("turbotaxReference",
            #"\b(?:turbotax|taxreturn|\.tax20\d{2}|\.tax\b|1040[-\s]?(?:EZ|SR|NR)?|w[-\s]?2\b|1099[-\s]?\w{1,4})\b"#,
            [.caseInsensitive], "Tax Document / TurboTax Reference", .high, "financial")

        // ── macOS App Data Keywords ────────────────────────────────────
        add("passwordManagerRef",
            #"\b(?:bitwarden|1password|lastpass|keychain|aura[\s_]?password|dashlane|keeper)\b"#,
            [.caseInsensitive], "Password Manager Reference", .high, "app_data")
        add("photosRef",
            #"\b(?:Photos\.app|Photos Library|photoslibrary|\.photoslibrary|PHAsset|PHFetchResult|com\.apple\.Photos)\b"#,
            [.caseInsensitive], "Apple Photos Library Reference", .high, "app_data")
        add("calendarData",
            #"\b(?:ics|vcal|vevent|dtstart|dtend|calendar(?:\.app)?)\b"#,
            [.caseInsensitive], "Calendar Data", .medium, "app_data")
        add("appleKeychainRef",
            #"\b(?:keychain|\.keychain-db|secitemcopy|kcitemref)\b"#,
            [.caseInsensitive], "macOS Keychain Reference", .critical, "app_data")

        // ── Environment / Config Files ─────────────────────────────────
        add("envFileSecret",
            #"^[\s#]*(?:DB_PASS|DATABASE_URL|REDIS_URL|MONGO_URI|SECRET|TOKEN|KEY|CERT|PRIVATE)\s*=\s*.+$"#,
            [.caseInsensitive, .anchorsMatchLines], ".env Secret Variable", .critical, "credential")
        add("privateKeyBlock",
            #"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"#,
            [.dotMatchesLineSeparators], "PEM Private Key Block", .critical, "credential")
        add("sshPrivateKey",
            #"-----BEGIN OPENSSH PRIVATE KEY-----"#,
            [], "SSH Private Key", .critical, "credential")

        self.patterns = defs
    }

    // MARK: - Scan Text

    func scanText(_ text: String, source: String = "unknown") -> [Finding] {
        guard !text.isEmpty else { return [] }

        lock.lock()
        totalScans += 1
        lock.unlock()

        let nsText = text as NSString
        let range = NSRange(location: 0, length: nsText.length)
        var findings: [Finding] = []

        for (key, def) in patterns {
            let matches = def.pattern.matches(in: text, range: range)
            for match in matches {
                let matchStr = nsText.substring(with: match.range)
                findings.append(Finding(
                    type: key,
                    label: def.label,
                    severity: def.severity,
                    category: def.category,
                    source: source,
                    matchPreview: redact(matchStr),
                    offset: match.range.location
                ))

                lock.lock()
                totalFindings += 1
                byCategory[def.category, default: 0] += 1
                bySeverity[def.severity, default: 0] += 1
                lock.unlock()
            }
        }

        return findings
    }

    // MARK: - Protected Paths

    static let protectedPaths: [String] = {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return [
            "\(home)/Pictures/Photos Library.photoslibrary",
            "\(home)/Pictures",
            "\(home)/Library/Application Support/com.apple.photoanalysisd",
            "\(home)/Library/Application Support/Photos",
            "\(home)/Library/Application Support/Sparrow",
            "\(home)/.sparrow",
            "\(home)/.bitcoin",
            "\(home)/.lnd",
            "\(home)/Library/Application Support/Bitwarden",
            "\(home)/Library/Application Support/Aura",
            "\(home)/Library/Keychains",
            "\(home)/Library/Mail",
            "\(home)/Library/Messages",
            "\(home)/Library/Group Containers/group.com.apple.notes",
            "\(home)/Library/Calendars",
            "\(home)/.ssh",
            "\(home)/.gnupg",
            "\(home)/Library/Safari",
            "\(home)/Documents/Tax Returns",
            "\(home)/Documents/TurboTax",
        ]
    }()

    static let sensitiveExtensions: Set<String> = [
        ".key", ".pem", ".p12", ".pfx", ".cert", ".crt",
        ".wallet", ".sparrow",
        ".tax", ".tax2022", ".tax2023", ".tax2024",
        ".kdbx",
        ".env", ".envrc",
        ".keychain", ".keychain-db",
        ".asc", ".gpg",
        ".id_rsa", ".id_ed25519", ".id_ecdsa",
        ".photoslibrary",
    ]

    func isProtectedPath(_ filePath: String) -> PathCheckResult {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let normalized = filePath.hasPrefix("~")
            ? home + filePath.dropFirst()
            : filePath

        for protected in Self.protectedPaths {
            if normalized.hasPrefix(protected) {
                return PathCheckResult(
                    isProtected: true,
                    reason: "Inside protected directory: \(protected)",
                    severity: .critical
                )
            }
        }

        let ext = (filePath as NSString).pathExtension.lowercased()
        let dotExt = ext.isEmpty ? "" : ".\(ext)"
        let basename = (filePath as NSString).lastPathComponent

        if Self.sensitiveExtensions.contains(dotExt) {
            return PathCheckResult(isProtected: true, reason: "Sensitive file extension: \(dotExt)", severity: .high)
        }
        if basename.range(of: #"^\.env(\.[a-z]+)?$"#, options: .regularExpression) != nil {
            return PathCheckResult(isProtected: true, reason: ".env file detected", severity: .critical)
        }
        if basename.range(of: #"id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$"#, options: .regularExpression) != nil {
            return PathCheckResult(isProtected: true, reason: "SSH key file detected", severity: .critical)
        }
        if filePath.hasSuffix(".photoslibrary") {
            return PathCheckResult(isProtected: true, reason: "Apple Photos Library detected", severity: .high)
        }

        return PathCheckResult(isProtected: false, reason: nil, severity: nil)
    }

    // MARK: - Private

    private func redact(_ value: String) -> String {
        guard value.count > 8 else { return "[REDACTED]" }
        let start = value.prefix(3)
        let end = value.suffix(3)
        return "\(start)***\(end)"
    }
}
