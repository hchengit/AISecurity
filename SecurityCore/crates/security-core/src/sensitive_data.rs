use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::severity::SeverityLevel;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    #[serde(rename = "type")]
    pub finding_type: String,
    pub label: String,
    pub severity: SeverityLevel,
    pub category: String,
    pub source: String,
    #[serde(rename = "matchPreview")]
    pub match_preview: String,
    pub offset: usize,
}

struct PatternDef {
    key: &'static str,
    regex: Regex,
    label: &'static str,
    severity: SeverityLevel,
    category: &'static str,
}

fn def(key: &'static str, pat: &str, case_insensitive: bool, label: &'static str, sev: SeverityLevel, cat: &'static str) -> Option<PatternDef> {
    regex::RegexBuilder::new(pat)
        .case_insensitive(case_insensitive)
        .build()
        .ok()
        .map(|regex| PatternDef { key, regex, label, severity: sev, category: cat })
}

static PATTERNS: Lazy<Vec<PatternDef>> = Lazy::new(|| {
    let mut v = Vec::new();
    macro_rules! add {
        ($key:expr, $pat:expr, $ci:expr, $label:expr, $sev:expr, $cat:expr) => {
            if let Some(d) = def($key, $pat, $ci, $label, $sev, $cat) { v.push(d); }
        };
    }
    use SeverityLevel::*;

    // Financial
    add!("creditCard", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b", false, "Credit Card Number", Critical, "financial");
    add!("bankRoutingNumber", r"\b(?:routing|aba|transit)[\s\w]*?:?\s*(\d{9})\b", true, "Bank Routing Number", Critical, "financial");
    add!("bankAccountNumber", r"\b(?:account|acct|bank acct)[\s\w]*?:?\s*(\d{10,17})\b", true, "Bank Account Number", Critical, "financial");
    add!("cvv", r"\b(?:cvv|cvc|cvv2|csc|security code)[\s:]*(\d{3,4})\b", true, "Card CVV/CVC", Critical, "financial");

    // Personal Identifiers
    add!("ssn", r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0{4})\d{4}\b", false, "Social Security Number (SSN)", Critical, "pii");
    add!("birthday", r"\b(?:dob|date of birth|born|birthday|birth date)[\s:]*(\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}|\w+ \d{1,2},? \d{4})\b", true, "Date of Birth", High, "pii");
    add!("passport", r"\b(?:passport(?:\s*(?:no|number|#))?[\s:]*[A-Z]{1,2}\d{6,9})\b", true, "Passport Number", High, "pii");

    // Driver's License
    add!("driversLicenseGeneric", r"\b(?:driver['\x27\s]?s?\s+licen[sc]e|drivers?\s+id|dl\s*#?|dmv\s*#?|license\s*(?:no|number|#))[\s:]*([A-Z]{0,2}\d{4,9}[A-Z]{0,2}|\d{3}[-\s]\d{3}[-\s]\d{3})\b", true, "Driver's License Number", Critical, "pii");
    add!("driversLicenseCA", r"\b(?:ca|california)\s*(?:dl|license|id)[\s:#]*([A-Z]\d{7})\b", true, "Driver's License (California)", Critical, "pii");
    add!("driversLicenseNY", r"\b(?:ny|new york)\s*(?:dl|license|id)[\s:#]*(\d{9}|\d{3}[-\s]\d{3}[-\s]\d{3})\b", true, "Driver's License (New York)", Critical, "pii");
    add!("driversLicenseTX", r"\b(?:tx|texas)\s*(?:dl|license|id)[\s:#]*(\d{8})\b", true, "Driver's License (Texas)", Critical, "pii");
    add!("driversLicenseFL", r"\b(?:fl|florida)\s*(?:dl|license|id)[\s:#]*([A-Z]\d{12})\b", true, "Driver's License (Florida)", Critical, "pii");
    add!("driversLicenseWA", r"\b(?:wa|washington)\s*(?:dl|license|id)[\s:#]*([A-Z]{2,7}\d{3}[A-Z0-9]{2,5})\b", true, "Driver's License (Washington)", Critical, "pii");

    // Crypto / Wallet
    add!("bitcoinPrivateKeyWIF", r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", false, "Bitcoin Private Key (WIF)", Critical, "crypto");
    add!("bitcoinXprv", r"\bxprv[a-zA-Z0-9]{107}\b", false, "Bitcoin Extended Private Key (xprv)", Critical, "crypto");
    add!("bitcoinZprv", r"\bzprv[a-zA-Z0-9]{107}\b", false, "Bitcoin Segwit Extended Private Key (zprv)", Critical, "crypto");
    add!("ethereumPrivateKey", r"\b(?:0x)?[0-9a-fA-F]{64}\b", false, "Ethereum/Crypto Private Key", Critical, "crypto");
    add!("seedPhraseMnemonic", r"\b(?:seed(?:\s+phrase)?|mnemonic|recovery(?:\s+phrase)?|backup(?:\s+phrase)?|secret(?:\s+phrase)?)[\s:]+([a-z]+(?:\s+[a-z]+){11,23})\b", true, "Cryptocurrency Seed Phrase / Mnemonic", Critical, "crypto");
    add!("sparrowWalletKeyword", r"\b(?:sparrow[\s._\-]?wallet|\.sparrow|sparrow\.wallet)\b", true, "Sparrow Wallet Reference", High, "crypto");

    // API Keys & Secrets
    add!("openAiKey", r"\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,}\b", false, "OpenAI API Key", Critical, "api_key");
    add!("anthropicKey", r"\bsk-ant-[a-zA-Z0-9\-_]{32,}\b", false, "Anthropic API Key", Critical, "api_key");
    add!("githubToken", r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b", false, "GitHub Personal Access Token", Critical, "api_key");
    add!("genericApiKey", r#"(?:^|[\s;,]|_)(?:API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN|JWT_SECRET|CLIENT_SECRET)\s*[=:]\s*["']?([A-Za-z0-9/\+_\-\.]{16,})["']?"#, true, "API Key / Secret", Critical, "api_key");
    add!("password", r#"\b(?:PASSWORD|PASSWD|PWD|PASS)\s*[=:]\s*["']?([^\s"']{8,})["']?\b"#, true, "Password in Config/Env", Critical, "credential");
    add!("bearerToken", r"\bBearer\s+[A-Za-z0-9\-_\.~\+/]+=*\b", false, "Bearer Token", High, "api_key");
    add!("awsKey", r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b", false, "AWS Access Key", Critical, "api_key");

    // Tax & Financial Documents
    add!("turbotaxReference", r"\b(?:turbotax|taxreturn|\.tax20\d{2}|\.tax\b|1040[-\s]?(?:EZ|SR|NR)?|w[-\s]?2\b|1099[-\s]?\w{1,4})\b", true, "Tax Document / TurboTax Reference", High, "financial");

    // macOS App Data Keywords
    add!("passwordManagerRef", r"\b(?:bitwarden|1password|lastpass|keychain|aura[\s_]?password|dashlane|keeper)\b", true, "Password Manager Reference", High, "app_data");
    add!("photosRef", r"\b(?:Photos\.app|Photos Library|photoslibrary|\.photoslibrary|PHAsset|PHFetchResult|com\.apple\.Photos)\b", true, "Apple Photos Library Reference", High, "app_data");
    add!("calendarData", r"\b(?:ics|vcal|vevent|dtstart|dtend|calendar(?:\.app)?)\b", true, "Calendar Data", Medium, "app_data");
    add!("appleKeychainRef", r"\b(?:keychain|\.keychain-db|secitemcopy|kcitemref)\b", true, "macOS Keychain Reference", Critical, "app_data");

    // Environment / Config Files
    add!("envFileSecret", r"(?m)^[\s#]*(?:DB_PASS|DATABASE_URL|REDIS_URL|MONGO_URI|SECRET|TOKEN|KEY|CERT|PRIVATE)\s*=\s*.+$", true, ".env Secret Variable", Critical, "credential");
    add!("privateKeyBlock", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", false, "PEM Private Key Block", Critical, "credential");
    add!("sshPrivateKey", r"-----BEGIN OPENSSH PRIVATE KEY-----", false, "SSH Private Key", Critical, "credential");

    v
});

fn redact(value: &str) -> String {
    if value.len() <= 8 {
        "[REDACTED]".to_string()
    } else {
        format!("{}***{}", &value[..3], &value[value.len()-3..])
    }
}

/// Scan text for sensitive personal, financial, and crypto data.
pub fn scan_text(text: &str, source: &str) -> Vec<Finding> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for def in PATTERNS.iter() {
        for mat in def.regex.find_iter(text) {
            findings.push(Finding {
                finding_type: def.key.to_string(),
                label: def.label.to_string(),
                severity: def.severity,
                category: def.category.to_string(),
                source: source.to_string(),
                match_preview: redact(mat.as_str()),
                offset: mat.start(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_credit_card() {
        let findings = scan_text("My card is 4111111111111111", "test");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, "financial");
    }

    #[test]
    fn detects_openai_key() {
        let findings = scan_text("sk-proj-abcdefghijklmnopqrst1234", "test");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].finding_type, "openAiKey");
    }

    #[test]
    fn detects_xprv() {
        let key = format!("xprv{}", "a".repeat(107));
        let findings = scan_text(&key, "test");
        assert!(findings.iter().any(|f| f.finding_type == "bitcoinXprv"));
    }

    #[test]
    fn clean_text_has_no_findings() {
        let findings = scan_text("Hello, this is a normal message about the weather.", "test");
        assert!(findings.is_empty());
    }

    #[test]
    fn redacts_sensitive_data() {
        let findings = scan_text("sk-proj-abcdefghijklmnopqrst1234", "test");
        assert!(!findings.is_empty());
        assert!(findings[0].match_preview.contains("***"));
    }
}
