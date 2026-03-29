use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::severity::SeverityLevel;

/// A detected threat in a message (SMS/iMessage).
#[derive(Debug, Clone, Serialize)]
pub struct MessageThreat {
    #[serde(rename = "type")]
    pub threat_type: String,
    pub label: String,
    pub severity: SeverityLevel,
    pub category: String,
}

struct PatternGroup {
    key: &'static str,
    patterns: Vec<Regex>,
    label: &'static str,
    severity: SeverityLevel,
    category: &'static str,
}

fn compile(pats: &[&str]) -> Vec<Regex> {
    pats.iter()
        .filter_map(|p| regex::RegexBuilder::new(p).case_insensitive(true).build().ok())
        .collect()
}

static THREAT_PATTERNS: Lazy<Vec<PatternGroup>> = Lazy::new(|| {
    vec![
        // 1. Bank/Financial Smishing (CRITICAL)
        PatternGroup {
            key: "smishingBank",
            patterns: compile(&[
                r"your\s+(?:bank\s+)?account\s+(?:has\s+been\s+)?(?:suspended|locked|flagged|compromised)",
                r"unusual\s+(?:activity|transaction|login)\s+(?:detected|noticed)\s+on\s+your\s+account",
                r"verify\s+your\s+(?:bank|account|card|identity)\s+(?:now|immediately|urgently)",
                r"(?:chase|wells\s+fargo|bank\s+of\s+america|citibank|us\s+bank|capital\s+one)\s+(?:alert|notice|security)",
                r"your\s+(?:debit|credit)\s+card\s+(?:has\s+been\s+)?(?:suspended|blocked|frozen)",
            ]),
            label: "Bank / Financial Smishing",
            severity: SeverityLevel::Critical,
            category: "smishing_bank",
        },
        // 2. Apple ID/iCloud Smishing (CRITICAL)
        PatternGroup {
            key: "smishingApple",
            patterns: compile(&[
                r"(?:apple|icloud|apple\s+id)\s+(?:account\s+)?(?:suspended|locked|compromised|disabled)",
                r"your\s+apple\s+id\s+(?:has\s+been\s+)?(?:used|signed\s+in|accessed)\s+(?:in|from)\s+",
                r"appleid\.apple\.com(?!\.apple\.com)",
                r"verify\s+your\s+apple\s+(?:id|account|payment)",
            ]),
            label: "Apple ID / iCloud Smishing",
            severity: SeverityLevel::Critical,
            category: "smishing_apple",
        },
        // 3. Delivery/Shipping Smishing (HIGH)
        PatternGroup {
            key: "smishingDelivery",
            patterns: compile(&[
                r"(?:fedex|ups|usps|dhl|amazon)\s+(?:package|delivery|shipment)\s+(?:held|failed|pending|delayed)",
                r"your\s+(?:package|parcel|delivery)\s+(?:could\s+not\s+be\s+delivered|is\s+pending|requires\s+action)",
                r"(?:reschedule|confirm|update)\s+your\s+(?:delivery|shipment|package)\s+(?:address|info)",
            ]),
            label: "Fake Delivery / Shipping Smishing",
            severity: SeverityLevel::High,
            category: "smishing_delivery",
        },
        // 4. Government/IRS Impersonation (CRITICAL)
        PatternGroup {
            key: "smishingIRS",
            patterns: compile(&[
                r"(?:irs|internal\s+revenue)\s+(?:notice|alert|warning|action\s+required)",
                r"tax\s+(?:refund|return|penalty|audit)\s+(?:pending|held|notice)",
                r"(?:social\s+security|ssa|medicare)\s+(?:number\s+)?(?:suspended|compromised|flagged)",
                r"warrant\s+(?:issued|filed)\s+for\s+(?:your\s+)?(?:arrest|non[-\s]?payment)",
            ]),
            label: "Government / IRS Impersonation",
            severity: SeverityLevel::Critical,
            category: "smishing_irs",
        },
        // 5. Malicious URLs (CRITICAL)
        PatternGroup {
            key: "maliciousUrls",
            patterns: compile(&[
                r"https?://(?:bit\.ly|tinyurl\.com|t\.co|ow\.ly|short\.io|cutt\.ly|is\.gd|rebrand\.ly)/\S+",
                r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/\S*",
                r"https?://[a-z0-9\-]+\.(?:xyz|tk|ml|ga|cf|gq|pw|top|click|loan|win|date|party|review|work)/\S*",
                r"https?://\S+\.(?:dmg|exe|sh|apk|pkg|msi|bat|ps1)\b",
                r"https?://[a-z0-9]*(?:paypa1|arnazon|g00gle|micros0ft|app1e|app1e-id|icloud-verify|apple-security)[a-z0-9]*\.",
            ]),
            label: "Malicious / Suspicious URL in Message",
            severity: SeverityLevel::Critical,
            category: "malicious_url",
        },
        // 6. Crypto Scam/Sextortion (CRITICAL)
        PatternGroup {
            key: "cryptoScam",
            patterns: compile(&[
                r"(?:send|transfer|pay)\s+(?:bitcoin|btc|ethereum|eth|usdt|crypto)\s+(?:to|worth|\$)",
                r"(?:i\s+have\s+)?(?:hacked|compromised|recorded)\s+your\s+(?:phone|device|computer|camera)",
                r"pay\s+(?:\$[\d,]+|[\d,]+\s+(?:btc|usd))\s+(?:or|within|to\s+prevent)",
                r"(?:investment|trading)\s+(?:opportunity|platform|returns?)\s+(?:guaranteed|risk[-\s]free)",
                r"double\s+your\s+(?:bitcoin|crypto|money|investment)\s+in\s+",
            ]),
            label: "Crypto Scam / Sextortion in Message",
            severity: SeverityLevel::Critical,
            category: "crypto_scam",
        },
        // 7. OTP/Code Theft (HIGH)
        PatternGroup {
            key: "otpTheft",
            patterns: compile(&[
                r"(?:share|send|provide|give|type|enter|read\s+out)\s+(?:your\s+)?(?:otp|one[-\s]time\s+(?:password|code)|verification\s+code)\s+(?:to|with)\s+(?:us|our|an?\s+agent|support)",
                r"(?:never\s+share|do\s+not\s+share|don'?t\s+share)\s+(?:your\s+)?(?:otp|code|pin)\s+with\s+(?:anyone|our\s+(?:team|agent|staff))",
                r"our\s+(?:agent|representative|support|team)\s+(?:will\s+)?(?:ask|never\s+ask)\s+(?:you\s+)?for\s+(?:your\s+)?(?:otp|code|pin|password)",
            ]),
            label: "OTP / Verification Code Theft Attempt",
            severity: SeverityLevel::High,
            category: "otp_theft",
        },
        // 8. Prize/Lottery Scam (HIGH)
        PatternGroup {
            key: "prizeScam",
            patterns: compile(&[
                r"(?:congratulations|you\s+(?:have\s+)?won|you've\s+been\s+selected)\s+(?:a\s+)?(?:prize|reward|gift\s+card|cash)",
                r"claim\s+your\s+(?:free\s+)?(?:prize|reward|gift|iphone|macbook|cash)\s+(?:now|today|here)",
                r"(?:winner|selected|chosen)\s+(?:for|to\s+receive)\s+(?:a\s+)?(?:\$[\d,]+|gift|prize)",
            ]),
            label: "Prize / Lottery Scam",
            severity: SeverityLevel::High,
            category: "prize_scam",
        },
        // 9. Urgency/Fear Tactic (MEDIUM)
        PatternGroup {
            key: "urgencyTactics",
            patterns: compile(&[
                r"(?:act|respond|reply|click)\s+(?:now|immediately|within\s+\d+\s+hours?)\s+(?:or|to\s+avoid)",
                r"(?:final|last|urgent)\s+(?:warning|notice|reminder|chance)\s+(?:before|to)",
                r"your\s+(?:account|service|number|line)\s+will\s+be\s+(?:terminated|cancelled|suspended)\s+(?:in\s+\d+|unless)",
            ]),
            label: "Urgency / Fear Tactic",
            severity: SeverityLevel::Medium,
            category: "urgency_tactic",
        },
    ]
});

/// Known phishing domain fragments.
pub static KNOWN_PHISHING_DOMAINS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "apple-id-verify", "icloud-locked", "account-verify", "secure-login",
        "apple-support-", "chase-secure", "paypal-secure", "amazon-security",
        "irs-refund", "usps-tracking-", "fedex-delivery-", "ups-alert-",
    ]
});

/// Analyze a message for threat patterns. Returns all matched threats.
pub fn analyze_message(text: &str) -> Vec<MessageThreat> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut threats = Vec::new();

    // Pattern-based detection
    for group in THREAT_PATTERNS.iter() {
        for pattern in &group.patterns {
            if pattern.is_match(text) {
                threats.push(MessageThreat {
                    threat_type: group.key.to_string(),
                    label: group.label.to_string(),
                    severity: group.severity,
                    category: group.category.to_string(),
                });
                break; // one match per group
            }
        }
    }

    // Known phishing domain check
    let lower = text.to_lowercase();
    for &domain in KNOWN_PHISHING_DOMAINS.iter() {
        if lower.contains(domain) {
            threats.push(MessageThreat {
                threat_type: "known_phishing_domain".to_string(),
                label: format!("Known phishing domain: {}", domain),
                severity: SeverityLevel::Critical,
                category: "malicious_url".to_string(),
            });
            break;
        }
    }

    threats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_message() {
        let threats = analyze_message("Hey, want to grab lunch tomorrow?");
        assert!(threats.is_empty());
    }

    #[test]
    fn detects_bank_smishing() {
        let threats = analyze_message("Your bank account has been suspended. Verify immediately.");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "smishing_bank"));
    }

    #[test]
    fn detects_apple_smishing() {
        let threats = analyze_message("Your Apple ID account suspended due to suspicious activity");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "smishing_apple"));
    }

    #[test]
    fn detects_delivery_smishing() {
        let threats = analyze_message("FedEx package delivery failed. Reschedule your delivery address now.");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "smishing_delivery"));
    }

    #[test]
    fn detects_irs_impersonation() {
        let threats = analyze_message("IRS notice: Your tax refund pending review");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "smishing_irs"));
    }

    #[test]
    fn detects_malicious_url() {
        let threats = analyze_message("Click https://bit.ly/abc123 to verify your account");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "malicious_url"));
    }

    #[test]
    fn detects_crypto_scam() {
        let threats = analyze_message("Send bitcoin to this address or I will share your footage. Pay $5,000 or within 48 hours");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "crypto_scam"));
    }

    #[test]
    fn detects_otp_theft() {
        let threats = analyze_message("Please share your one-time password with our support team");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "otp_theft"));
    }

    #[test]
    fn detects_prize_scam() {
        let threats = analyze_message("Congratulations you won a prize! Claim your free iPhone now");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "prize_scam"));
    }

    #[test]
    fn detects_urgency_tactic() {
        let threats = analyze_message("Act now immediately or your account will be terminated in 24 hours");
        assert!(!threats.is_empty());
        // Could match urgency_tactic or smishing_bank
        assert!(threats.iter().any(|t| t.category == "urgency_tactic" || t.category == "smishing_bank"));
    }

    #[test]
    fn detects_known_phishing_domain() {
        let threats = analyze_message("Visit apple-id-verify.com to restore your account");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.threat_type == "known_phishing_domain"));
    }

    #[test]
    fn detects_ip_url_in_message() {
        let threats = analyze_message("Go to https://192.168.1.100:8080/login now");
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.category == "malicious_url"));
    }
}
