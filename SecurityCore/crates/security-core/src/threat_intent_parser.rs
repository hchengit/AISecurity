use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::severity::SeverityLevel;

/// Channel the message arrived on — SMS gets boosted scoring.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Email = 0,
    Sms = 1,
}

/// Result of intent analysis.
#[derive(Debug, Clone, Serialize)]
pub struct IntentResult {
    #[serde(rename = "isThreat")]
    pub is_threat: bool,
    pub severity: Option<SeverityLevel>,
    #[serde(rename = "layersFired")]
    pub layers_fired: u8,
    pub layers: Layers,
    pub label: String,
    pub confidence: String,
    /// Weighted score out of 100.
    pub score: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Layers {
    pub l1: bool,
    pub l2: bool,
    pub l3: bool,
    pub l4: bool,
    pub l5: bool,
    pub l6: bool,
}

fn compile(patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| regex::RegexBuilder::new(p).case_insensitive(true).build().ok())
        .collect()
}

fn any_match(text: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|p| p.is_match(text))
}

// ═══════════════════════════════════════════════════════════════════
// TRAIT DETECTORS — reusable building blocks for signatures
// ═══════════════════════════════════════════════════════════════════

// -- Sender / source traits --
// Gov agency IMPERSONATION — must claim to BE the agency, not just mention it.
// "This is the IRS" = impersonation. "The IRS announced new rules" = journalism.
static TRAIT_GOV_AGENCY: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:this\s+is|we\s+are|from)\s+(?:the\s+)?(?:irs|internal\s+revenue|fbi|federal\s+bureau|ssa|social\s+security|doj|department\s+of\s+justice|homeland\s+security|dhs)\b",
    r"\b(?:irs|fbi|ssa|doj|dhs|ftc|fdic)\s+(?:notice|case|file|action|warning|alert|investigation)\b",
    r"\b(?:irs|fbi|ssa)\s+(?:has|is)\s+(?:contacting|notifying|investigating|flagged)\b",
    r"\byour\s+(?:irs|fbi|ssa|social\s+security)\s+(?:case|file|number|account|benefits?)\b",
]));
static TRAIT_FINANCIAL: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:chase|wells\s+fargo|bank\s+of\s+america|citibank|capital\s+one|us\s+bank|td\s+bank|paypal|zelle|venmo|cashapp|american\s+express|amex|discover|mastercard|visa)\b",
]));
static TRAIT_TECH_COMPANY: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:apple|icloud|apple\s+id|google|microsoft|amazon|netflix|meta|facebook|instagram)\b",
]));
static TRAIT_CRYPTO: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:bitcoin|btc|ethereum|eth|crypto|usdt|usdc|blockchain|coinbase|binance|wallet)\b",
]));

// -- Sensitive data requests --
static TRAIT_ASK_CREDENTIALS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:provide|send|enter|reply\s+with|submit|confirm|verify|update)\s+your\s+(?:password|passphrase|passcode|pin|login|credentials?)\b",
    r"\b(?:provide|send|enter|reply\s+with|forward)\s+(?:the\s+)?(?:verification|security|confirmation|one[-\s]?time|otp|2fa|mfa)\s+(?:code|token|number)\b",
]));
static TRAIT_ASK_SSN: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:provide|send|enter|reply\s+with|confirm|verify)\s+your\s+(?:social\s+security|ssn|tax\s+id)\b",
    r"\byour\s+(?:social\s+security|ssn)\s+(?:number|#)?\s+(?:has\s+been|is|was)\s+(?:suspended|compromised|flagged|used)\b",
]));
static TRAIT_ASK_FINANCIAL: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:provide|send|enter|reply\s+with|confirm|verify)\s+your\s+(?:credit\s+card|card\s+number|cvv|cvc|billing|routing\s+number|account\s+number|bank\s+(?:account|details?))\b",
]));
static TRAIT_ASK_CRYPTO_KEYS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:provide|send|enter|share|reply\s+with)\s+your\s+(?:private\s+key|seed\s+phrase|recovery\s+phrase|wallet\s+(?:key|phrase|password)|mnemonic)\b",
]));

// -- Dangerous actions --
static TRAIT_WIRE_TRANSFER: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    // Must specifically mention "wire" or "transfer" with money — not just "pay $X"
    r"\b(?:wire|wire\s+transfer)\s+(?:\$[\d,]+|the\s+(?:funds?|money|amount|balance))\b",
    r"\b(?:transfer|send)\s+(?:\$[\d,]+|the\s+(?:funds?|money|amount))\s+(?:to|into)\s+(?:the|this|our|a)\s+(?:account|bank)\b",
    // Bank account change requests (BEC)
    r"\b(?:change|update|modify)\s+(?:the\s+)?(?:bank|payment|wire|ach|routing|account)\s+(?:details?|information|instructions?)\b",
    // Explicit wire transfer request
    r"\b(?:initiate|process|complete)\s+(?:a\s+)?(?:wire\s+transfer|bank\s+transfer)\b",
]));
static TRAIT_GIFT_CARDS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:purchase|buy|get)\s+(?:\w+\s+)*gift\s+cards?\b",
    r"\b(?:apple|google\s+play|amazon|steam|itunes|ebay)\s+gift\s+cards?\b",
    r"\bgift\s+cards?\s+(?:for|worth|at|of)\s+\$?\d",
    r"\b(?:send|give)\s+(?:me\s+)?the\s+(?:codes?|numbers?)\b",
]));
static TRAIT_CRYPTO_PAYMENT: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    // Explicit crypto payment demand — must mention crypto currency by name
    r"\b(?:send|transfer|pay)\s+(?:[\d.]+\s+)?(?:bitcoin|btc|ethereum|eth|crypto|usdt|usdc)\b",
    r"\b(?:send|transfer|pay)\s+(?:bitcoin|btc|ethereum|eth|crypto|usdt|usdc)\s+(?:to|worth|at)\b",
    // Bitcoin address with explicit label (not bare — bare matches too many base64 strings)
    r"\bbitcoin\s+(?:wallet\s+)?address\s*[:=]?\s*[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    // "pay in bitcoin/crypto" or "bitcoin payment"
    r"\b(?:bitcoin|btc|ethereum|eth|crypto)\s+(?:payment|transfer|wallet)\b",
    r"\bpay\s+(?:in|with|using)\s+(?:bitcoin|btc|ethereum|eth|crypto|cryptocurrency)\b",
]));
static TRAIT_SECRECY: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r#"\b(?:keep\s+this|this\s+is)\s+(?:between\s+us|confidential|quiet|secret)\b"#,
    r#"\b(?:don'?t|do\s+not)\s+(?:tell|inform|mention\s+(?:this\s+)?to|discuss\s+(?:this\s+)?with)\b"#,
]));

// -- Links & attachments --
// Known safe domains that should NOT trigger suspicious URL detection.
static SAFE_URL_DOMAINS: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"https?://(?:[a-z0-9\-]+\.)*(?:linkedin\.com|lnkd\.in|substack\.com|apple\.com|google\.com|microsoft\.com|amazon\.com|chase\.com|wellsfargo\.com|bankofamerica\.com|americanexpress\.com|paypal\.com|usbank\.com|coinbureau\.com|netflix\.com|facebook\.com|instagram\.com|twitter\.com|youtube\.com|github\.com|stackoverflow\.com|reddit\.com|medium\.com|nytimes\.com|wsj\.com|macys\.com|ups\.com|fedex\.com|usps\.com|sos\.ca\.gov|\.gov/)",
]));
static TRAIT_SUSPICIOUS_URL: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]",  // IP-based URL (always suspicious)
    r"\bhttps?://(?:bit\.ly|tinyurl\.com|is\.gd|adf\.ly|rb\.gy|short\.io|cutt\.ly|v\.gd)/[a-zA-Z0-9]+",  // URL shorteners (hide destination)
    r#"https?://[^\s"'>]+\.(?:xyz|tk|ml|ga|cf|gq|pw|top|click|download|work|party|loan|review|trade|win|date|buzz|rest|surf|icu)(?:/|\?|$)"#,  // suspicious TLDs
]));
static TRAIT_TYPOSQUAT: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:paypa1|arnazon|arnerica[nm]express|arnerican|g00gle|micros0ft|app1e|netfl1x|faceb00k|we11sfargo|chasse|citlbank|capita1one)\b",
]));
static TRAIT_FREEMAIL_IMPERSONATION: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"(?:support|service|security|admin|help|billing|account|verify|alert)@(?:gmail|yahoo|hotmail|outlook|protonmail|aol|mail|yandex|zoho)\.com\b",
]));

// -- Sextortion / blackmail --
static TRAIT_SEXTORTION: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:i\s+(?:have|got)\s+(?:bad|disturbing)\s+news|hello\s+pervert)\b",
    r"\b(?:hacked|compromised)\s+your\s+(?:computer|device|webcam|camera)\b",
    r"\b(?:your|ur)\s+(?:webcam|camera)\s+(?:was|has\s+been)\s+(?:hacked|compromised)\b",
    r"\b(?:recorded|watching)\s+you\s+(?:through|via|using)\s+(?:your\s+)?(?:webcam|camera)\b",
    r"\b(?:i\s+(?:placed|installed)\s+(?:a\s+)?(?:malware|trojan|rat|virus))\b",
    r"\b(?:dirty|intimate|compromising)\s+(?:video|photo|material|content|footage)\b",
    r"\b(?:ruin|destroy|damage)\s+your\s+(?:life|reputation|marriage|career)\b",
    r"\bsend\s+(?:it|them|this|the\s+\w+)\s+to\s+(?:all|every)\s+(?:your\s+)?(?:contacts|friends|family)\b",
    r"\bshare\s+the\s+(?:footage|video|recording)\s+with\s+(?:your|all)\b",
]));

// -- Pressure & threats --
static TRAIT_ACCOUNT_THREAT: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:suspend|suspended|termina(?:te|ted)|cancel(?:led)?|clos(?:e|ed)|deactivat(?:e|ed)|restrict(?:ed)?|locked?|disabled?)\s+your\s+(?:account|card|access|service|benefits?)\b",
    r"\byour\s+(?:account|card|access|service)\s+(?:will\s+be|has\s+been|is|was)\s+(?:suspended|terminated|cancelled|closed|deactivated|restricted|locked|disabled)\b",
]));
static TRAIT_ARREST_LEGAL: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\b(?:arrest|arrested|detain|detained|taken\s+into\s+custody|prosecution|prosecuted|indicted|warrant)\b",
    r"\b(?:legal|criminal|civil)\s+(?:action|charges?|proceedings?|penalty|penalties)\b",
    r"\bfailure\s+to\s+(?:comply|respond|pay|act|verify)\s+(?:will|may|could|shall)\b",
]));
static TRAIT_URGENCY: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\bwithin\s+(?:\d+\s+)?(?:hours?|minutes?|days?)\b",
    r"\b(?:immediately|urgently|right\s+away|right\s+now|asap)\b",
    r"\b(?:final|last|urgent|immediate)\s+(?:notice|warning|reminder|chance)\b",
    r"\b(?:expires?|expiring)\s+(?:today|tonight|soon|in\s+\d+)\b",
]));
static TRAIT_IMPERSONATION: Lazy<Vec<Regex>> = Lazy::new(|| compile(&[
    r"\bthis\s+is\s+(?:the\s+)?(?:irs|fbi|ssa|social\s+security|homeland\s+security|department\s+of)\b",
    r"\b(?:official|formal)\s+(?:notice|communication|letter|warning)\s+from\b",
    r"\b(?:agent|officer|investigator)\s+(?:id|badge|number|#)\s*:?\s*\d+\b",
]));

// ═══════════════════════════════════════════════════════════════════
// THREAT SIGNATURES — category-specific combos that score high
// Each signature: (name, score, required traits test function)
// ═══════════════════════════════════════════════════════════════════

struct SignatureMatch {
    name: &'static str,
    score: u32,
}

/// Evaluate all threat signatures against the text. Returns the highest-scoring match.
fn check_signatures(text: &str) -> Option<SignatureMatch> {
    let mut best: Option<SignatureMatch> = None;

    let has_gov = any_match(text, &TRAIT_GOV_AGENCY);
    let has_fin = any_match(text, &TRAIT_FINANCIAL);
    let has_tech = any_match(text, &TRAIT_TECH_COMPANY);
    let has_crypto_ctx = any_match(text, &TRAIT_CRYPTO);
    let has_creds = any_match(text, &TRAIT_ASK_CREDENTIALS);
    let has_ssn = any_match(text, &TRAIT_ASK_SSN);
    let has_fin_data = any_match(text, &TRAIT_ASK_FINANCIAL);
    let has_crypto_keys = any_match(text, &TRAIT_ASK_CRYPTO_KEYS);
    let has_wire = any_match(text, &TRAIT_WIRE_TRANSFER);
    let has_gift = any_match(text, &TRAIT_GIFT_CARDS);
    let has_crypto_pay = any_match(text, &TRAIT_CRYPTO_PAYMENT);
    let has_secrecy = any_match(text, &TRAIT_SECRECY);
    // Suspicious URL: only if NOT from a known safe domain
    let has_sus_url = any_match(text, &TRAIT_SUSPICIOUS_URL) && !any_match(text, &SAFE_URL_DOMAINS);
    let has_typo = any_match(text, &TRAIT_TYPOSQUAT);
    let has_freemail = any_match(text, &TRAIT_FREEMAIL_IMPERSONATION);
    let has_sextortion = any_match(text, &TRAIT_SEXTORTION);
    let has_acct_threat = any_match(text, &TRAIT_ACCOUNT_THREAT);
    let has_arrest = any_match(text, &TRAIT_ARREST_LEGAL);
    let has_urgency = any_match(text, &TRAIT_URGENCY);
    let has_impersonation = any_match(text, &TRAIT_IMPERSONATION);

    // Helper: update best if this score is higher
    macro_rules! sig {
        ($name:expr, $score:expr, $cond:expr) => {
            if $cond {
                let s = $score;
                if best.as_ref().map_or(true, |b| s > b.score) {
                    best = Some(SignatureMatch { name: $name, score: s });
                }
            }
        }
    }

    // ── CATEGORY: Government Agency Impersonation ──────────────────
    // IRS/FBI/SSA + SSN request + any link/threat = 100 (slam dunk scam)
    sig!("Gov-agency + SSN request + link", 100,
        has_gov && has_ssn && (has_sus_url || has_arrest));
    // IRS/FBI + SSN request (no link needed — the SSN ask alone is dangerous)
    sig!("Gov-agency + SSN request", 85,
        has_gov && has_ssn);
    // IRS/FBI + wire transfer demand
    sig!("Gov-agency + wire transfer", 90,
        has_gov && has_wire);
    // IRS/FBI + arrest threat + urgency (classic phone/email scam pattern)
    sig!("Gov-agency + arrest + urgency", 80,
        has_gov && has_arrest && has_urgency);
    // IRS/FBI impersonation + suspicious URL
    sig!("Gov-agency + suspicious URL", 75,
        has_gov && has_impersonation && has_sus_url);

    // ── CATEGORY: Bank / Financial Institution Phishing ────────────
    // Bank name + credential request + suspicious URL = classic phishing
    sig!("Bank + credential request + suspicious URL", 95,
        has_fin && has_creds && has_sus_url);
    // Bank + credential request + typosquatted domain
    sig!("Bank + credential request + typosquat", 100,
        has_fin && has_creds && has_typo);
    // Bank + account threat + suspicious URL
    sig!("Bank + account threat + suspicious URL", 80,
        has_fin && has_acct_threat && has_sus_url);
    // Financial data request + suspicious URL
    sig!("Financial data request + suspicious URL", 85,
        has_fin_data && has_sus_url);
    // Bank + credential request (even without URL — the ask is the red flag)
    sig!("Bank + credential request", 70,
        has_fin && has_creds);

    // ── CATEGORY: Tech Company Impersonation ──────────────────────
    // Apple/Google/Microsoft + credential request + suspicious URL
    sig!("Tech + credential request + suspicious URL", 90,
        has_tech && has_creds && has_sus_url);
    // Tech + account threat + suspicious URL
    sig!("Tech + account threat + suspicious URL", 75,
        has_tech && has_acct_threat && has_sus_url);
    // Tech + credential request + typosquat
    sig!("Tech + credential request + typosquat", 95,
        has_tech && has_creds && has_typo);

    // ── CATEGORY: Sextortion / Blackmail ──────────────────────────
    // Sextortion language + crypto payment = instant flag
    sig!("Sextortion + crypto payment", 100,
        has_sextortion && has_crypto_pay);
    // Sextortion language alone (still very likely scam)
    sig!("Sextortion language", 80,
        has_sextortion);

    // ── CATEGORY: BEC (Business Email Compromise) ─────────────────
    // Gift card request + secrecy = classic BEC
    sig!("Gift cards + secrecy", 90,
        has_gift && has_secrecy);
    // Gift card request + urgency
    sig!("Gift cards + urgency", 75,
        has_gift && has_urgency);
    // Wire transfer + secrecy
    sig!("Wire transfer + secrecy", 90,
        has_wire && has_secrecy);
    // Wire transfer change request (payroll/vendor fraud)
    sig!("Wire transfer + urgency", 70,
        has_wire && has_urgency);

    // ── CATEGORY: Crypto Scam ─────────────────────────────────────
    // Crypto key/seed phrase request — always dangerous (no legit email asks for this)
    sig!("Crypto key request", 95,
        has_crypto_keys);
    // Crypto payment + sextortion = slam dunk scam
    sig!("Crypto payment + sextortion", 100,
        has_crypto_pay && has_sextortion);
    // Crypto payment demand + arrest/legal threats (extortion)
    sig!("Crypto payment + arrest/legal threats", 90,
        has_crypto_pay && has_arrest);
    // Crypto payment demand + account threats
    sig!("Crypto payment + account threats", 85,
        has_crypto_pay && has_acct_threat);
    // Crypto payment + suspicious URL (credential harvesting for wallets)
    sig!("Crypto payment + suspicious URL", 80,
        has_crypto_pay && has_sus_url);
    // NOTE: Crypto payment + urgency alone is NOT flagged — too many legit crypto
    // newsletters discuss payments, and urgency is common in marketing emails.
    // Crypto payment + secrecy IS suspicious though.
    sig!("Crypto payment + secrecy", 80,
        has_crypto_pay && has_secrecy);
    // Crypto exchanges/wallets (Coinbase, Binance, etc.) are impersonation
    // targets like banks and tech companies, but are not in TRAIT_FINANCIAL
    // or TRAIT_TECH_COMPANY — so mirror the bank/tech credential-phishing
    // rules here using the crypto-context signal. Scoped to credential asks
    // and account threats (not payment/urgency, which is newsletter-noisy).
    // Fake-exchange login harvesting.
    sig!("Crypto exchange + credential request + suspicious URL", 90,
        has_crypto_ctx && has_creds && has_sus_url);
    // The credential ask against a crypto brand is itself the red flag —
    // legit exchanges never ask you to reply with/confirm your password.
    // (Mirrors "Bank + credential request" = 70.)
    sig!("Crypto exchange + credential request", 70,
        has_crypto_ctx && has_creds);
    // "Your Coinbase account is suspended — click here" wallet-drain lure.
    sig!("Crypto exchange + account threat + suspicious URL", 80,
        has_crypto_ctx && has_acct_threat && has_sus_url);

    // ── CATEGORY: Credential Harvesting (generic) ─────────────────
    // Credential request + suspicious URL (no specific brand needed)
    sig!("Credential request + suspicious URL", 80,
        has_creds && has_sus_url);
    // Credential request + typosquat
    sig!("Credential request + typosquat", 90,
        has_creds && has_typo);
    // SSN request + any link
    sig!("SSN request + link", 85,
        has_ssn && has_sus_url);
    // Financial data request alone
    sig!("Financial data request", 70,
        has_fin_data);
    // Freemail impersonation + credential request
    sig!("Freemail impersonation + credential request", 85,
        has_freemail && has_creds);
    // Freemail impersonation + account threat
    sig!("Freemail impersonation + account threat", 70,
        has_freemail && has_acct_threat);

    // ── CATEGORY: Suspicious sender + pressure (weaker signals) ───
    // Typosquat alone (no other strong signal)
    sig!("Typosquatted domain", 60,
        has_typo);
    // Freemail impersonation alone
    sig!("Freemail impersonation", 50,
        has_freemail);

    best
}

/// Threshold for threat classification.
const THREAT_THRESHOLD: u32 = 70;

/// 7-Layer Weighted Intent Scoring Engine with Category-Specific Signatures.
///
/// Two-pass approach:
/// 1. **Signature matching**: check category-specific threat combos (IRS+SSN+link, etc.)
///    These produce high scores (70-100) when a known threat pattern is detected.
/// 2. **Generic layer scoring**: for emails that don't match a known signature,
///    fall back to weighted generic layers. Newsletters score low (0-20) here
///    because they only hit urgency/context layers, never structural harm layers.
pub fn parse(text: &str, channel: Channel) -> IntentResult {
    if text.is_empty() {
        return clean_result();
    }

    let lower = text.to_lowercase();

    // Pass 1: Category-specific signature matching
    let signature = check_signatures(&lower);
    let sig_score = signature.as_ref().map_or(0, |s| s.score);
    let sig_label = signature.as_ref().map_or("", |s| s.name);

    // Pass 2: Detect which trait categories fired (for the Layers struct and label)
    let has_cred = any_match(&lower, &TRAIT_ASK_CREDENTIALS)
        || any_match(&lower, &TRAIT_ASK_SSN)
        || any_match(&lower, &TRAIT_ASK_FINANCIAL)
        || any_match(&lower, &TRAIT_ASK_CRYPTO_KEYS);
    let has_deception = any_match(&lower, &TRAIT_TYPOSQUAT)
        || any_match(&lower, &TRAIT_FREEMAIL_IMPERSONATION);
    let has_dangerous = any_match(&lower, &TRAIT_WIRE_TRANSFER)
        || any_match(&lower, &TRAIT_GIFT_CARDS)
        || any_match(&lower, &TRAIT_CRYPTO_PAYMENT)
        || any_match(&lower, &TRAIT_SECRECY)
        || any_match(&lower, &TRAIT_SEXTORTION);
    let has_sus_link = any_match(&lower, &TRAIT_SUSPICIOUS_URL) && !any_match(&lower, &SAFE_URL_DOMAINS);
    let has_threats = any_match(&lower, &TRAIT_ACCOUNT_THREAT)
        || any_match(&lower, &TRAIT_ARREST_LEGAL);
    let has_urgency = any_match(&lower, &TRAIT_URGENCY);

    let layers = Layers {
        l1: has_cred,
        l2: has_deception,
        l3: has_dangerous,
        l4: has_sus_link,
        l5: has_threats,
        l6: has_urgency,
    };
    let fired = [has_cred, has_deception, has_dangerous, has_sus_link, has_threats, has_urgency]
        .iter().filter(|&&b| b).count() as u8;

    // Final score = signature score (if any)
    let score = sig_score;

    // SMS boost: lower threshold
    let effective_threshold = if channel == Channel::Sms { 50 } else { THREAT_THRESHOLD };
    let is_threat = score >= effective_threshold;

    let severity = if score >= 90 {
        Some(SeverityLevel::Critical)
    } else if score >= 70 {
        Some(SeverityLevel::High)
    } else if score >= 50 {
        Some(SeverityLevel::Medium)
    } else if score >= 30 {
        Some(SeverityLevel::Low)
    } else {
        None
    };

    let confidence = format!("{}%", score.min(100));

    // Label: signature name if matched, else generic layer description
    let label = if !sig_label.is_empty() {
        sig_label.to_string()
    } else {
        make_layer_label(&layers)
    };

    IntentResult {
        is_threat,
        severity,
        layers_fired: fired,
        layers,
        label,
        confidence,
        score,
    }
}

fn clean_result() -> IntentResult {
    IntentResult {
        is_threat: false,
        severity: None,
        layers_fired: 0,
        layers: Layers {
            l1: false, l2: false, l3: false,
            l4: false, l5: false, l6: false,
        },
        label: "Clean".to_string(),
        confidence: "0%".to_string(),
        score: 0,
    }
}

fn make_layer_label(layers: &Layers) -> String {
    let mut parts = Vec::new();
    if layers.l1 { parts.push("Credential-harvest"); }
    if layers.l2 { parts.push("Sender-deception"); }
    if layers.l3 { parts.push("Dangerous-action"); }
    if layers.l4 { parts.push("Suspicious-link"); }
    if layers.l5 { parts.push("Threat/extortion"); }
    if layers.l6 { parts.push("Urgency"); }
    if parts.is_empty() { "Clean".to_string() } else { parts.join(" + ") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_is_clean() {
        let r = parse("", Channel::Email);
        assert!(!r.is_threat);
        assert_eq!(r.score, 0);
        assert_eq!(r.label, "Clean");
    }

    #[test]
    fn benign_text_is_clean() {
        let r = parse("Hello, how are you today? The weather is nice.", Channel::Email);
        assert!(!r.is_threat);
        assert_eq!(r.score, 0);
    }

    #[test]
    fn newsletter_not_a_threat() {
        let text = "Here's your weekly account snapshot from American Express. \
                     View your statement now. Limited time: earn 5x points. Act now!";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Newsletter should be safe, score={}, label={}", r.score, r.label);
    }

    #[test]
    fn legitimate_bank_notification_safe() {
        let text = "Your Chase account: A new transaction of $52.00 was posted. \
                     Log in to chase.com to review your recent activity.";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Bank notification should be safe, score={}", r.score);
    }

    #[test]
    fn shipping_notification_safe() {
        let text = "Your UPS package is scheduled for delivery tomorrow. \
                     Track your shipment at ups.com/track.";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Shipping notification should be safe, score={}", r.score);
    }

    #[test]
    fn irs_phishing_ssn_plus_link() {
        let text = "This is the IRS. Your Social Security Number has been suspended. \
                     Verify your SSN immediately at http://192.168.1.1/verify \
                     or face arrest within 24 hours.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "IRS+SSN+IP-URL should be threat, score={}", r.score);
        assert!(r.score >= 85, "Score should be high, got {}", r.score);
    }

    #[test]
    fn irs_phishing_wire_transfer() {
        let text = "This is the IRS. Wire $5,000 penalty fee immediately \
                     to avoid prosecution. Your case officer demands action.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "IRS+wire should be threat, score={}", r.score);
        assert!(r.score >= 70);
    }

    #[test]
    fn bank_credential_phishing() {
        let text = "Your PayPal account has been limited. Please verify your password \
                     at http://paypa1-secure.xyz/login within 24 hours.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "Bank+cred+URL should be threat, score={}", r.score);
        assert!(r.score >= 80);
    }

    #[test]
    fn sextortion_is_threat() {
        let text = "Hello pervert. I have bad news. Your webcam was hacked. \
                     Send 0.5 bitcoin to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \
                     within 48 hours or I will ruin your reputation.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "Sextortion+crypto should be threat, score={}", r.score);
        assert!(r.score >= 90);
    }

    #[test]
    fn bec_gift_card_scam() {
        let text = "Hi, I need you to purchase some Google Play gift cards urgently. \
                     Get 5 cards at $200 each. Keep this between us. Send codes ASAP.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "BEC gift card should be threat, score={}", r.score);
        assert!(r.score >= 75);
    }

    #[test]
    fn bec_wire_transfer_scam() {
        let text = "Please wire $15,000 to the new vendor account immediately. \
                     This is confidential — do not tell anyone about this transfer.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "BEC wire should be threat, score={}", r.score);
        assert!(r.score >= 70);
    }

    #[test]
    fn crypto_seed_phrase_request() {
        let text = "To verify your wallet, please provide your seed phrase.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "Seed phrase request should be threat, score={}", r.score);
        assert!(r.score >= 90);
    }

    #[test]
    fn crypto_exchange_credential_phishing() {
        // Crypto-brand credential phishing with no suspicious URL: a Coinbase
        // exchange is not in TRAIT_FINANCIAL/TRAIT_TECH_COMPANY, so before the
        // crypto-context signal was wired in this scored below threshold and
        // slipped through, unlike the equivalent bank/tech phish.
        let text = "Security alert from Coinbase: your account has been locked. \
                     Confirm your password to restore access to your wallet.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "Crypto exchange credential phish should be threat, score={}", r.score);
        assert!(r.score >= 70, "Expected >=70, got {}", r.score);
    }

    #[test]
    fn legitimate_crypto_newsletter_safe() {
        // Crypto context + payment/urgency language, but no credential ask or
        // account threat — must stay below threshold (the false-positive case
        // the payment+urgency rules were deliberately left out to avoid).
        let text = "Bitcoin weekly: BTC and ethereum rallied. Our analysts expect \
                     more crypto momentum soon — read the full report now.";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Crypto newsletter should be safe, score={}, label={}", r.score, r.label);
    }

    #[test]
    fn urgency_alone_is_harmless() {
        let text = "Act now! Limited time offer. Final notice: your subscription expires today.";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Urgency alone should be safe, score={}", r.score);
    }

    #[test]
    fn threat_language_alone_not_enough() {
        let text = "Your account may be suspended. Failure to comply will result in legal action.";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Threats alone should be safe, score={}", r.score);
    }

    #[test]
    fn typosquat_alone_is_medium() {
        let text = "Visit paypa1-secure.com for your account update.";
        let r = parse(text, Channel::Email);
        // Typosquat alone = 60 (below 70 threshold but flagged as suspicious)
        assert!(!r.is_threat, "Typosquat alone should be below threshold, score={}", r.score);
        assert!(r.score >= 50, "But should have a meaningful score, got {}", r.score);
    }

    #[test]
    fn sms_bank_smishing() {
        let text = "Chase alert: Verify your password now at https://bit.ly/chase-verify \
                     or your account will be suspended.";
        let r = parse(text, Channel::Sms);
        assert!(r.is_threat, "SMS bank smishing should be threat, score={}", r.score);
    }

    #[test]
    fn fbi_arrest_urgency() {
        let text = "This is the FBI. You are required to respond immediately or face arrest \
                     within 24 hours. Failure to comply will result in legal action.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat, "FBI+arrest+urgency should be threat, score={}", r.score);
        assert!(r.score >= 70);
    }

    #[test]
    fn sales_email_safe() {
        let text = "Don't miss out! Our biggest sale of the year ends today. \
                     Save 50% on all items. Shop now at example.com. Final reminder!";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Sales email should be safe, score={}", r.score);
    }

    #[test]
    fn healthcare_notification_safe() {
        let text = "You have new test results available from Yorba Linda Primary Care. \
                     Log in to your patient portal to view them.";
        let r = parse(text, Channel::Email);
        assert!(!r.is_threat, "Healthcare notification should be safe, score={}", r.score);
    }
}
