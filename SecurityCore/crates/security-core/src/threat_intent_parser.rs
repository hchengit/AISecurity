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

/// Result of 7-layer intent analysis.
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

// L1 — Entity Mention
static L1_ENTITIES: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r"\b(?:irs|internal\s+revenue|fbi|federal\s+bureau|ssa|social\s+security|doj|department\s+of\s+justice|homeland\s+security|dhs|sec\b|ftc|fdic)\b",
        r"\b(?:chase|wells\s+fargo|bank\s+of\s+america|citibank|capital\s+one|us\s+bank|td\s+bank|paypal|zelle|venmo|cashapp|wire\s+transfer)\b",
        r"\b(?:apple|icloud|apple\s+id|google|microsoft|amazon|netflix|paypal)\b",
        r"\b(?:fedex|ups|usps|dhl|amazon\s+delivery)\b",
        r"\b(?:court|warrant|subpoena|lawsuit|litigation|legal\s+action|attorney|counsel)\b",
    ])
});

// L2 — Directed At User
static L2_DIRECTED: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r"\byour\s+(?:account|card|number|identity|information|records?|case|file|benefits?|ssn|license)\b",
        r"\byou\s+(?:must|need\s+to|are\s+required\s+to|have\s+been|owe|will\s+be|may\s+be)\b",
        r"\bwe\s+(?:are\s+contacting|have\s+flagged|have\s+detected|are\s+reaching\s+out\s+to)\s+you\b",
        r"\byour\s+(?:recent|last|latest)\s+(?:transaction|activity|login|sign[-\s]?in|purchase)\b",
        r"\bnotice\s+(?:to|for)\s+(?:you|the\s+account\s+holder)\b",
    ])
});

// L3 — Authority Claim
static L3_AUTHORITY: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r"\bthis\s+is\s+(?:the\s+)?(?:irs|fbi|ssa|social\s+security|your\s+bank|apple|microsoft|amazon)\b",
        r"\b(?:official|formal)\s+(?:notice|communication|letter|warning)\s+from\b",
        r"\bwe\s+(?:are|represent)\s+(?:the\s+)?(?:irs|fbi|ssa|federal|your\s+financial\s+institution)\b",
        r"\b(?:on\s+behalf\s+of|acting\s+(?:as|for))\s+(?:the\s+)?(?:irs|fbi|ssa|department|agency|bank)\b",
        r"\b(?:agent|officer|investigator|representative|department)\s+(?:id|badge|number|#)\s*:?\s*\d+\b",
        r"\byour\s+(?:assigned|case|file)\s+(?:agent|officer|investigator)\b",
    ])
});

// L4 — Action Demand
static L4_ACTION: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r"\b(?:click|tap)\s+(?:here|the\s+link|below)\s+(?:to|now)\b",
        r"\b(?:call|contact|reach)\s+(?:us|our\s+(?:team|support|office)|immediately)\s+(?:at|on|now)?\s*(?:\+?[\d\s\-\(\)]{7,})?",
        r"\b(?:pay|send|transfer|wire)\s+(?:\$[\d,]+|the\s+(?:amount|balance|fee))\b",
        r"\b(?:verify|confirm|update|provide|submit|enter|reply\s+with)\s+your\s+(?:account|identity|information|details|card|ssn|password|pin|code)\b",
        r"\b(?:download|open|run|install|execute)\s+(?:the\s+)?(?:attachment|file|document|form|app)\b",
        r"\b(?:do\s+not\s+ignore|must\s+respond|required\s+to\s+(?:respond|act|comply))\b",
    ])
});

// L5 — Urgency Signal
static L5_URGENCY: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r"\bwithin\s+(?:\d+\s+)?(?:hours?|minutes?|days?|business\s+days?)\b",
        r"\b(?:immediately|urgently|right\s+away|right\s+now|as\s+soon\s+as\s+possible|asap)\b",
        r"\b(?:final|last|urgent|immediate)\s+(?:notice|warning|reminder|chance|opportunity)\b",
        r"\b(?:expires?|expiring)\s+(?:today|tonight|soon|in\s+\d+\s+hours?)\b",
        r"\b(?:deadline|time[-\s]sensitive|time\s+is\s+running\s+out|do\s+not\s+delay)\b",
        r"\b(?:today\s+only|limited\s+time|act\s+now|respond\s+now|call\s+now)\b",
    ])
});

// L6 — Fear / Consequence
static L6_CONSEQUENCE: Lazy<Vec<Regex>> = Lazy::new(|| {
    compile(&[
        r"\b(?:arrest|arrested|detain|detained|taken\s+into\s+custody)\b",
        r"\b(?:suspend|suspended|termina(?:te|ted)|cancel(?:led)?|clos(?:e|ed))\s+your\s+(?:account|card|number|access|service|benefits?)\b",
        r"\b(?:legal|criminal|civil)\s+(?:action|charges?|proceedings?|penalty|penalties)\b",
        r"\b(?:lawsuit|sued|prosecution|prosecuted|indicted|indictment)\b",
        r"\b(?:freeze|frozen|block(?:ed)?)\s+(?:your\s+)?(?:account|funds?|assets?|card)\b",
        r"\bpenalt(?:y|ies)\s+(?:of|including|up\s+to)\s+\$[\d,]+\b",
        r"\b(?:lose|forfeit|seize|seized)\s+(?:your\s+)?(?:account|assets?|funds?|property|license)\b",
        r"\bfailure\s+to\s+(?:comply|respond|pay|act|verify)\s+(?:will|may|could|shall)\b",
    ])
});

/// 7-Layer Intent Scoring Engine.
///
/// Each layer asks a progressively deeper question about the text's intent.
/// Only content scoring across MULTIPLE layers is treated as a real threat.
pub fn parse(text: &str, channel: Channel) -> IntentResult {
    if text.is_empty() {
        return clean_result();
    }

    let lower = text.to_lowercase();

    let l1 = any_match(&lower, &L1_ENTITIES);
    let l2 = any_match(&lower, &L2_DIRECTED);
    let l3 = any_match(&lower, &L3_AUTHORITY);
    let l4 = any_match(&lower, &L4_ACTION);
    let l5 = any_match(&lower, &L5_URGENCY);
    let l6 = any_match(&lower, &L6_CONSEQUENCE);

    let layers = Layers { l1, l2, l3, l4, l5, l6 };
    let fired = [l1, l2, l3, l4, l5, l6].iter().filter(|&&b| b).count() as u8;

    let mut severity = None;
    let mut is_threat = false;

    if fired >= 5 {
        severity = Some(SeverityLevel::Critical);
        is_threat = true;
    } else if fired >= 4 {
        severity = Some(SeverityLevel::High);
        is_threat = true;
    } else if fired >= 3 {
        severity = Some(SeverityLevel::Medium);
        is_threat = true;
    } else if fired >= 2 {
        severity = Some(SeverityLevel::Low);
        // is_threat stays false
    }

    // SMS boost — scammers use less text
    if channel == Channel::Sms && fired >= 4 {
        severity = Some(SeverityLevel::Critical);
    }

    let confidence = format!("{}%", (fired as f64 / 6.0 * 100.0).round() as u32);

    let label = make_label(&layers);

    IntentResult {
        is_threat,
        severity,
        layers_fired: fired,
        layers,
        label,
        confidence,
    }
}

fn clean_result() -> IntentResult {
    IntentResult {
        is_threat: false,
        severity: None,
        layers_fired: 0,
        layers: Layers {
            l1: false,
            l2: false,
            l3: false,
            l4: false,
            l5: false,
            l6: false,
        },
        label: "Clean".to_string(),
        confidence: "0%".to_string(),
    }
}

fn make_label(layers: &Layers) -> String {
    let mut parts = Vec::new();
    if layers.l1 { parts.push("Entity"); }
    if layers.l2 { parts.push("Directed-at-user"); }
    if layers.l3 { parts.push("Authority-claim"); }
    if layers.l4 { parts.push("Action-demand"); }
    if layers.l5 { parts.push("Urgency"); }
    if layers.l6 { parts.push("Fear/consequence"); }
    if parts.is_empty() {
        "Clean".to_string()
    } else {
        parts.join(" + ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_is_clean() {
        let r = parse("", Channel::Email);
        assert!(!r.is_threat);
        assert_eq!(r.layers_fired, 0);
        assert_eq!(r.label, "Clean");
    }

    #[test]
    fn benign_text_is_clean() {
        let r = parse("Hello, how are you today? The weather is nice.", Channel::Email);
        assert!(!r.is_threat);
        assert_eq!(r.layers_fired, 0);
    }

    #[test]
    fn irs_phishing_is_critical() {
        let text = "This is the IRS. Your account has been suspended. \
                     Call us immediately at 1-800-555-0123 or face arrest within 24 hours.";
        let r = parse(text, Channel::Email);
        assert!(r.is_threat);
        assert!(r.layers_fired >= 5);
        assert_eq!(r.severity, Some(SeverityLevel::Critical));
    }

    #[test]
    fn sms_boost_four_layers_to_critical() {
        // Construct text that hits exactly 4 layers
        let text = "Your Chase account has been suspended. Verify your identity immediately or your account will be frozen.";
        let r = parse(text, Channel::Sms);
        if r.layers_fired >= 4 {
            assert_eq!(r.severity, Some(SeverityLevel::Critical));
        }
    }

    #[test]
    fn two_layers_is_low_not_threat() {
        let text = "Apple has detected unusual activity on your account.";
        let r = parse(text, Channel::Email);
        // Should hit L1 (entity) and L2 (directed at user)
        assert!(r.layers_fired >= 2);
        if r.layers_fired == 2 {
            assert!(!r.is_threat);
            assert_eq!(r.severity, Some(SeverityLevel::Low));
        }
    }
}
