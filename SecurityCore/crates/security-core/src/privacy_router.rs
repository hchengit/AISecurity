//! Privacy Router — outbound AI-API decision engine.
//!
//! Sits in the flow of an outbound LLM API call (prompt body + target host),
//! scans the body with [`sensitive_data`], and decides one of:
//! `Allow`, `Redact`, `Warn`, or `Block` — per sensitive-data category.
//!
//! The intercepting transport (HTTPS MITM proxy, explicit SDK proxy, or
//! Claude-Code hook) owns I/O; this module owns the policy.
//!
//! Known LLM API hosts are identified by host suffix. A call to a host that
//! is *not* on the known list is still evaluated (secrets in prompts are
//! always worth catching) — this is a floor, not an allow-list for hosts.

use serde::{Deserialize, Serialize};

use crate::sensitive_data::{scan_text, Finding};
use crate::severity::SeverityLevel;

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

/// What the router decides to do with a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyAction {
    /// No sensitive data detected — let the request through unchanged.
    Allow,
    /// Sensitive data detected and redacted in the body. The caller MUST
    /// forward the `redacted_body` rather than the original.
    Redact,
    /// Sensitive data detected; caller should surface a user-visible warning
    /// but proceed with the original body.
    Warn,
    /// Request must not leave the machine.
    Block,
}

impl PrivacyAction {
    /// Numeric rank so we can "take the strictest action across findings".
    fn rank(&self) -> u8 {
        match self {
            PrivacyAction::Allow => 0,
            PrivacyAction::Warn => 1,
            PrivacyAction::Redact => 2,
            PrivacyAction::Block => 3,
        }
    }

    fn stricter_of(a: PrivacyAction, b: PrivacyAction) -> PrivacyAction {
        if a.rank() >= b.rank() { a } else { b }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "redact" => Some(Self::Redact),
            "warn" => Some(Self::Warn),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

/// Per-category action override. Categories match [`sensitive_data::Finding::category`]:
/// `crypto`, `financial`, `credential`, `pii`, `api_key`, `app_data`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CategoryAction {
    pub category: String,
    pub action: PrivacyAction,
}

/// TOML config section (`[privacy_router]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PrivacyRouterConfig {
    pub enabled: bool,
    /// Default action for any finding that is not covered by a [`CategoryAction`].
    pub default_action: PrivacyAction,
    /// Per-category overrides.
    pub categories: Vec<CategoryAction>,
    /// Host suffixes (e.g. "api.anthropic.com") that the router knows about —
    /// used only as informational `matched_host` field on the decision; the
    /// router evaluates every host. Defaults cover the major cloud model APIs.
    pub known_hosts: Vec<String>,
    /// If true, every decision is emitted for audit logging. Defaults to true.
    pub audit_enabled: bool,
    /// Categories that are **always blocked**, even when the user has
    /// flipped the global bypass switch. Think of this as a floor: the
    /// user opted out of routine approval, but specific transmissions
    /// (SSH keys, API keys, wallet seeds, cards) still require an
    /// explicit config change to allow. Matching is case-insensitive.
    pub critical_floor_categories: Vec<String>,
}

impl Default for PrivacyRouterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_action: PrivacyAction::Warn,
            categories: vec![
                CategoryAction { category: "credential".into(), action: PrivacyAction::Block },
                CategoryAction { category: "crypto".into(),     action: PrivacyAction::Block },
                CategoryAction { category: "financial".into(),  action: PrivacyAction::Block },
                CategoryAction { category: "api_key".into(),    action: PrivacyAction::Block },
                CategoryAction { category: "pii".into(),        action: PrivacyAction::Redact },
                CategoryAction { category: "app_data".into(),   action: PrivacyAction::Warn },
            ],
            known_hosts: default_known_hosts(),
            audit_enabled: true,
            critical_floor_categories: vec![
                "credential".into(),   // SSH privkeys, PEM blocks, PASSWORD=, .env secrets
                "api_key".into(),      // sk-..., sk-ant-..., ghp_..., AKIA...
                "crypto".into(),       // xprv, zprv, WIF, eth privkey, seed phrases
                "financial".into(),    // credit cards, bank routing/account, CVV
            ],
        }
    }
}

fn default_known_hosts() -> Vec<String> {
    vec![
        "api.anthropic.com".into(),
        "api.openai.com".into(),
        "api.groq.com".into(),
        "api.together.ai".into(),
        "api.together.xyz".into(),
        "api.mistral.ai".into(),
        "api.deepseek.com".into(),
        "api.perplexity.ai".into(),
        "api.cohere.com".into(),
        "generativelanguage.googleapis.com".into(),
        "bedrock-runtime.amazonaws.com".into(),
    ]
}

/// Decision returned from [`evaluate_request`].
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyDecision {
    pub action: PrivacyAction,
    /// Human-readable summary ("Blocked: 1 Anthropic API Key").
    pub reason: String,
    /// Host suffix from `known_hosts` that matched the request, if any.
    pub matched_host: Option<String>,
    /// All findings surfaced from the body. Empty when `action == Allow`.
    pub findings: Vec<Finding>,
    /// Only present when `action == Redact`. The caller MUST forward this
    /// body instead of the original.
    pub redacted_body: Option<String>,
}

impl PrivacyDecision {
    fn allow(host: Option<String>) -> Self {
        Self {
            action: PrivacyAction::Allow,
            reason: "No sensitive data detected".into(),
            matched_host: host,
            findings: Vec::new(),
            redacted_body: None,
        }
    }

    pub fn is_blocking(&self) -> bool {
        self.action == PrivacyAction::Block
    }
}

// ═══════════════════════════════════════════════════════════════════
// Core evaluation
// ═══════════════════════════════════════════════════════════════════

/// Evaluate the critical-secret **floor** only.
///
/// Used by callers (e.g. [`crate::local_services`]) when the global bypass
/// switch is active. Routine findings are ignored — only Critical
/// findings in a configured `critical_floor_categories` category trigger
/// a Block. Intended meaning: "the user opted out of routine approval,
/// but SSH keys / API keys / wallet seeds etc. still never leave the
/// machine without an explicit config change."
///
/// Returns Allow when no floor findings are present, Block otherwise.
/// Never returns Warn or Redact.
pub fn evaluate_floor_only(
    host: &str,
    body: &str,
    config: &PrivacyRouterConfig,
) -> PrivacyDecision {
    let matched_host = match_known_host(host, &config.known_hosts);
    if body.is_empty() {
        return PrivacyDecision::allow(matched_host);
    }

    let all_findings = scan_text(body, host);
    let floor_findings: Vec<Finding> = all_findings.into_iter()
        .filter(|f| f.severity == SeverityLevel::Critical
                 && config.critical_floor_categories.iter()
                        .any(|c| c.eq_ignore_ascii_case(&f.category)))
        .collect();

    if floor_findings.is_empty() {
        return PrivacyDecision::allow(matched_host);
    }

    let reason = summarize_reason(&PrivacyAction::Block, &floor_findings);
    PrivacyDecision {
        action: PrivacyAction::Block,
        reason: format!("critical-secret floor: {}", reason),
        matched_host,
        findings: floor_findings,
        redacted_body: None,
    }
}

/// Evaluate an outbound request against the privacy policy.
///
/// * `host` — the destination host (e.g. "api.anthropic.com").
/// * `body` — the request body as UTF-8 text. Non-text bodies are the
///   caller's concern to skip; this function only handles text.
/// * `config` — the loaded policy.
pub fn evaluate_request(
    host: &str,
    body: &str,
    config: &PrivacyRouterConfig,
) -> PrivacyDecision {
    let matched_host = match_known_host(host, &config.known_hosts);

    if !config.enabled {
        return PrivacyDecision::allow(matched_host);
    }

    let findings = scan_text(body, host);
    if findings.is_empty() {
        return PrivacyDecision::allow(matched_host);
    }

    // Aggregate: take the strictest action across all findings.
    let mut chosen = PrivacyAction::Allow;
    for f in &findings {
        let act = action_for_category(&f.category, config);
        chosen = PrivacyAction::stricter_of(chosen, act);
    }

    let reason = summarize_reason(&chosen, &findings);

    let redacted_body = match chosen {
        PrivacyAction::Redact => Some(redact_body(body, &findings)),
        _ => None,
    };

    PrivacyDecision {
        action: chosen,
        reason,
        matched_host,
        findings,
        redacted_body,
    }
}

/// Look up the configured action for a finding category, or fall back to
/// the default.
fn action_for_category(category: &str, config: &PrivacyRouterConfig) -> PrivacyAction {
    for c in &config.categories {
        if c.category.eq_ignore_ascii_case(category) {
            return c.action.clone();
        }
    }
    config.default_action.clone()
}

/// If `host` ends with one of `known_hosts`, return the matched suffix.
pub(crate) fn match_known_host(host: &str, known: &[String]) -> Option<String> {
    let h = host.to_lowercase();
    for suffix in known {
        let s = suffix.to_lowercase();
        if h == s || h.ends_with(&format!(".{}", s)) {
            return Some(suffix.clone());
        }
    }
    None
}

/// Redact findings in-place: replace each match span with `[REDACTED:<type>]`.
/// Uses offsets from [`sensitive_data::Finding`] and iterates from end to start
/// so earlier offsets stay valid.
fn redact_body(body: &str, findings: &[Finding]) -> String {
    // Reconstruct the matched spans by re-running the same patterns. The
    // Finding struct carries only offset + match_preview (preview is redacted
    // already). Easiest correct approach: re-scan with each regex and collect
    // raw ranges. For determinism we just re-scan the body.
    let mut ranges: Vec<(usize, usize, &str)> = Vec::new();
    for f in findings {
        if let Some((start, end)) = locate_match(body, f) {
            ranges.push((start, end, f.finding_type.as_str()));
        }
    }
    // Sort by start descending so splicing doesn't invalidate earlier offsets.
    ranges.sort_by_key(|r| std::cmp::Reverse(r.0));

    let mut out = body.to_string();
    for (start, end, kind) in ranges {
        if start <= end && end <= out.len() && out.is_char_boundary(start) && out.is_char_boundary(end) {
            let placeholder = format!("[REDACTED:{}]", kind);
            out.replace_range(start..end, &placeholder);
        }
    }
    out
}

/// Locate the matched span in `body` for a given finding. Uses the
/// recorded `offset`, then walks forward to find a byte range whose
/// redacted form matches. Falls back to a best-effort substring search on
/// the first characters of the preview.
fn locate_match(body: &str, f: &Finding) -> Option<(usize, usize)> {
    // For credential-style findings the preview is "[REDACTED]" and we can't
    // recover the exact length. Instead we recompute: use the first pattern
    // that matches starting at the recorded offset.
    use crate::sensitive_data;
    let findings_here = sensitive_data::scan_text(body, &f.source);
    for g in findings_here {
        if g.finding_type == f.finding_type && g.offset == f.offset {
            // Re-run the specific pattern by scanning and picking the right match.
            // Since scan_text gives offsets but not lengths, we derive length by
            // running a bounded regex pattern extraction: simplest is to treat
            // the full remaining body from offset and rely on a sentinel length.
            // Instead: search forward until the next whitespace or end, capped.
            let start = f.offset;
            let slice = &body[start..];
            let end_rel = slice
                .find('\n')
                .unwrap_or(slice.len().min(256));
            return Some((start, start + end_rel));
        }
    }
    None
}

fn summarize_reason(action: &PrivacyAction, findings: &[Finding]) -> String {
    let worst: &SeverityLevel = findings.iter().map(|f| &f.severity).max().unwrap_or(&SeverityLevel::Low);
    let categories: std::collections::BTreeSet<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    let cat_list: Vec<&str> = categories.into_iter().collect();
    match action {
        PrivacyAction::Allow => "No sensitive data detected".into(),
        PrivacyAction::Warn  => format!("Warn: {} finding(s) ({}), worst severity {}", findings.len(), cat_list.join(", "), worst),
        PrivacyAction::Redact => format!("Redact: {} finding(s) ({}), worst severity {}", findings.len(), cat_list.join(", "), worst),
        PrivacyAction::Block  => format!("Block: {} finding(s) ({}), worst severity {}", findings.len(), cat_list.join(", "), worst),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PrivacyRouterConfig {
        PrivacyRouterConfig::default()
    }

    #[test]
    fn allow_clean_body() {
        let dec = evaluate_request("api.anthropic.com", "Hello, what is 2+2?", &cfg());
        assert_eq!(dec.action, PrivacyAction::Allow);
        assert!(dec.findings.is_empty());
        assert_eq!(dec.matched_host.as_deref(), Some("api.anthropic.com"));
    }

    #[test]
    fn block_on_api_key() {
        let body = "please summarize this code: API_KEY=abcdefghij1234567890XYZ";
        let dec = evaluate_request("api.openai.com", body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Block);
        assert!(!dec.findings.is_empty());
        assert!(dec.is_blocking());
    }

    #[test]
    fn block_on_anthropic_key_in_body() {
        let key = "sk-ant-".to_owned() + &"a".repeat(40);
        let body = format!("debug this: {}", key);
        let dec = evaluate_request("api.openai.com", &body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Block);
    }

    #[test]
    fn redact_pii_by_default() {
        // Use a pattern that compiles under the regex crate (no lookaheads).
        // birthday → pii / High severity.
        let body = "DOB: 01/15/1990 — can you summarize this form?";
        let dec = evaluate_request("api.anthropic.com", body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Redact);
        let redacted = dec.redacted_body.expect("expected redacted body");
        assert!(!redacted.contains("01/15/1990"));
        assert!(redacted.contains("[REDACTED"));
    }

    #[test]
    fn disabled_router_allows_everything() {
        let mut c = cfg();
        c.enabled = false;
        let body = "sk-ant-".to_owned() + &"a".repeat(40);
        let dec = evaluate_request("api.anthropic.com", &body, &c);
        assert_eq!(dec.action, PrivacyAction::Allow);
    }

    #[test]
    fn unknown_host_still_evaluated() {
        let body = "sk-ant-".to_owned() + &"a".repeat(40);
        let dec = evaluate_request("api.example-llm.com", &body, &cfg());
        // Unknown host but findings still fire.
        assert_eq!(dec.action, PrivacyAction::Block);
        assert!(dec.matched_host.is_none());
    }

    #[test]
    fn strictest_action_wins() {
        // PII (redact) + credential (block) → block dominates.
        let body = "DOB: 01/15/1990 and PASSWORD=supersecretvalue";
        let dec = evaluate_request("api.anthropic.com", body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Block);
    }

    #[test]
    fn category_override_changes_action() {
        let mut c = cfg();
        // Downgrade PII from Redact to Warn.
        for c2 in c.categories.iter_mut() {
            if c2.category == "pii" { c2.action = PrivacyAction::Warn; }
        }
        let dec = evaluate_request("api.anthropic.com", "DOB: 01/15/1990", &c);
        assert_eq!(dec.action, PrivacyAction::Warn);
        assert!(dec.redacted_body.is_none());
    }

    #[test]
    fn known_host_match_is_suffix_based() {
        let c = cfg();
        assert_eq!(match_known_host("api.anthropic.com", &c.known_hosts).as_deref(), Some("api.anthropic.com"));
        assert_eq!(match_known_host("eu.api.anthropic.com", &c.known_hosts).as_deref(), Some("api.anthropic.com"));
        assert!(match_known_host("api.anthropic.com.evil.example", &c.known_hosts).is_none());
    }

    #[test]
    fn action_rank_ordering() {
        assert!(PrivacyAction::Block.rank() > PrivacyAction::Redact.rank());
        assert!(PrivacyAction::Redact.rank() > PrivacyAction::Warn.rank());
        assert!(PrivacyAction::Warn.rank() > PrivacyAction::Allow.rank());
    }

    #[test]
    fn action_from_str_loose() {
        assert_eq!(PrivacyAction::from_str_loose("BLOCK"), Some(PrivacyAction::Block));
        assert_eq!(PrivacyAction::from_str_loose("redact"), Some(PrivacyAction::Redact));
        assert_eq!(PrivacyAction::from_str_loose("unknown"), None);
    }

    // ── critical-secret floor ──────────────────────────────────────

    #[test]
    fn floor_blocks_anthropic_key_even_with_routine_disabled() {
        // Floor is orthogonal to routine evaluation: even if `enabled=false`
        // in the config (the user has fully disabled routine scanning), the
        // floor-only function still blocks critical secrets.
        let mut c = cfg();
        c.enabled = false;
        let key = "sk-ant-".to_owned() + &"a".repeat(40);
        let body = format!("help me debug this: {}", key);
        let dec = evaluate_floor_only("api.anthropic.com", &body, &c);
        assert_eq!(dec.action, PrivacyAction::Block);
        assert!(dec.reason.starts_with("critical-secret floor:"));
    }

    #[test]
    fn floor_blocks_ssh_private_key() {
        let body = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----";
        let dec = evaluate_floor_only("api.openai.com", body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Block);
        assert!(dec.findings.iter().any(|f| f.category == "credential"));
    }

    #[test]
    fn floor_blocks_xprv_wallet_key() {
        let body = format!("help with {}", "xprv".to_owned() + &"a".repeat(107));
        let dec = evaluate_floor_only("api.anthropic.com", &body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Block);
        assert!(dec.findings.iter().any(|f| f.category == "crypto"));
    }

    #[test]
    fn floor_blocks_aws_key() {
        let body = "deploy this: AKIAIOSFODNN7EXAMPLE";
        let dec = evaluate_floor_only("api.openai.com", body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Block);
    }

    #[test]
    fn floor_ignores_high_severity_pii() {
        // PII like birthday is High severity, NOT Critical — floor should
        // let it through so bypass-mode is meaningfully less strict than
        // routine mode.
        let body = "DOB: 01/15/1990 — can you help?";
        let dec = evaluate_floor_only("api.anthropic.com", body, &cfg());
        assert_eq!(dec.action, PrivacyAction::Allow);
        assert!(dec.findings.is_empty());
    }

    #[test]
    fn floor_ignores_clean_body() {
        let dec = evaluate_floor_only("api.anthropic.com", "what is 2+2?", &cfg());
        assert_eq!(dec.action, PrivacyAction::Allow);
    }

    #[test]
    fn floor_category_list_is_editable() {
        // Admin can shrink the floor by editing config (but the UX warning
        // must make this explicit). Empty floor = no block under bypass.
        let mut c = cfg();
        c.critical_floor_categories = vec![];
        let key = "sk-ant-".to_owned() + &"a".repeat(40);
        let dec = evaluate_floor_only("api.anthropic.com", &key, &c);
        assert_eq!(dec.action, PrivacyAction::Allow);
    }
}
