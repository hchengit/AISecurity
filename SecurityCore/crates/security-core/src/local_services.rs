//! `local_services` — in-process HTTP endpoints for AI-agent security.
//!
//! One bind port, two routes:
//!
//! * `POST /privacy/evaluate` — wraps [`privacy_router::evaluate_request`].
//! * `POST /intent/verify`    — wraps [`intent_verifier::verify`].
//! * `GET  /health`           — liveness probe.
//!
//! Designed for both uses:
//!
//! * **In-process (SecurityDaemon)**: call [`start_in_background`] once at
//!   daemon start. The listener lives on a detached thread and exits when
//!   the process exits.
//! * **Standalone binary**: `privacy-router` and the future intent-server
//!   binary both re-use [`run_blocking`].
//!
//! The listener uses `std::net` + hand-rolled HTTP/1.1 parsing — keeps the
//! dependency footprint small and avoids pulling tokio/hyper into
//! `security-core`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bypass::{self, BypassReason};
use crate::command_policy::CommandPolicyConfig;
use crate::config::SecurityConfig;
use crate::intent_verifier::{self, ActionKind, IntentDecision, IntentRequest, IntentVerifierConfig};
use crate::privacy_router::{self, PrivacyAction, PrivacyRouterConfig};

// ═══════════════════════════════════════════════════════════════════
// Public config
// ═══════════════════════════════════════════════════════════════════

/// Runtime options for the listener. `port=0` picks a free port (helpful in
/// tests; [`bound_port`] on the returned [`ServiceHandle`] reports the chosen
/// value).
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    pub bind_addr: String,
    pub config_path: Option<String>,
    pub audit_log_path: Option<String>,
}

impl Default for ServiceOptions {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:7459".into(),
            config_path: None,
            audit_log_path: None,
        }
    }
}

/// Returned from [`start_in_background`] so callers can log the bound port.
pub struct ServiceHandle {
    pub bound_addr: String,
}

// ═══════════════════════════════════════════════════════════════════
// Snapshot loaded at bind time (cheap on every request — no re-parse).
// ═══════════════════════════════════════════════════════════════════

struct Snapshot {
    privacy: PrivacyRouterConfig,
    intent: IntentVerifierConfig,
    command: CommandPolicyConfig,
    audit_log_path: Option<String>,
}

fn snapshot(opts: &ServiceOptions) -> Snapshot {
    let cfg = match &opts.config_path {
        Some(p) => SecurityConfig::load_or_default(p),
        None => SecurityConfig::default(),
    };
    Snapshot {
        privacy: cfg.privacy_router.clone(),
        intent: cfg.intent_verifier.clone(),
        command: cfg.command_policy.clone(),
        audit_log_path: opts.audit_log_path.clone(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Public entry points
// ═══════════════════════════════════════════════════════════════════

/// Spawn a detached thread running the listener. Returns immediately.
/// On bind failure, writes to stderr and returns `None`.
pub fn start_in_background(opts: ServiceOptions) -> Option<ServiceHandle> {
    let listener = match TcpListener::bind(&opts.bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("local_services: bind {} failed: {}", opts.bind_addr, e);
            return None;
        }
    };
    let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| opts.bind_addr.clone());
    let snap = Arc::new(snapshot(&opts));
    thread::Builder::new()
        .name("aisec-local-services".into())
        .spawn(move || {
            accept_loop(listener, snap);
        })
        .ok()?;
    Some(ServiceHandle { bound_addr: bound })
}

/// Blocking variant — used by the standalone binary. Never returns unless
/// the listener fails to bind.
pub fn run_blocking(opts: ServiceOptions) -> std::io::Result<()> {
    let listener = TcpListener::bind(&opts.bind_addr)?;
    let snap = Arc::new(snapshot(&opts));
    accept_loop(listener, snap);
    Ok(())
}

fn accept_loop(listener: TcpListener, snap: Arc<Snapshot>) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let snap = Arc::clone(&snap);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(s, &snap) {
                        eprintln!("local_services: conn error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("local_services: accept error: {}", e),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// HTTP — minimal, single-request, non-chunked.
// ═══════════════════════════════════════════════════════════════════

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024; // 8 MB

fn handle_conn(mut stream: TcpStream, snap: &Snapshot) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let peer = stream.peer_addr()?;
    let mut reader = BufReader::new(stream.try_clone()?);

    // Request line
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 { return Ok(()); }
    let req_line = line.trim_end_matches(&['\r', '\n'][..]).to_string();
    let mut parts = req_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    // Headers
    let mut content_length: usize = 0;
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 { break; }
        let h = h.trim_end_matches(&['\r', '\n'][..]).to_string();
        if h.is_empty() { break; }
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    // Routes
    match (method.as_str(), path.as_str()) {
        ("GET", "/health") => {
            return respond(&mut stream, 200, "application/json", b"{\"ok\":true}");
        }
        ("POST", "/privacy/evaluate") | ("POST", "/intent/verify") => {}
        _ => {
            return respond(&mut stream, 404, "application/json",
                b"{\"error\":\"unknown route. See docs for POST /privacy/evaluate, POST /intent/verify, GET /health.\"}");
        }
    }

    // Body
    if content_length > MAX_BODY_BYTES {
        return respond(&mut stream, 413, "application/json", b"{\"error\":\"body too large\"}");
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    let req_json: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{{\"error\":\"invalid JSON: {}\"}}", json_escape(&e.to_string()));
            return respond(&mut stream, 400, "application/json", msg.as_bytes());
        }
    };

    match path.as_str() {
        "/privacy/evaluate" => handle_privacy(&mut stream, snap, &peer.to_string(), &req_json),
        "/intent/verify"   => handle_intent(&mut stream, snap, &req_json),
        _ => unreachable!(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Route handlers
// ═══════════════════════════════════════════════════════════════════

fn handle_privacy(stream: &mut TcpStream, snap: &Snapshot, peer: &str, req: &Value) -> std::io::Result<()> {
    let host = req.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let body = req.get("body").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // Global bypass: user opted out of ROUTINE approval. Critical secrets
    // still never leave the machine — see privacy_router::evaluate_floor_only.
    if let Some(r) = bypass::active(None) {
        let floor = privacy_router::evaluate_floor_only(&host, &body, &snap.privacy);
        if floor.action == PrivacyAction::Block {
            // Floor violation under bypass — log both the bypass and the block.
            if let Some(path) = &snap.audit_log_path {
                let _ = write_audit_bypass(path, "privacy", peer, &host, &r);
                let _ = write_audit_privacy(path, peer, &host, &floor);
            }
            let response = json!({
                "action": "block",
                "reason": format!("{} — floor applies even while bypassed", floor.reason),
                "matched_host": floor.matched_host,
                "findings": floor.findings,
                "body_to_forward": Value::Null,
                "_bypass": true,
                "_floor": true,
            });
            let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
            return respond(stream, 403, "application/json", &bytes);
        }
        // No floor findings — pass the body through with a bypass marker.
        if let Some(path) = &snap.audit_log_path {
            let _ = write_audit_bypass(path, "privacy", peer, &host, &r);
        }
        let response = json!({
            "action": "allow",
            "reason": format!("bypass active ({})", r.as_audit_str()),
            "matched_host": floor.matched_host,
            "findings": [],
            "body_to_forward": body,
            "_bypass": true,
        });
        let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
        return respond(stream, 200, "application/json", &bytes);
    }

    let decision = privacy_router::evaluate_request(&host, &body, &snap.privacy);

    if snap.privacy.audit_enabled {
        if let Some(path) = &snap.audit_log_path {
            let _ = write_audit_privacy(path, peer, &host, &decision);
        }
    }

    let body_to_forward: Option<String> = match decision.action {
        PrivacyAction::Allow | PrivacyAction::Warn => Some(body),
        PrivacyAction::Redact => decision.redacted_body.clone(),
        PrivacyAction::Block => None,
    };

    let response = json!({
        "action": privacy_action_str(&decision.action),
        "reason": decision.reason,
        "matched_host": decision.matched_host,
        "findings": decision.findings,
        "body_to_forward": body_to_forward,
    });
    let status = if decision.action == PrivacyAction::Block { 403 } else { 200 };
    let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
    respond(stream, status, "application/json", &bytes)
}

#[derive(Debug, Deserialize)]
struct IntentRequestBody {
    current_task: Option<String>,
    proposed_action: Option<String>,
    kind: Option<String>,
    agent: Option<String>,
}

fn handle_intent(stream: &mut TcpStream, snap: &Snapshot, req: &Value) -> std::io::Result<()> {
    let body: IntentRequestBody = match serde_json::from_value(req.clone()) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{{\"error\":\"invalid intent request: {}\"}}", json_escape(&e.to_string()));
            return respond(stream, 400, "application/json", msg.as_bytes());
        }
    };

    // Global bypass.
    if let Some(r) = bypass::active(None) {
        if let Some(path) = &snap.audit_log_path {
            let agent = body.agent.as_deref().unwrap_or("");
            let _ = write_audit_bypass(path, "intent", agent, "", &r);
        }
        let response = json!({
            "decision": "allow",
            "reason": format!("bypass active ({})", r.as_audit_str()),
            "matched_rule": "bypass",
            "task_coherent": serde_json::Value::Null,
            "_bypass": true,
        });
        let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
        return respond(stream, 200, "application/json", &bytes);
    }

    let kind = match body.kind.as_deref().unwrap_or("other") {
        "shell" => ActionKind::Shell,
        "file_write" => ActionKind::FileWrite,
        "file_read"  => ActionKind::FileRead,
        "network"    => ActionKind::Network,
        _            => ActionKind::Other,
    };

    let req = IntentRequest {
        current_task: body.current_task.unwrap_or_default(),
        proposed_action: body.proposed_action.unwrap_or_default(),
        kind,
        agent: body.agent,
    };

    let verdict = intent_verifier::verify(&req, &snap.command, &snap.intent);

    if let Some(path) = &snap.audit_log_path {
        let _ = write_audit_intent(path, &req, &verdict);
    }

    let status = match verdict.decision {
        IntentDecision::Deny => 403,
        IntentDecision::Ask  => 202,
        IntentDecision::Allow => 200,
    };
    let response = json!({
        "decision": intent_decision_str(&verdict.decision),
        "reason": verdict.reason,
        "matched_rule": verdict.matched_rule,
        "task_coherent": verdict.task_coherent,
    });
    let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
    respond(stream, status, "application/json", &bytes)
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn respond(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK", 202 => "Accepted", 400 => "Bad Request", 403 => "Forbidden",
        404 => "Not Found", 413 => "Payload Too Large", _ => "Error"
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, reason, ctype, body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn privacy_action_str(a: &PrivacyAction) -> &'static str {
    match a {
        PrivacyAction::Allow => "allow",
        PrivacyAction::Warn  => "warn",
        PrivacyAction::Redact => "redact",
        PrivacyAction::Block => "block",
    }
}

fn intent_decision_str(d: &IntentDecision) -> &'static str {
    match d {
        IntentDecision::Allow => "allow",
        IntentDecision::Deny  => "deny",
        IntentDecision::Ask   => "ask",
    }
}

#[derive(Serialize)]
struct AuditPrivacy<'a> {
    ts: String,
    kind: &'static str,
    peer: &'a str,
    host: &'a str,
    action: &'a str,
    reason: &'a str,
    finding_count: usize,
}

fn write_audit_privacy(path: &str, peer: &str, host: &str, d: &privacy_router::PrivacyDecision) -> std::io::Result<()> {
    let rec = AuditPrivacy {
        ts: now_rfc3339(),
        kind: "privacy",
        peer,
        host,
        action: privacy_action_str(&d.action),
        reason: d.reason.as_str(),
        finding_count: d.findings.len(),
    };
    append_jsonl(path, &serde_json::to_string(&rec).unwrap_or_default())
}

#[derive(Serialize)]
struct AuditIntent<'a> {
    ts: String,
    kind: &'static str,
    agent: &'a str,
    action_kind: String,
    decision: &'a str,
    reason: &'a str,
    matched_rule: &'a str,
    task_coherent: Option<bool>,
}

fn write_audit_intent(path: &str, req: &IntentRequest, v: &intent_verifier::IntentVerdict) -> std::io::Result<()> {
    let rec = AuditIntent {
        ts: now_rfc3339(),
        kind: "intent",
        agent: req.agent.as_deref().unwrap_or(""),
        action_kind: format!("{:?}", req.kind),
        decision: intent_decision_str(&v.decision),
        reason: v.reason.as_str(),
        matched_rule: v.matched_rule.as_str(),
        task_coherent: v.task_coherent,
    };
    append_jsonl(path, &serde_json::to_string(&rec).unwrap_or_default())
}

#[derive(Serialize)]
struct AuditBypass<'a> {
    ts: String,
    kind: &'static str,
    subject: &'a str,      // "privacy" or "intent"
    peer_or_agent: &'a str,
    host: &'a str,
    bypass_source: String, // "file=..." or "env=AISEC_BYPASS"
}

fn write_audit_bypass(
    path: &str,
    subject: &'static str,
    peer_or_agent: &str,
    host: &str,
    reason: &BypassReason,
) -> std::io::Result<()> {
    let rec = AuditBypass {
        ts: now_rfc3339(),
        kind: "bypass",
        subject,
        peer_or_agent,
        host,
        bypass_source: reason.as_audit_str(),
    };
    append_jsonl(path, &serde_json::to_string(&rec).unwrap_or_default())
}

fn append_jsonl(path: &str, line: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ")
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn start_test_server() -> ServiceHandle {
        let opts = ServiceOptions {
            bind_addr: "127.0.0.1:0".into(),
            config_path: None,
            audit_log_path: None,
        };
        start_in_background(opts).expect("bind failed")
    }

    fn http_post(addr: &str, path: &str, body: &str) -> (u16, String) {
        let mut s = TcpStream::connect(addr).expect("connect");
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            path, body.len(), body
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status = out.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
        let body_start = out.find("\r\n\r\n").map(|i| i + 4).unwrap_or(out.len());
        (status, out[body_start..].to_string())
    }

    fn http_get(addr: &str, path: &str) -> (u16, String) {
        let mut s = TcpStream::connect(addr).expect("connect");
        let req = format!("GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        let status = out.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
        let body_start = out.find("\r\n\r\n").map(|i| i + 4).unwrap_or(out.len());
        (status, out[body_start..].to_string())
    }

    #[test]
    fn health_ok() {
        let h = start_test_server();
        let (status, body) = http_get(&h.bound_addr, "/health");
        assert_eq!(status, 200);
        assert!(body.contains("\"ok\":true"));
    }

    #[test]
    fn privacy_block_on_anthropic_key() {
        let h = start_test_server();
        let key = "sk-ant-".to_owned() + &"a".repeat(40);
        let payload = format!(
            r#"{{"host":"api.openai.com","body":"debug this: {}"}}"#, key);
        let (status, body) = http_post(&h.bound_addr, "/privacy/evaluate", &payload);
        assert_eq!(status, 403);
        assert!(body.contains("\"action\":\"block\""));
        assert!(body.contains("\"body_to_forward\":null"));
    }

    #[test]
    fn privacy_allow_clean_body() {
        let h = start_test_server();
        let payload = r#"{"host":"api.anthropic.com","body":"what is 2+2?"}"#;
        let (status, body) = http_post(&h.bound_addr, "/privacy/evaluate", payload);
        assert_eq!(status, 200);
        assert!(body.contains("\"action\":\"allow\""));
    }

    #[test]
    fn intent_deny_rms_root() {
        let h = start_test_server();
        let payload = r#"{"current_task":"clean up","proposed_action":"rm -rf /","kind":"shell","agent":"test"}"#;
        let (status, body) = http_post(&h.bound_addr, "/intent/verify", payload);
        assert_eq!(status, 403);
        assert!(body.contains("\"decision\":\"deny\""));
    }

    #[test]
    fn intent_allow_safe_shell() {
        let h = start_test_server();
        let payload = r#"{"current_task":"check git state","proposed_action":"git status","kind":"shell","agent":"test"}"#;
        let (status, body) = http_post(&h.bound_addr, "/intent/verify", payload);
        assert_eq!(status, 200);
        assert!(body.contains("\"decision\":\"allow\""));
    }

    #[test]
    fn intent_ask_for_install() {
        let h = start_test_server();
        let payload = r#"{"current_task":"add a tool","proposed_action":"brew install ripgrep","kind":"shell","agent":"test"}"#;
        let (status, body) = http_post(&h.bound_addr, "/intent/verify", payload);
        assert_eq!(status, 202);
        assert!(body.contains("\"decision\":\"ask\""));
    }

    #[test]
    fn unknown_route_404() {
        let h = start_test_server();
        let (status, _body) = http_post(&h.bound_addr, "/nope", "{}");
        assert_eq!(status, 404);
    }

    #[test]
    fn malformed_json_400() {
        let h = start_test_server();
        let (status, _body) = http_post(&h.bound_addr, "/privacy/evaluate", "not-json");
        assert_eq!(status, 400);
    }
}
