//! `aisec-mcp` — MCP (Model Context Protocol) server exposing AISecurity's
//! intent_verifier and privacy_router as MCP tools.
//!
//! # Protocol
//!
//! Newline-delimited JSON-RPC 2.0 over stdio (the stdio variant of MCP).
//! Implements the minimum subset any MCP client needs:
//!
//!   * `initialize`       — handshake, returns protocol version + tools capability.
//!   * `initialized`      — one-shot notification after initialize, accepted & ignored.
//!   * `tools/list`       — enumerates `verify_intent`, `evaluate_privacy`,
//!     and `evaluate_install`.
//!   * `tools/call`       — dispatches to the configured AISecurity daemon.
//!   * `ping`             — returns `{}` (used by some clients as a health check).
//!
//! # Transport
//!
//! Tool calls are relayed over HTTP to the SecurityDaemon's in-process
//! listener at `127.0.0.1:7459` (override with `AISEC_DAEMON_URL`). This
//! keeps every MCP-capable agent honoring the same policy, audit log,
//! and coherence checks as the Claude Code hook and the local-HTTP
//! callers.
//!
//! If the daemon is not reachable, tool calls return an MCP error result
//! (not a JSON-RPC error) so the client surfaces it to the model as a
//! normal tool failure.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// Bypass is applied daemon-side — we stay a pure relay.

// ═══════════════════════════════════════════════════════════════════
// Protocol types — only what we need.
// ═══════════════════════════════════════════════════════════════════

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "aisec-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct JsonRpcReq {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: Value,
    /// Present on requests, absent on notifications.
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcOk<'a> {
    jsonrpc: &'a str,
    id: Value,
    result: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcErr<'a> {
    jsonrpc: &'a str,
    id: Value,
    error: JsonRpcErrBody<'a>,
}

#[derive(Debug, Serialize)]
struct JsonRpcErrBody<'a> {
    code: i32,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

// ═══════════════════════════════════════════════════════════════════
// Tool descriptors
// ═══════════════════════════════════════════════════════════════════

fn tool_descriptors() -> Value {
    json!([
        {
            "name": "verify_intent",
            "description": "Ask AISecurity whether a proposed AI-agent action \
                            should be allowed, denied, or asked about — given the \
                            stated current task. Uses the command-policy engine plus \
                            a task-coherence heuristic. Return shape: \
                            {decision, reason, matched_rule, task_coherent}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "current_task": {
                        "type": "string",
                        "description": "Natural-language description of what the user asked the agent to do."
                    },
                    "proposed_action": {
                        "type": "string",
                        "description": "The concrete action the agent is about to take, e.g. a shell command."
                    },
                    "kind": {
                        "type": "string",
                        "enum": ["shell", "file_write", "file_read", "network", "other"],
                        "description": "Kind of action. Shell gets full command-policy treatment; other kinds fall through to the configured default."
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional agent name (e.g. 'claude-code', 'aider') for per-agent policy lookup."
                    }
                },
                "required": ["current_task", "proposed_action", "kind"]
            }
        },
        {
            "name": "evaluate_privacy",
            "description": "Ask AISecurity whether an outbound LLM API request \
                            should proceed. Returns allow / warn / redact / block \
                            and, for redact, the sanitized body the caller should \
                            forward instead of the original. Use before sending \
                            prompts to third-party model APIs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Destination host, e.g. 'api.anthropic.com'."
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body as a UTF-8 string (typically JSON). Non-text bodies should be skipped by the caller."
                    }
                },
                "required": ["host", "body"]
            }
        },
        {
            "name": "evaluate_install",
            "description": "Ask AISecurity whether a proposed package install \
                            should proceed. Parses the manifest, cross-checks every \
                            pinned dependency against the OSV advisory database, and \
                            returns allow / ask / deny plus a list of flagged \
                            packages. Use before running `pip install`, `npm install`, \
                            `cargo install`, or any equivalent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest_content": {
                        "type": "string",
                        "description": "The text of a requirements.txt, package.json, or Cargo.toml (or similar)."
                    },
                    "ecosystem": {
                        "type": "string",
                        "enum": ["pypi", "npm", "cargo", "auto"],
                        "description": "Ecosystem hint. 'auto' detects from manifest shape. Defaults to 'auto'."
                    }
                },
                "required": ["manifest_content"]
            }
        }
    ])
}

// ═══════════════════════════════════════════════════════════════════
// HTTP client — keeps dependency footprint small.
// ═══════════════════════════════════════════════════════════════════

struct DaemonClient {
    host_port: String, // e.g. "127.0.0.1:7459"
}

impl DaemonClient {
    fn from_env() -> Self {
        let url = std::env::var("AISEC_DAEMON_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:7459".into());
        // Strip scheme; the client only speaks plain HTTP on localhost.
        let host_port = url
            .strip_prefix("http://")
            .unwrap_or(&url)
            .trim_end_matches('/')
            .to_string();
        Self { host_port }
    }

    /// POST `body` (UTF-8 JSON) to `path`. Returns (status, body).
    fn post_json(&self, path: &str, body: &str) -> std::io::Result<(u16, String)> {
        let mut s = TcpStream::connect(&self.host_port)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;

        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            path, self.host_port, body.len(), body
        );
        s.write_all(req.as_bytes())?;
        s.flush()?;

        let mut out = Vec::new();
        s.read_to_end(&mut out)?;
        let text = String::from_utf8_lossy(&out).into_owned();

        // Parse the status line.
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
        Ok((status, text[body_start..].to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════════

fn handle_initialize(req_id: Value) -> Value {
    let result = json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
        },
        "instructions": "Call verify_intent before executing any sensitive agent \
                         action (shell commands, file writes, outbound network). \
                         Call evaluate_privacy before sending a prompt to a \
                         third-party LLM API — the server may redact the body or \
                         block the call outright."
    });
    serde_json::to_value(JsonRpcOk {
        jsonrpc: "2.0",
        id: req_id,
        result,
    }).unwrap()
}

fn handle_tools_list(req_id: Value) -> Value {
    let result = json!({ "tools": tool_descriptors() });
    serde_json::to_value(JsonRpcOk {
        jsonrpc: "2.0",
        id: req_id,
        result,
    }).unwrap()
}

fn handle_ping(req_id: Value) -> Value {
    serde_json::to_value(JsonRpcOk {
        jsonrpc: "2.0",
        id: req_id,
        result: json!({}),
    }).unwrap()
}

fn handle_tools_call(req_id: Value, params: &Value, client: &DaemonClient) -> Value {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    // Note: bypass is applied daemon-side. We relay every call to the
    // daemon, which owns the bypass check AND the critical-secret floor.
    // A short-circuit here would bypass the floor too — which is exactly
    // what must NOT happen.
    let (path, forwarded_body) = match name {
        "verify_intent" => ("/intent/verify", args),
        "evaluate_privacy" => ("/privacy/evaluate", args),
        "evaluate_install" => ("/install/evaluate", args),
        _ => return error_response(req_id, -32602, &format!("unknown tool: {}", name), None),
    };

    let payload = match serde_json::to_string(&forwarded_body) {
        Ok(s) => s,
        Err(e) => return error_response(req_id, -32602, "invalid arguments", Some(json!(e.to_string()))),
    };

    match client.post_json(path, &payload) {
        Ok((status, body)) => {
            let parsed: Value = serde_json::from_str(&body).unwrap_or(json!({ "raw": body }));
            let is_error = status >= 400;
            // MCP tool results: content[].text carries the payload, isError signals failure.
            let result = json!({
                "content": [
                    {
                        "type": "text",
                        "text": serde_json::to_string(&parsed).unwrap_or(body.clone()),
                    }
                ],
                "isError": is_error,
                // Structured content (MCP 2024-11-05 optional but useful to clients).
                "structuredContent": parsed,
                "_meta": { "status": status }
            });
            serde_json::to_value(JsonRpcOk { jsonrpc: "2.0", id: req_id, result }).unwrap()
        }
        Err(e) => {
            // Daemon unreachable — return a tool-level error so the model sees it.
            let result = json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!(
                            "AISecurity daemon unreachable at {} — is AISecurity.app running? ({})",
                            client.host_port, e
                        ),
                    }
                ],
                "isError": true
            });
            serde_json::to_value(JsonRpcOk { jsonrpc: "2.0", id: req_id, result }).unwrap()
        }
    }
}

fn error_response(req_id: Value, code: i32, message: &str, data: Option<Value>) -> Value {
    serde_json::to_value(JsonRpcErr {
        jsonrpc: "2.0",
        id: req_id,
        error: JsonRpcErrBody { code, message, data },
    }).unwrap()
}

// ═══════════════════════════════════════════════════════════════════
// Dispatch
// ═══════════════════════════════════════════════════════════════════

/// Route a single JSON-RPC message. Returns `Some(response)` for requests,
/// `None` for notifications (which must not produce a reply).
fn route(raw: &Value, client: &DaemonClient) -> Option<Value> {
    let req: JsonRpcReq = match serde_json::from_value(raw.clone()) {
        Ok(r) => r,
        Err(_) => {
            // Can't recover an id from a malformed message; reply with null id.
            return Some(error_response(Value::Null, -32700, "parse error", None));
        }
    };

    if req.jsonrpc != "2.0" {
        return req.id.map(|id| error_response(id, -32600, "invalid jsonrpc version", None));
    }

    // Notifications: no reply.
    let is_notification = req.id.is_none();

    match req.method.as_str() {
        "initialize" => req.id.map(handle_initialize),
        "notifications/initialized" | "initialized" => {
            // Standard notification — acknowledge silently.
            None
        }
        "tools/list" => req.id.map(handle_tools_list),
        "tools/call" => req.id.map(|id| handle_tools_call(id, &req.params, client)),
        "ping" => req.id.map(handle_ping),
        _ => {
            if is_notification { None }
            else { Some(error_response(req.id.unwrap(), -32601, "method not found", Some(json!(req.method)))) }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// main — stdin line loop.
// ═══════════════════════════════════════════════════════════════════

fn main() {
    let client = DaemonClient::from_env();
    eprintln!(
        "{} v{} — relaying to http://{}",
        SERVER_NAME, SERVER_VERSION, client.host_port
    );

    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}: stdin error: {}", SERVER_NAME, e);
                break;
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                let err = error_response(Value::Null, -32700, "parse error", None);
                let _ = writeln!(out, "{}", err);
                let _ = out.flush();
                continue;
            }
        };

        if let Some(resp) = route(&parsed, &client) {
            if let Err(e) = writeln!(out, "{}", resp) {
                eprintln!("{}: stdout error: {}", SERVER_NAME, e);
                break;
            }
            let _ = out.flush();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests — unit-test the dispatcher with a mock (dead) daemon.
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// A client pointed at a closed port so we can exercise the error path
    /// deterministically without spinning up a fake server in each test.
    fn dead_client() -> DaemonClient {
        DaemonClient { host_port: "127.0.0.1:1".into() }
    }

    fn req(method: &str, id: Option<i64>, params: Value) -> Value {
        let mut m = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        if let Some(i) = id {
            m["id"] = json!(i);
        }
        m
    }

    #[test]
    fn initialize_returns_protocol_version_and_tools_cap() {
        let resp = route(&req("initialize", Some(1), json!({})), &dead_client()).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert!(resp["result"]["capabilities"]["tools"].is_object());
        assert_eq!(resp["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn tools_list_advertises_all_tools() {
        let resp = route(&req("tools/list", Some(2), json!({})), &dead_client()).unwrap();
        let tools = &resp["result"]["tools"];
        assert!(tools.is_array());
        let names: Vec<&str> = tools.as_array().unwrap().iter()
            .map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"verify_intent"));
        assert!(names.contains(&"evaluate_privacy"));
        assert!(names.contains(&"evaluate_install"));
    }

    #[test]
    fn initialized_notification_has_no_reply() {
        let mut msg = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        // No id — it's a notification.
        assert!(route(&msg, &dead_client()).is_none());
        // Also accept the bare "initialized" variant.
        msg["method"] = json!("initialized");
        assert!(route(&msg, &dead_client()).is_none());
    }

    #[test]
    fn unknown_method_returns_32601_for_requests() {
        let resp = route(&req("nope", Some(3), json!({})), &dead_client()).unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn unknown_method_has_no_reply_for_notifications() {
        let msg = json!({ "jsonrpc": "2.0", "method": "nope" });
        assert!(route(&msg, &dead_client()).is_none());
    }

    #[test]
    fn bad_jsonrpc_version_rejected() {
        let msg = json!({ "jsonrpc": "1.0", "method": "initialize", "id": 4 });
        let resp = route(&msg, &dead_client()).unwrap();
        assert_eq!(resp["error"]["code"], -32600);
    }

    #[test]
    fn tools_call_unknown_tool_is_32602() {
        let params = json!({ "name": "no_such_tool", "arguments": {} });
        let resp = route(&req("tools/call", Some(5), params), &dead_client()).unwrap();
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[test]
    fn tools_call_daemon_unreachable_is_tool_error_not_rpc_error() {
        // Routed to a closed port — the HTTP POST must fail and surface as
        // an MCP tool error (isError=true), not a JSON-RPC error.
        let params = json!({
            "name": "verify_intent",
            "arguments": {
                "current_task": "t", "proposed_action": "git status", "kind": "shell"
            }
        });
        let resp = route(&req("tools/call", Some(6), params), &dead_client()).unwrap();
        // Should be a successful JSON-RPC reply (no error field) with isError=true inside.
        assert!(resp.get("error").is_none());
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("daemon unreachable"));
    }

    #[test]
    fn ping_returns_empty_result() {
        let resp = route(&req("ping", Some(7), json!({})), &dead_client()).unwrap();
        assert_eq!(resp["result"], json!({}));
    }

    #[test]
    fn daemon_url_env_override_parses_scheme() {
        // Direct unit test of the URL-normalizing logic.
        std::env::set_var("AISEC_DAEMON_URL", "http://127.0.0.1:9999/");
        let c = DaemonClient::from_env();
        assert_eq!(c.host_port, "127.0.0.1:9999");
        std::env::set_var("AISEC_DAEMON_URL", "127.0.0.1:8888");
        let c = DaemonClient::from_env();
        assert_eq!(c.host_port, "127.0.0.1:8888");
        std::env::remove_var("AISEC_DAEMON_URL");
    }
}
