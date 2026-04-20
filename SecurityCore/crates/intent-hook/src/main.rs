//! `intent-hook` — Claude Code PreToolUse hook.
//!
//! Reads the hook event JSON from stdin, extracts the proposed action,
//! consults [`security_core::intent_verifier::verify`], and emits
//! Claude Code's `hookSpecificOutput` JSON on stdout with a decision of
//! `allow` / `deny` / `ask`.
//!
//! Task signal: tries the most recent user turn in `transcript_path`.
//! If missing / unreadable, falls back to an empty task string — the
//! coherence heuristic treats that as "always coherent", so the hook
//! degrades gracefully to pure command-policy enforcement.
//!
//! Wire up in `~/.claude/settings.json`:
//!
//! ```json
//! {
//!   "hooks": {
//!     "PreToolUse": [
//!       {
//!         "matcher": "Bash|Write|Edit",
//!         "hooks": [{ "type": "command",
//!                     "command": "/usr/local/bin/intent-hook" }]
//!       }
//!     ]
//!   }
//! }
//! ```
//!
//! Exit codes:
//!   0 — normal; decision is in stdout JSON.
//!   2 — blocking error (malformed input, verifier crashed). Claude Code
//!       shows stderr to the model as a tool-prevention message.

use std::io::Read;
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::{json, Value};

use security_core::bypass;
use security_core::config::SecurityConfig;
use security_core::intent_verifier::{
    verify, ActionKind, IntentDecision, IntentRequest,
};

// ═══════════════════════════════════════════════════════════════════
// Claude Code hook input shape
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    transcript_path: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Action extraction
// ═══════════════════════════════════════════════════════════════════

fn tool_to_action(tool_name: &str, input: &Value) -> Option<(ActionKind, String)> {
    match tool_name {
        "Bash" => {
            let cmd = input.get("command")?.as_str()?.to_string();
            Some((ActionKind::Shell, cmd))
        }
        "Write" => {
            let path = input.get("file_path")?.as_str()?.to_string();
            Some((ActionKind::FileWrite, format!("Write to {}", path)))
        }
        "Edit" | "NotebookEdit" => {
            let path = input.get("file_path")?.as_str()?.to_string();
            Some((ActionKind::FileWrite, format!("Edit {}", path)))
        }
        "Read" => {
            let path = input.get("file_path")?.as_str()?.to_string();
            Some((ActionKind::FileRead, format!("Read {}", path)))
        }
        "WebFetch" | "WebSearch" => {
            let target = input.get("url")
                .or_else(|| input.get("query"))
                .and_then(|v| v.as_str()).unwrap_or("").to_string();
            Some((ActionKind::Network, format!("{} {}", tool_name, target)))
        }
        _ => {
            // Unknown tool — treat as Other with a best-effort stringification.
            let s = serde_json::to_string(input).unwrap_or_default();
            Some((ActionKind::Other, format!("{}: {}", tool_name, s)))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Transcript → last user turn
// ═══════════════════════════════════════════════════════════════════

/// Walk the transcript JSONL and return the most recent user message text.
/// On any error, returns an empty string. The intent verifier's coherence
/// check treats an empty task as "coherent" so we fail-open for the
/// coherence signal while the command-policy check is unaffected.
fn last_user_turn(path: &str) -> String {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    let mut last: Option<String> = None;
    for line in content.lines() {
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|s| s.as_str()) == Some("user")
            || v.get("role").and_then(|s| s.as_str()) == Some("user")
        {
            if let Some(text) = extract_user_text(&v) {
                if !text.trim().is_empty() {
                    last = Some(text);
                }
            }
        }
    }
    last.unwrap_or_default()
}

fn extract_user_text(v: &Value) -> Option<String> {
    // Try common shapes used by Claude Code transcripts:
    //   { "message": { "content": [{ "type": "text", "text": "..." }, ...] } }
    //   { "message": { "content": "plain string" } }
    //   { "content": [...] }
    let msg = v.get("message").unwrap_or(v);
    let content = msg.get("content")?;
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(arr) => {
            let mut buf = String::new();
            for item in arr {
                if item.get("type").and_then(|t| t.as_str()) == Some("text") {
                    if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                        if !buf.is_empty() { buf.push('\n'); }
                        buf.push_str(t);
                    }
                } else if let Some(t) = item.as_str() {
                    buf.push_str(t);
                }
            }
            if buf.is_empty() { None } else { Some(buf) }
        }
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Decision → hook output
// ═══════════════════════════════════════════════════════════════════

fn hook_decision_json(decision: &IntentDecision, reason: &str) -> Value {
    let perm = match decision {
        IntentDecision::Allow => "allow",
        IntentDecision::Deny  => "deny",
        IntentDecision::Ask   => "ask",
    };
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": perm,
            "permissionDecisionReason": reason,
        }
    })
}

// ═══════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════

fn resolve_config_path() -> String {
    if let Ok(p) = std::env::var("AISECURITY_CONFIG") {
        return p;
    }
    match std::env::var("HOME") {
        Ok(h) => format!("{}/.mac-security/config.toml", h),
        Err(_) => "/tmp/.mac-security/config.toml".into(),
    }
}

fn main() -> ExitCode {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        eprintln!("intent-hook: failed to read stdin: {}", e);
        return ExitCode::from(2);
    }
    if raw.trim().is_empty() {
        // Nothing to evaluate — allow.
        println!("{}", hook_decision_json(&IntentDecision::Allow, "no input"));
        return ExitCode::SUCCESS;
    }

    let input: HookInput = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            // Fail open with a warning. A malformed hook input should not
            // block every Claude Code tool call.
            eprintln!("intent-hook: invalid JSON on stdin: {}", e);
            println!("{}", hook_decision_json(&IntentDecision::Allow, "invalid hook input"));
            return ExitCode::SUCCESS;
        }
    };

    let (kind, proposed_action) = match tool_to_action(&input.tool_name, &input.tool_input) {
        Some(x) => x,
        None => {
            // Couldn't extract — let it through with a note.
            println!("{}", hook_decision_json(&IntentDecision::Allow,
                &format!("no action extractable for {}", input.tool_name)));
            return ExitCode::SUCCESS;
        }
    };

    // Global bypass: user opted out of agent protection.
    if let Some(r) = bypass::active(None) {
        println!("{}", hook_decision_json(&IntentDecision::Allow,
            &format!("bypass active ({}) — AI-agent protection disabled", r.as_audit_str())));
        return ExitCode::SUCCESS;
    }

    let task = input.transcript_path.as_deref()
        .map(last_user_turn)
        .unwrap_or_default();

    let req = IntentRequest {
        current_task: task,
        proposed_action,
        kind,
        agent: Some("claude-code".into()),
    };

    let cfg = SecurityConfig::load_or_default(&resolve_config_path());
    let verdict = verify(&req, &cfg.command_policy, &cfg.intent_verifier);

    // Compose a reason that includes both the rule and the coherence hint.
    let mut reason = format!("{} ({})", verdict.reason, verdict.matched_rule);
    if verdict.task_coherent == Some(false) {
        reason.push_str(" [task-coherence: FAIL — action not plausibly related to stated task]");
    }

    println!("{}", hook_decision_json(&verdict.decision, &reason));
    ExitCode::SUCCESS
}

// ═══════════════════════════════════════════════════════════════════
// Tests — the CLI is trivial, but the helpers are worth nailing down.
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bash_command() {
        let input = json!({ "command": "rm -rf /tmp/foo", "description": "clean up" });
        let (kind, action) = tool_to_action("Bash", &input).unwrap();
        assert_eq!(kind, ActionKind::Shell);
        assert_eq!(action, "rm -rf /tmp/foo");
    }

    #[test]
    fn extract_write_path() {
        let input = json!({ "file_path": "/tmp/x.txt", "content": "hi" });
        let (kind, action) = tool_to_action("Write", &input).unwrap();
        assert_eq!(kind, ActionKind::FileWrite);
        assert!(action.contains("/tmp/x.txt"));
    }

    #[test]
    fn extract_edit_path() {
        let input = json!({ "file_path": "/tmp/y.rs", "old_string": "a", "new_string": "b" });
        let (kind, _) = tool_to_action("Edit", &input).unwrap();
        assert_eq!(kind, ActionKind::FileWrite);
    }

    #[test]
    fn extract_webfetch_url() {
        let input = json!({ "url": "https://example.com", "prompt": "summarize" });
        let (kind, action) = tool_to_action("WebFetch", &input).unwrap();
        assert_eq!(kind, ActionKind::Network);
        assert!(action.contains("example.com"));
    }

    #[test]
    fn unknown_tool_defaults_to_other() {
        let (kind, _) = tool_to_action("SomeCustomTool", &json!({"x": 1})).unwrap();
        assert_eq!(kind, ActionKind::Other);
    }

    #[test]
    fn hook_decision_json_shape() {
        let v = hook_decision_json(&IntentDecision::Deny, "nope");
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "nope");
    }

    #[test]
    fn last_user_turn_handles_string_content() {
        let tmp = std::env::temp_dir().join("intent_hook_transcript_s.jsonl");
        let _ = std::fs::write(&tmp, "{\"type\":\"user\",\"message\":{\"content\":\"do the thing\"}}\n");
        let last = last_user_turn(tmp.to_str().unwrap());
        assert_eq!(last, "do the thing");
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn last_user_turn_handles_array_content() {
        let tmp = std::env::temp_dir().join("intent_hook_transcript_a.jsonl");
        let body = "{\"type\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"read the readme\"}]}}\n\
                    {\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}\n";
        let _ = std::fs::write(&tmp, body);
        let last = last_user_turn(tmp.to_str().unwrap());
        assert_eq!(last, "read the readme");
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn last_user_turn_returns_empty_when_missing() {
        let last = last_user_turn("/nonexistent/path/here.jsonl");
        assert!(last.is_empty());
    }

    #[test]
    fn last_user_turn_returns_latest_when_multiple() {
        let tmp = std::env::temp_dir().join("intent_hook_transcript_m.jsonl");
        let body = "{\"type\":\"user\",\"message\":{\"content\":\"first request\"}}\n\
                    {\"type\":\"user\",\"message\":{\"content\":\"second request\"}}\n";
        let _ = std::fs::write(&tmp, body);
        let last = last_user_turn(tmp.to_str().unwrap());
        assert_eq!(last, "second request");
        let _ = std::fs::remove_file(tmp);
    }
}
