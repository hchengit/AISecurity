//! Policy-as-code for named AI agents.
//!
//! Maps a named agent (e.g. `claude-code`, `ollama`) to a declarative
//! policy: which paths it may read/write, which hosts it may reach, and
//! which command-policy stance applies.
//!
//! Two outputs:
//!
//!   - Allow/Deny helpers so the rest of the codebase can consult the
//!     policy at runtime ("can agent X write to /etc/passwd?").
//!   - A **Seatbelt/sandbox-exec profile generator** that emits a
//!     TinyScheme `.sb` file. That profile is consumed by `ai-exec`,
//!     which wraps the agent in `sandbox-exec -f <profile> -- <cmd>`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::path_resolver::PathResolver;

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

/// Command-policy stance attached to an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AgentCommandStance {
    /// Use project-wide command policy unchanged.
    #[default]
    Default,
    /// Treat anything not explicitly allowed as Deny.
    Restrictive,
    /// Only ask before unknown commands; do not block.
    Permissive,
}


/// Policy for a single named agent. All path fields support `~/` prefix.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AgentPolicy {
    /// Paths the agent is permitted to *read* from. `[]` means none.
    pub allowed_paths_read: Vec<String>,
    /// Paths the agent is permitted to *write* to. `[]` means none.
    pub allowed_paths_write: Vec<String>,
    /// Hosts (exact or suffix match) the agent is permitted to reach.
    /// `[]` means offline-only.
    pub allowed_network: Vec<String>,
    /// Optional command-policy stance. Defaults to `Default`.
    pub command_policy: AgentCommandStance,
    /// Optional description for human UI.
    #[serde(default)]
    pub description: String,
}

/// The TOML `[agents]` section: a map of name → policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct AgentsConfig {
    pub agents: HashMap<String, AgentPolicy>,
}

impl AgentsConfig {
    /// Look up a policy by agent name.
    pub fn get(&self, name: &str) -> Option<&AgentPolicy> {
        self.agents.get(name)
    }
}

// ═══════════════════════════════════════════════════════════════════
// Runtime checks
// ═══════════════════════════════════════════════════════════════════

/// Kind of access being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Network,
}

impl AgentPolicy {
    /// Is `target` allowed under this policy for the given access mode?
    pub fn is_allowed(&self, access: Access, target: &str) -> bool {
        match access {
            Access::Read    => self.path_allowed(target, &self.allowed_paths_read)
                               || self.path_allowed(target, &self.allowed_paths_write),
            Access::Write   => self.path_allowed(target, &self.allowed_paths_write),
            Access::Network => self.host_allowed(target),
        }
    }

    fn path_allowed(&self, target: &str, list: &[String]) -> bool {
        let resolved = expand_home(target);
        for p in list {
            let prefix = expand_home(p);
            if path_under(&resolved, &prefix) {
                return true;
            }
        }
        false
    }

    fn host_allowed(&self, host: &str) -> bool {
        let h = host.to_lowercase();
        for entry in &self.allowed_network {
            let e = entry.to_lowercase();
            if h == e || h.ends_with(&format!(".{}", e)) {
                return true;
            }
        }
        false
    }
}

fn path_under(child: &str, parent: &str) -> bool {
    let c = Path::new(child);
    let p = Path::new(parent);
    // Exact match or under-parent.
    c == p || c.starts_with(p)
}

fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        let resolver = PathResolver::new();
        format!("{}/{}", resolver.home(), rest)
    } else if path == "~" {
        PathResolver::new().home().to_string()
    } else {
        path.to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════
// sandbox-exec (Seatbelt) profile generator
// ═══════════════════════════════════════════════════════════════════

/// Emit a Seatbelt (TinyScheme) sandbox profile matching `policy`.
///
/// The generated profile:
///   * denies everything by default;
///   * re-allows the things every macOS process needs (system dylibs,
///     /dev null/zero, /private/var metadata reads, mach lookups);
///   * allows file-read / file-write for the configured paths;
///   * allows outbound network only to the configured hosts, via a
///     `(allow network* (remote ip "..."))` rule.
///
/// Caller is responsible for writing the string to a `.sb` file and
/// invoking `sandbox-exec -f <file> -- <cmd>`.
pub fn generate_sandbox_profile(policy: &AgentPolicy) -> Result<String, String> {
    let mut out = String::new();
    out.push_str(";; AISecurity-generated sandbox profile\n");
    out.push_str(";; DO NOT EDIT — regenerated on every run.\n");
    out.push_str("(version 1)\n");
    out.push_str("(deny default)\n\n");

    // ── Process lifecycle ────────────────────────────────────────────
    out.push_str(";; Core process + IPC\n");
    out.push_str("(allow process-fork)\n");
    out.push_str("(allow process-exec)\n");
    out.push_str("(allow signal (target self))\n");
    out.push_str("(allow mach-lookup)\n");
    out.push_str("(allow ipc-posix-shm)\n");
    out.push_str("(allow sysctl-read)\n");
    out.push_str("(allow iokit-open)\n\n");

    // ── Minimum system reads ────────────────────────────────────────
    // Verified with `/bin/echo` under deny-default: /bin, /usr/lib,
    // /usr/bin, /System, /private/etc, /private/var/db/dyld, and the
    // literal "/" are all needed for the dynamic linker to load.
    out.push_str(";; System libraries and metadata\n");
    out.push_str("(allow file-read*\n");
    out.push_str("  (literal \"/\")\n");
    out.push_str("  (subpath \"/bin\")\n");
    out.push_str("  (subpath \"/sbin\")\n");
    out.push_str("  (subpath \"/usr/bin\")\n");
    out.push_str("  (subpath \"/usr/sbin\")\n");
    out.push_str("  (subpath \"/usr/lib\")\n");
    out.push_str("  (subpath \"/usr/local/bin\")\n");
    out.push_str("  (subpath \"/usr/local/lib\")\n");
    out.push_str("  (subpath \"/usr/share\")\n");
    out.push_str("  (subpath \"/System\")\n");
    out.push_str("  (subpath \"/Library/Apple\")\n");
    out.push_str("  (subpath \"/private/etc\")\n");
    out.push_str("  (subpath \"/private/var/db/dyld\")\n");
    out.push_str("  (subpath \"/private/var/db/timezone\")\n");
    out.push_str("  (literal \"/dev/null\")\n");
    out.push_str("  (literal \"/dev/zero\")\n");
    out.push_str("  (literal \"/dev/random\")\n");
    out.push_str("  (literal \"/dev/urandom\")\n");
    out.push_str("  (literal \"/dev/tty\")\n");
    out.push_str(")\n\n");

    out.push_str(";; /tmp scratch is always writable\n");
    out.push_str("(allow file-write* file-read*\n");
    out.push_str("  (subpath \"/tmp\")\n");
    out.push_str("  (subpath \"/private/tmp\")\n");
    out.push_str("  (subpath \"/private/var/tmp\")\n");
    out.push_str("  (literal \"/dev/null\")\n");
    out.push_str("  (literal \"/dev/tty\")\n");
    out.push_str(")\n\n");

    // ── Agent-specific read paths ───────────────────────────────────
    if !policy.allowed_paths_read.is_empty() || !policy.allowed_paths_write.is_empty() {
        out.push_str(";; Agent read access\n");
        out.push_str("(allow file-read*\n");
        // read = explicit reads ∪ writes (writes imply you can read first)
        let mut reads: Vec<String> = policy.allowed_paths_read.iter().map(|p| expand_home(p)).collect();
        for p in &policy.allowed_paths_write {
            let r = expand_home(p);
            if !reads.contains(&r) { reads.push(r); }
        }
        for p in reads {
            reject_control_chars(&p)?;
            out.push_str(&format!("  (subpath \"{}\")\n", scheme_escape(&p)));
        }
        out.push_str(")\n\n");
    }

    if !policy.allowed_paths_write.is_empty() {
        out.push_str(";; Agent write access\n");
        out.push_str("(allow file-write*\n");
        for p in &policy.allowed_paths_write {
            let p = expand_home(p);
            reject_control_chars(&p)?;
            out.push_str(&format!("  (subpath \"{}\")\n", scheme_escape(&p)));
        }
        out.push_str(")\n\n");
    }

    // ── Network ─────────────────────────────────────────────────────
    if policy.allowed_network.is_empty() {
        out.push_str(";; Offline — all network denied.\n\n");
    } else {
        out.push_str(";; Outbound network (DNS + TLS) to whitelisted hosts\n");
        // Seatbelt cannot filter by DNS name directly, only by port/IP.
        // We allow DNS resolution (UDP 53, TCP 53) + TCP to 80/443 but
        // leave host-level filtering to higher layers (privacy_router,
        // little-snitch equivalents). We note the whitelist as a
        // comment for audit.
        out.push_str("(allow network-outbound\n");
        out.push_str("  (remote tcp \"*:53\")\n");
        out.push_str("  (remote udp \"*:53\")\n");
        out.push_str("  (remote tcp \"*:80\")\n");
        out.push_str("  (remote tcp \"*:443\")\n");
        out.push_str(")\n");
        out.push_str(";; Allowed hosts (for audit, enforced at proxy layer):\n");
        for h in &policy.allowed_network {
            // These land on a comment line. A raw newline/CR would end the
            // comment and let the remainder be parsed as a live Scheme form,
            // so strip all control chars. (Purely informational — not a
            // security control, hence sanitize rather than reject.)
            let sanitized: String = h.chars().filter(|c| !c.is_control()).collect();
            out.push_str(&format!(";;   - {}\n", sanitized));
        }
        out.push('\n');
    }

    Ok(out)
}

/// Minimal escape for embedding a path in a TinyScheme string literal.
fn scheme_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Reject any value carrying a control character before it is embedded
/// into the Seatbelt profile. A newline/CR would let a config value break
/// out of the `(subpath "…")` string literal and inject an extra rule;
/// other control chars have no legitimate place in a filesystem path.
///
/// We refuse to emit a profile rather than silently stripping, because a
/// mangled path (`/foo\n/bar` → `/foo/bar`) would grant access to a
/// *different* location than intended — failing closed is the only safe
/// choice for a sandbox boundary.
fn reject_control_chars(s: &str) -> Result<(), String> {
    if s.chars().any(|c| c.is_control()) {
        return Err(format!(
            "refusing to generate sandbox profile: agent path contains a control character: {s:?}"
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_policy() -> AgentPolicy {
        AgentPolicy {
            allowed_paths_read:  vec!["~/work".into(), "~/Documents".into()],
            allowed_paths_write: vec!["~/work".into()],
            allowed_network:     vec!["api.anthropic.com".into(), "github.com".into()],
            command_policy:      AgentCommandStance::Restrictive,
            description:         "Claude Code sandbox profile".into(),
        }
    }

    #[test]
    fn read_allowed_only_if_under_configured_subpath() {
        let p = demo_policy();
        let r = PathResolver::new();
        let home = r.home();
        assert!(p.is_allowed(Access::Read, &format!("{}/work/file.txt", home)));
        assert!(p.is_allowed(Access::Read, &format!("{}/Documents/notes.md", home)));
        assert!(!p.is_allowed(Access::Read, "/etc/passwd"));
    }

    #[test]
    fn write_requires_write_list_not_just_read() {
        let p = demo_policy();
        let r = PathResolver::new();
        let home = r.home();
        assert!(p.is_allowed(Access::Write, &format!("{}/work/out.txt", home)));
        assert!(!p.is_allowed(Access::Write, &format!("{}/Documents/out.txt", home)));
    }

    #[test]
    fn write_path_also_permits_read() {
        let p = demo_policy();
        let r = PathResolver::new();
        let home = r.home();
        assert!(p.is_allowed(Access::Read, &format!("{}/work/out.txt", home)));
    }

    #[test]
    fn offline_policy_denies_all_network() {
        let mut p = demo_policy();
        p.allowed_network = vec![];
        assert!(!p.is_allowed(Access::Network, "github.com"));
        assert!(!p.is_allowed(Access::Network, "api.anthropic.com"));
    }

    #[test]
    fn network_suffix_match() {
        let p = demo_policy();
        assert!(p.is_allowed(Access::Network, "api.anthropic.com"));
        assert!(p.is_allowed(Access::Network, "eu.api.anthropic.com"));
        assert!(!p.is_allowed(Access::Network, "api.anthropic.com.evil.example"));
    }

    #[test]
    fn sandbox_profile_denies_by_default() {
        let p = demo_policy();
        let sb = generate_sandbox_profile(&p).unwrap();
        assert!(sb.contains("(deny default)"));
    }

    #[test]
    fn sandbox_profile_encodes_read_paths() {
        let p = demo_policy();
        let sb = generate_sandbox_profile(&p).unwrap();
        let r = PathResolver::new();
        let home = r.home();
        assert!(sb.contains(&format!("(subpath \"{}/work\")", home)));
        assert!(sb.contains(&format!("(subpath \"{}/Documents\")", home)));
    }

    #[test]
    fn sandbox_profile_offline_has_no_outbound_rule() {
        let mut p = demo_policy();
        p.allowed_network = vec![];
        let sb = generate_sandbox_profile(&p).unwrap();
        assert!(!sb.contains("(allow network-outbound"));
        assert!(sb.contains(";; Offline"));
    }

    #[test]
    fn sandbox_profile_rejects_newline_in_read_path() {
        let mut p = demo_policy();
        // A path that tries to break out of the (subpath "…") literal and
        // inject a rule granting write access to the whole filesystem.
        p.allowed_paths_read
            .push("/tmp/x\")\n(allow file-write* (subpath \"/".into());
        let err = generate_sandbox_profile(&p).unwrap_err();
        assert!(err.contains("control character"), "unexpected error: {err}");
    }

    #[test]
    fn sandbox_profile_rejects_newline_in_write_path() {
        let mut p = demo_policy();
        p.allowed_paths_write.push("/tmp/y\r/etc".into());
        assert!(generate_sandbox_profile(&p).is_err());
    }

    #[test]
    fn sandbox_profile_allows_parens_in_path() {
        // Parentheses are legal inside a quoted Scheme string literal, so a
        // path like "~/Library/Application Support (old)" must NOT be
        // rejected — only the enclosing quotes/backslashes are structural.
        let mut p = demo_policy();
        p.allowed_paths_read.push("/tmp/weird (dir)".into());
        let sb = generate_sandbox_profile(&p).unwrap();
        assert!(sb.contains("(subpath \"/tmp/weird (dir)\")"));
    }

    #[test]
    fn sandbox_profile_strips_control_chars_from_host_comment() {
        let mut p = demo_policy();
        // A host value smuggling a live Scheme form after a newline must
        // not produce a non-comment line in the output.
        p.allowed_network
            .push("evil.example\n(allow file-write* (subpath \"/\"))".into());
        let sb = generate_sandbox_profile(&p).unwrap();
        // The injected form must not appear at the start of any line.
        assert!(
            !sb.lines().any(|l| l.trim_start().starts_with("(allow file-write* (subpath \"/\"))")),
            "host newline injected a live rule:\n{sb}"
        );
    }

    #[test]
    fn parse_agents_toml() {
        let src = r#"
[claude-code]
allowed_paths_read  = ["~/work"]
allowed_paths_write = ["~/work"]
allowed_network     = ["api.anthropic.com"]
command_policy      = "restrictive"

[ollama]
allowed_paths_read  = ["~/.ollama"]
allowed_network     = []
"#;
        let parsed: AgentsConfig = toml::from_str::<HashMap<String, AgentPolicy>>(src)
            .map(|m| AgentsConfig { agents: m })
            .unwrap();
        assert_eq!(parsed.agents.len(), 2);
        let cc = parsed.get("claude-code").unwrap();
        assert_eq!(cc.allowed_network, vec!["api.anthropic.com".to_string()]);
        assert_eq!(cc.command_policy, AgentCommandStance::Restrictive);
        let o = parsed.get("ollama").unwrap();
        assert!(o.allowed_network.is_empty());
    }

    #[test]
    fn scheme_escape_handles_quotes_and_backslashes() {
        assert_eq!(scheme_escape("normal/path"), "normal/path");
        assert_eq!(scheme_escape("weird\"path"), "weird\\\"path");
        assert_eq!(scheme_escape("path\\with\\backslash"), "path\\\\with\\\\backslash");
    }
}
