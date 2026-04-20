//! `ai-exec` — run an AI agent inside a sandbox-exec profile derived from
//! the user's `[agents.<name>]` policy in `~/.mac-security/config.toml`.
//!
//! Usage:
//!     ai-exec --agent claude-code -- claude --help
//!     ai-exec --agent ollama --dry-run -- ollama run llama3
//!
//! Flags:
//!   --agent <name>   required — which policy to load
//!   --config <path>  optional — default is ~/.mac-security/config.toml
//!   --dry-run        print the generated sandbox profile and exit 0
//!   --print-profile  alias of --dry-run
//!
//! Everything after `--` is the command to launch. On macOS it is wrapped
//! in `sandbox-exec -f <generated.sb> -- <argv...>`. On non-macOS the
//! wrapper falls back to a plain `exec` with a visible warning — the
//! path/network checks from `AgentPolicy` still apply at higher layers.

use std::process::{Command, ExitCode};

use security_core::agent_policy::{generate_sandbox_profile, AgentPolicy};
use security_core::config::SecurityConfig;

#[derive(Debug, Default)]
struct Args {
    agent: Option<String>,
    config_path: Option<String>,
    dry_run: bool,
    argv: Vec<String>,
}

fn print_usage() {
    eprintln!(
"ai-exec — run an AI agent inside a sandbox-exec profile.

USAGE:
    ai-exec --agent <name> [--config <path>] [--dry-run] -- <cmd> [args...]

FLAGS:
    --agent <name>    Load [agents.<name>] from config.toml (required)
    --config <path>   Path to config.toml (default: ~/.mac-security/config.toml)
    --dry-run         Print the sandbox profile and exit without exec
    --print-profile   Alias of --dry-run
    -h, --help        Show this help

EXAMPLES:
    ai-exec --agent claude-code -- claude --help
    ai-exec --agent ollama --dry-run -- ollama run llama3
"
    );
}

fn parse_args() -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = std::env::args().skip(1).peekable();
    let mut seen_dashdash = false;

    while let Some(tok) = it.next() {
        if seen_dashdash {
            out.argv.push(tok);
            continue;
        }
        match tok.as_str() {
            "--" => { seen_dashdash = true; }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "--agent" => {
                out.agent = Some(it.next().ok_or("--agent needs a value")?.to_string());
            }
            "--config" => {
                out.config_path = Some(it.next().ok_or("--config needs a value")?.to_string());
            }
            "--dry-run" | "--print-profile" => { out.dry_run = true; }
            _ => return Err(format!("unknown argument: {}", tok)),
        }
    }

    if out.agent.is_none() {
        return Err("--agent is required".into());
    }
    if !seen_dashdash && !out.dry_run {
        return Err("expected `--` followed by the command to run".into());
    }
    if seen_dashdash && out.argv.is_empty() && !out.dry_run {
        return Err("no command provided after `--`".into());
    }
    Ok(out)
}

fn resolve_config_path(explicit: Option<&str>) -> String {
    if let Some(p) = explicit { return p.to_string(); }
    match std::env::var("HOME") {
        Ok(home) => format!("{}/.mac-security/config.toml", home),
        Err(_) => "/tmp/.mac-security/config.toml".to_string(),
    }
}

fn load_policy(config_path: &str, agent_name: &str) -> Result<AgentPolicy, String> {
    let cfg = SecurityConfig::load_or_default(config_path);
    cfg.agents.get(agent_name)
        .cloned()
        .ok_or_else(|| format!(
            "no [agents.{}] section in {}. Add one per config.toml.example.",
            agent_name, config_path
        ))
}

fn write_profile(profile: &str, agent_name: &str) -> Result<String, String> {
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let pid = std::process::id();
    let path = format!("{}/ai-exec-{}-{}.sb", tmp.trim_end_matches('/'), agent_name, pid);
    std::fs::write(&path, profile).map_err(|e| format!("write profile {}: {}", path, e))?;
    Ok(path)
}

#[cfg(target_os = "macos")]
fn exec_sandboxed(profile_path: &str, argv: &[String]) -> std::io::Error {
    // exec replaces our process; use `-c` not at all — sandbox-exec runs argv directly.
    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-f").arg(profile_path).arg("--");
    cmd.args(argv);
    use std::os::unix::process::CommandExt;
    cmd.exec()
}

#[cfg(not(target_os = "macos"))]
fn exec_sandboxed(_profile_path: &str, argv: &[String]) -> std::io::Error {
    eprintln!("ai-exec: sandbox-exec is macOS-only; running unsandboxed.");
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        return cmd.exec();
    }
    #[cfg(not(unix))]
    {
        let _ = cmd.status();
        std::io::Error::new(std::io::ErrorKind::Unsupported, "exec unsupported on this platform")
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ai-exec: {}", e);
            print_usage();
            return ExitCode::from(2);
        }
    };

    let config_path = resolve_config_path(args.config_path.as_deref());
    let agent_name = args.agent.as_deref().unwrap();

    let policy = match load_policy(&config_path, agent_name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ai-exec: {}", e);
            return ExitCode::from(3);
        }
    };

    let profile = generate_sandbox_profile(&policy);

    if args.dry_run {
        print!("{}", profile);
        return ExitCode::SUCCESS;
    }

    let profile_path = match write_profile(&profile, agent_name) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ai-exec: {}", e);
            return ExitCode::from(4);
        }
    };

    eprintln!("ai-exec: launching `{}` under profile {}", args.argv.join(" "), profile_path);
    let err = exec_sandboxed(&profile_path, &args.argv);
    // If we reach here, exec failed.
    eprintln!("ai-exec: exec failed: {}", err);
    ExitCode::from(5)
}
