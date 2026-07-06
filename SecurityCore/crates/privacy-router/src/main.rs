//! `privacy-router` — thin CLI wrapper around [`security_core::local_services`].
//!
//! The real HTTP server lives in `security-core::local_services` so the
//! same code can be embedded in-process by `SecurityDaemon` (via FFI) or
//! run standalone via this binary for dev/debug.
//!
//! Routes (served by the shared listener):
//!   POST /privacy/evaluate   — outbound LLM request decision
//!   POST /intent/verify      — AI-agent pre-action gate
//!   GET  /health             — liveness
//!
//! Flags:
//!   --port <n>          default 7459
//!   --bind <host:port>  overrides --port
//!   --config <path>     default ~/.mac-security/config.toml
//!   --audit-log <path>  default off

use std::process::ExitCode;

use security_core::local_services::{run_blocking, ServiceOptions};

#[derive(Debug, Default)]
struct Args {
    port: Option<u16>,
    bind: Option<String>,
    config_path: Option<String>,
    audit_log: Option<String>,
}

fn print_usage() {
    eprintln!(
"privacy-router — local decision proxy for outbound AI API calls +
                 AI-agent intent verification.

USAGE:
    privacy-router [--bind <host:port>] [--port <n>]
                   [--config <path>] [--audit-log <path>]

ROUTES:
    POST /privacy/evaluate — outbound LLM request decision.
    POST /intent/verify    — AI-agent pre-action gate.
    GET  /health           — liveness.

FLAGS:
    --bind <addr>      Bind address (default 127.0.0.1:<port>).
    --port <n>         Bind port (default 7459). Ignored if --bind is set.
    --config <path>    Path to config.toml (default ~/.mac-security/config.toml).
    --audit-log <path> Append-only JSONL audit log (default off).
    -h, --help         Show this help.
"
    );
}

fn parse_args() -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "-h" | "--help" => { print_usage(); std::process::exit(0); }
            "--port" => {
                let v = it.next().ok_or("--port needs a value")?;
                out.port = Some(v.parse().map_err(|_| "--port must be a number")?);
            }
            "--bind" => {
                out.bind = Some(it.next().ok_or("--bind needs a value")?);
            }
            "--config" => {
                out.config_path = Some(it.next().ok_or("--config needs a value")?);
            }
            "--audit-log" => {
                out.audit_log = Some(it.next().ok_or("--audit-log needs a value")?);
            }
            _ => return Err(format!("unknown argument: {}", tok)),
        }
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

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => { eprintln!("privacy-router: {}", e); print_usage(); return ExitCode::from(2); }
    };

    let bind = args.bind.unwrap_or_else(||
        format!("127.0.0.1:{}", args.port.unwrap_or(7459)));
    let config_path = resolve_config_path(args.config_path.as_deref());

    let opts = ServiceOptions {
        bind_addr: bind.clone(),
        config_path: Some(config_path.clone()),
        audit_log_path: args.audit_log.clone(),
        security_dir: None,
    };

    eprintln!(
        "privacy-router: listening on http://{} (config {}){}",
        bind,
        config_path,
        if args.audit_log.is_some() {
            format!("  audit: {}", args.audit_log.as_deref().unwrap())
        } else {
            String::new()
        }
    );

    if let Err(e) = run_blocking(opts) {
        eprintln!("privacy-router: {}", e);
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}
