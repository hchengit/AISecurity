# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## How work gets done here — binding

[`docs/BUILD-PROCEDURE.md`](docs/BUILD-PROCEDURE.md) is the standard work for
this repo: the Five Laws, Phase 0, the per-change loop (PLAN → BUILD → DEBUG →
TEST/VERIFY → CLOSE OUT), the scrap taxonomy, the periodic drills, the incident
procedure, and the release gate. **Any session working in this repo is bound by
it**, and its own "Working with AI Assistants" section says so explicitly.

It is not in tension with the "Security practices" section at the bottom of
this file — it is the general form of it. Where they overlap, both apply; where
this repo is stricter (fail-closed, crown-jewel threat-model review), the
stricter rule wins.

The parts that bite hardest in a security-enforcement product:

- **Nothing is silent** (Law 1). A fallback that engages is an ALERT, not a
  save. This repo already fails closed on purpose — a relay that quietly
  degrades to an unguarded path is the exact failure this law names.
- **Alert on the absence of success** (Law 4). Heartbeats over error handlers:
  a detection path that stops firing looks identical to a quiet day unless
  something is watching for the silence.
- **Encode every lesson as a gate** (Law 5). This is already the house style —
  `cargo deny` accepted-advisory entries carry a reason and a tracking note,
  and the `bypass`/`threat_feeds` serial guards exist because flaky tests hid
  real bugs. Keep converting incidents into tripwires.
- **The security question, asked explicitly every time** (BUILD step 2): does
  this change touch auth, money, execution, or private data? Name the gate and
  the test that proves it holds — **and check both directions**, since a
  hardening pass that breaks a legitimate path is also a defect.
- **Clean as you go.** The old version dies in the same change; scratch and
  probe scripts die with the session, in a scratchpad, never in the repo.

**Every change carries a build record.** Copy
[`docs/build-records/TEMPLATE.md`](docs/build-records/TEMPLATE.md) to
`docs/build-records/YYYY-MM-DD-<slug>.md` when planning starts, tick boxes with
evidence as the work happens, and commit the record with the change. That
record is what makes a change auditable after the fact: the reasoning, the
receipts, and the diff arrive in one commit. Unchecked boxes are listed under
"Skipped items" or the change is not done.

**Phase 0 status, honestly:**

- CI gates hard (`.github/workflows/ci.yml` — clippy `-D warnings`,
  `cargo deny`, workspace tests, Rust↔Swift parity).
- `./scripts/smoke.sh` is the session-exit gate: tests, clippy, deny, parity,
  the agent binaries, and live probes of the `:7459` policy service. It is
  platform-aware (excludes `security-linux` on macOS, which needs libdbus) and
  bypass-aware (an active `~/.mac-security/bypass` SKIPs the deny-path
  assertion instead of failing it). `--fast` skips the slow Rust gates.
- `./scripts/install-hooks.sh` installs a pre-commit secret scan that runs with
  no external tooling, and calls `gitleaks` too when it is on PATH. It also
  refuses a new `#[allow(...)]` without a justification comment.
- **Still missing: the debt ratchet.** It needs baselines the owner agrees to,
  so it is a named open item, not an omission.
- Red-test drill: run 2026-08-19, gate confirmed RED then GREEN
  (see `docs/build-records/2026-08-19-phase0-gates.md`).

The smoke gate is GREEN, `cargo deny` included. Keep it that way — a red gate
stops the line (Law 2), it does not get papered over.

## What this is

AISecurity is a "General AI Security Layer" — a macOS menu-bar app plus a cross-platform Rust detection engine that guards AI agents (Claude Code, OpenClaw, etc.) and the host machine. All detection logic (pattern matching, scoring, redaction, policy) lives in Rust and is shared by every consumer; the Swift app and the standalone binaries are thin front-ends over it.

Note: the primary working directory (`AIS Learn`) contains only unrelated notes. The actual codebase is the `AISecurity/` working directory — do all work there.

## Architecture

Detection logic is written **once** in Rust (`SecurityCore/crates/security-core`) and consumed three ways:

1. **Swift macOS app** (`Sources/AISecurity`) — links the Rust `staticlib` through a C ABI. `build-rust.sh` compiles `security-core-ffi` into `CSecurityCore/lib/libsecurity_core_ffi.a` + a cbindgen-generated header; the `CSecurityCore` system-library target exposes it to Swift, and `RustBridge/SecurityCoreBridge.swift` wraps the C functions. Swift owns the UI, the launch-time integrity/keychain gating, file/process/TCC monitoring, and the encrypted Vault; it calls into Rust for every actual detection decision.
2. **Linux daemon** (`crates/security-linux`) — same core, native binary + TUI, no Swift.
3. **AI-agent integration binaries** (below) — link `security-core` directly as a Rust dependency.

### The daemon and the :7459 loopback service

The running app/daemon (`Core/SecurityDaemon.swift`) hosts an in-process HTTP listener on `127.0.0.1:7459` exposing `intent_verifier` and `privacy_router`. The AI-agent binaries are **thin relays** to this port so policy stays centralized in one running process:

- **`aisec-mcp`** — MCP server. Exposes `verify_intent` and `evaluate_privacy` as MCP tools (registered via `claude mcp add --scope user aisec …`). This is the `aisec` MCP server whose instructions appear in this session.
- **`intent-hook`** — Claude Code `PreToolUse` hook. Consults `intent_verifier` and returns allow/deny/ask; `install.sh` merges it into `~/.claude/settings.json`.
- **`privacy-router`** — local forward-proxy for outbound LLM API calls (`HTTPS_PROXY=http://127.0.0.1:7459`). Scans request bodies and applies allow/redact/warn/block.
- **`ai-exec`** — wraps a command in macOS `sandbox-exec` using the `[agents.*]` policy from config.

If the daemon isn't running, relays fail closed rather than making unguarded decisions.

### security-core module map

Each concern is one module in `crates/security-core/src/` with a matching config section. Detection modules: `threat_intent_parser` (7-layer scoring engine), `sensitive_data`, `prompt_injection`, `file_sanitizer`, `email_patterns`, `message_patterns`, `sender_whitelist`. Agent-facing policy: `intent_verifier`, `privacy_router`, `agent_policy`, `command_policy`, `model_verifier`/`model_vetting`, `package_vulns`, `threat_feeds`, `bypass`, `policy_audit`. Infrastructure: `config` (TOML + `MACSEC_*` env overrides), `path_resolver` (macOS vs Linux defaults), `encryption` (AES-256-GCM), `key_filter` (redaction), `wasm_sandbox` (wasmtime plugin loader), `tls_transport` (rustls log shipping), `vault`, `process_manager`, `local_services` (the :7459 handlers), `severity`, `alert`.

When adding a detection capability, add/extend the Rust module + its config section; the Swift `Modules/*.swift` file is a monitor/orchestrator that calls into it, not a second copy of the logic.

## Build & test

**Rust core** (from `SecurityCore/`):
```bash
cargo build --release -p security-core-ffi   # what build-rust.sh compiles for Swift
cargo test -p security-core                   # unit tests (~122)
cargo test --test cross_validation            # shared JSON suite validating Rust vs Swift parity
cargo test --workspace
cargo test -p security-core sensitive_data    # single module's tests
```

**Full macOS build** (from repo root):
```bash
./build-rust.sh release      # MUST run before/after any Rust change — Swift links the .a, edits to .rs are invisible until you rebuild it
swift build -c release
swift run AISecurity          # menu-bar app, no Dock icon (.accessory)
```
`.build/` (Swift) and `SecurityCore/target/` (Cargo) are build output.

**Full install** (builds everything, installs the `.app` + LaunchAgent, installs the agent binaries, wires the MCP server and PreToolUse hook):
```bash
./install.sh     # see uninstall.sh to reverse
```

## Config

Runtime config: `~/.mac-security/config.toml` (template: `config.toml.example`). One `[section]` per module. `MACSEC_*` environment variables override individual keys at highest priority (e.g. `MACSEC_MODE`, `MACSEC_SCAN_DIRS`).

`[general].mode` is `PRODUCTION | TESTING | DEVELOPMENT` and gates safety behavior — e.g. in `PRODUCTION` the default encryption passphrase is rejected, so `SECURITYCORE_PASSPHRASE` must be set for at-rest encryption of the whitelist/config secrets.

## Conventions that matter here

- **Fail closed.** Startup and the relays deliberately refuse to proceed when a security precondition can't be met (code-signature mismatch in a production install, missing Keychain master key, daemon unreachable) rather than degrading silently. Preserve this — don't add fallbacks that quietly downgrade to plaintext or unguarded paths.
- **Rust is the single source of truth** for detection. The `cross_validation` test enforces Rust/Swift parity; if you change scoring or patterns, keep that test green.
- **Custom rules are WASM.** User plugins go in `~/.mac-security/rules/` and run sandboxed in wasmtime (no fs/network), exporting `name`, `analyze`, and `alloc`. Extend `wasm_sandbox.rs` rather than adding ad-hoc rule-loading paths.

## Security practices (this is a security-enforcement product)

The hard gates are in CI (`.github/workflows/ci.yml`) — they fail the build, so they
can't quietly rot. This section is the judgment CI can't automate.

**Before a change is done, all of these pass (CI enforces them):**
- `cargo clippy --workspace -- -D warnings` — zero warnings. No new `#[allow(...)]`
  without a one-line justification comment.
- `cargo deny check advisories bans sources` — no un-accepted dependency advisories.
  Accepted ones live in `SecurityCore/deny.toml` with a reason; **prune that list as
  fixes land, and never add a new ignore without a reason and a tracking note.**
- `cargo test --workspace` passes **and is deterministic.** Never let a test depend on
  a process-global (env var, `static` DB/connection, a shared file like the real
  `~/.mac-security/bypass`) without a serial guard or explicit isolation — flaky tests
  hide real bugs (see the `bypass` and `threat_feeds` test guards for the pattern).
- Rust↔Swift parity: if you touch scoring/patterns, keep `cross_validation` green, and
  remember `./build-rust.sh` must run for Swift to see `.rs` changes.

**Crown-jewel code — changes here get a threat-model review, not just a unit test:**
the bypass/critical-secret floors (`bypass.rs`, `privacy_router.rs`), intent & command
policy (`intent_verifier.rs`, `command_policy.rs`), the MCP/PreToolUse trust boundary
(`aisec-mcp`, `intent-hook`, `local_services.rs`), and the Rust↔Swift FFI
(`security-core-ffi`). For these, ask **"how would a compromised or prompt-injected
agent evade or disable this?"** and prefer fail-closed. Enforcement inputs an agent can
control — env vars, config it can write, transcript contents — are IN scope. Many of the
worst historical findings were cross-module interaction bugs (floor asymmetry between the
daemon and the hook; the MCP relay trusting a redirectable daemon URL), so review the
trust boundary, not just the diffed lines.

**Deeper passes (not per-commit):** run the `security-audit-pipeline` skill per milestone
or before releases, and fuzz the hand-rolled parsers (`local_services.rs` HTTP,
`email_scanner`, the PyPI/manifest parser). A model finds the interesting logic bugs;
fuzzers and `cargo deny` find the complete boring set — use both.

**WASM sandbox:** runs on `wasmtime` 47 **with default features off** (only
`cranelift`, `runtime`, `std`) with fuel metering (bounds guest instructions per
call), a linear-memory cap, and a host-side result-size cap — see `wasm_sandbox.rs`.
wasmtime ships frequent security releases, so keep it current; the supply-chain gate flags
new advisories. Any new plugin entry point must preserve those three limits.

The default features are OFF deliberately, and that is a security property not
a build-time nicety: they pulled `wasm-compose` -> `im-rc` -> `bitmaps` +
`sized-chunks` (32 crates, three of them RUSTSEC-unmaintained) for a
component-model API `wasm_sandbox.rs` never calls. They also pulled `wat`, so
the shipped sandbox now cannot parse text-format modules at all — it accepts
compiled `.wasm` and nothing else. Tests compile their own fixtures through the
`wat` dev-dependency, exercising the same binary path a real plugin takes. If
you re-enable a wasmtime feature, say why in the manifest.
