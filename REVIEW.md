# Review instructions

How any review of a change to this repo is run: `/code-review`, the
`verifier` subagent's report, a human reviewer, a PR bot. Referenced from the
build record's Close Out and from `docs/BUILD-PROCEDURE.md`. The CLAUDE.md
section "Security practices" is the judgement this review applies.

## Passes (run all three; tag every finding with its pass)

- **Bugs**: logic errors, edge cases, regressions, non-deterministic tests
  (process-global env, shared files, statics without a serial guard).
- **Security**: this product *is* a security boundary. For every change ask
  **"how would a compromised or prompt-injected agent evade or disable
  this?"** Inputs an agent controls (env vars, config it can write,
  transcript contents) are in scope. Review the trust boundary, not just the
  diffed lines: floor asymmetry between the daemon and the hook, relays
  trusting a redirectable URL, a fallback that downgrades to unguarded.
- **Compliance**: does the diff match the build record's Intent, Spec and
  Plan? Plus the rules only this repo has:
  - **Fail closed**. A new path that degrades silently is **Important**.
  - **Rust is the single source of truth for detection**. Detection logic
    added in Swift is **Important**. `cross_validation` stays green.
  - WASM entry points keep all three limits (fuel, memory cap, result cap).
  - No new `#[allow(...)]` or `deny.toml` ignore without a reason.

## What "Important" means here

Reserve **Important** for findings that let an agent bypass, disable, or
downgrade a control; leak a secret or vault contents; break fail-closed; or
diverge from the approved intent. Changes to crown-jewel code (`bypass.rs`,
`privacy_router.rs`, `intent_verifier.rs`, `command_policy.rs`,
`local_services.rs`, `aisec-mcp`, `intent-hook`, `security-core-ffi`) always
get a written threat-model note in the build record, finding or not.

## Cap the nits

At most five nits per review; summarise the rest as a count.

## Do not report

Build output (`.build/`, `SecurityCore/target/`, `CSecurityCore/lib/`),
`security_core.h` (cbindgen-generated), and what CI already enforces
(`cargo test`, clippy `-D warnings`, `cargo deny`, the guard tests).

## Separation of duties

The session that wrote a change does not approve it. Review findings are
evidence in the build record; the owner decides.
