# Build Record — wasmtime 47 → 48: close RUSTSEC-2026-0315 and -0316 in the WASM rule sandbox

| | |
|---|---|
| **Date** | 2026-09-29 |
| **Author / session** | Claude Opus 5.5 session |
| **Branch** | main |
| **Commits** | the commit that adds this record |
| **Status** | COMPLETE |
| **Change type** | fix (security dependency) |

## 0. Intent — the owner's words, approved before design
- [x] **Problem:**
      - The weekly supply-chain audit (run 36582282966, 2026-09-29, on
        1ecb15f) failed: `cargo deny` found two advisories published this
        week against wasmtime 47.0.4, the engine of the custom-rule
        sandbox (`security-core/src/wasm_sandbox.rs`, feature
        `wasm-plugins`, on by default).
      - **RUSTSEC-2026-0315:** `call_ref` and exception `catch` can drop
        fuel accounting (exponential fuel amplification).
      - **RUSTSEC-2026-0316:** dynamic record lifting can allocate beyond
        the hostcall fuel limit.
      - Both let a hostile rule escape the sandbox's execution or memory
        budget (denial of service).
- [x] **Outcome:** wasmtime ≥ 48.0.3; the sandbox's limits still hold; the
      audit passes.
- [x] **Rejected alternative, stated to the owner:** ignoring both IDs in
      `deny.toml` silences the audit and leaves the hole open.
- [x] **Owner approved:** 2026-09-29, "Yes, upgrade with build record."

## 0b. Spec
- [x] R1 `crates/security-core/Cargo.toml`: `wasmtime = "48"`, same
      features; Cargo.lock at ≥ 48.0.3.
- [x] R2 The sandbox's guarantees hold on 48:
      - an infinite loop traps on fuel;
      - memory growth is capped;
      - an oversized result is refused;
      - a real plugin loads and runs.
      These are the existing `wasm_sandbox` tests.
- [x] R3 `cargo deny check advisories bans sources` passes (the failing
      gate).
- [x] R4 The full workspace builds and tests with the pinned toolchain
      (`cargo +1.98.1`); clippy is clean. (fmt is not: pre-existing drift in `ai-exec`,
      untouched here and not a CI step; see Skipped.)

## 1. Plan
- [x] Seen failing: `cargo deny check advisories` locally shows both IDs,
      `advisories FAILED`.
- [x] Change the requirement → `cargo update -p wasmtime` → fix any API
      breaks in `wasm_sandbox.rs` → tests → deny → clippy/fmt.
- [x] **Blast radius:** security-core's WASM sandbox, and every crate that
      links security-core (Cargo.lock). No auth, funds or exec paths.
- [x] **Risks:** a major-version API change; wasmtime 48 may raise its
      minimum Rust version.
- [x] **I will know this works when:**
      - Cargo.lock has wasmtime ≥ 48.0.3;
      - the `wasm_sandbox` tests pass;
      - `cargo deny` reads `advisories ok`;
      - the workspace gate is green.

## 2. Build
- [x] `crates/security-core/Cargo.toml`: `wasmtime = "48"` (features
      unchanged).
- [x] `cargo +1.98.1 update -p wasmtime`: 47.0.4 → **48.0.3**, and 27
      packages moved, all in the wasmtime family: 13 cranelift 0.134.4 →
      0.135.3, pulley-*, 11 wasmtime-internal-*, regalloc2 0.15.1 → 0.15.2,
      wasmprinter 0.252 → 0.254. None added or removed.
- [x] **No code change was needed.** `wasm_sandbox.rs` uses only Config
      fuel, Store with StoreLimits, `set_fuel`, Instance, typed functions
      and Memory, all unchanged in 48.

## 3. Debug
- [x] **Seen failing:** a local `cargo deny check advisories` showed
      RUSTSEC-2026-0315 and -0316 on wasmtime 47.0.4, `advisories FAILED`,
      the same as CI run 36582282966.
- [x] **My mistake, repaired within seconds:** an exploratory command
      ended with a stray `git stash -q`, which stashed the whole working
      tree. That included another session's uncommitted guard work
      (`inline_tests`: `.claude/hooks/*`, `docs/BUILD-PROCEDURE.md`).
      - `git stash pop` restored it at once; the diffstat was identical
        before and after (guard.py +172, test_guard.py +275,
        guard-config.json +11, BUILD-PROCEDURE.md ±18).
      - For those seconds the live hook ran the committed guard.
      - The pop gave those files new mtimes. The other session's fix-lock
        audit, if any, should not read them as its own edits.

## 4. Verify
- [x] `cargo deny check advisories bans sources`: **advisories ok, bans
      ok, sources ok**.
- [x] `wasm_sandbox` tests on 48: 7/7, including the infinite loop trapping
      on fuel, the oversized result refused, and a real plugin that loads
      and runs.
- [x] Workspace (`cargo +1.98.1 test --workspace`, as CI): 312 + 10 + 10 +
      7 passed, 0 failed.
- [x] `cargo +1.98.1 clippy --workspace -- -D warnings`: clean.
- [x] `cargo +1.98.1 build --release -p security-linux`: finished.

## 5. Close Out
- [x] Commit and push. Owner, 2026-09-29: "commit and push". Only the two Cargo files and this record; the other session's guard work stays out.

## Skipped items — visible, never silent
- **The verifier subagent was not run.** This is a dependency bump with no
  code change. It is proven by the failing gate turning green (`cargo
  deny`), plus the sandbox's own limit tests and the full CI gate run
  locally.
- **rustfmt drift, pre-existing:** `cargo fmt --check` flags
  `crates/ai-exec/src/main.rs` (7 hunks). That is committed code this
  change doesn't touch, and CI has no fmt step. Separately, rustfmt isn't
  installed for the pinned 1.98.1 toolchain here.
- **wasmtime 49.0.1 exists.** 48.0.3 is the smallest step that closes both
  advisories; 49 is a separate upgrade.
- **CI's `cargo deny` runs on push/PR too** (ci.yml:98); the weekly job
  found it first. A new advisory can turn a quiet repo red at any time.
  That is the gate working, not a flake.
