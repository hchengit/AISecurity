# Build Record — wasmtime 47 with default features off (clears all 4 advisories)

| | |
|---|---|
| **Date** | 2026-08-19 |
| **Author / session** | Claude Fable 5 (Claude Code) |
| **Branch** | main |
| **Commits** | see close-out |
| **Status** | COMPLETE |

## 1. Plan
- [x] One-sentence statement: clear every open `cargo deny` advisory by moving
      the WASM sandbox to wasmtime 47 with default features off.
- [x] Blast radius: `wasm_sandbox.rs` — **crown-jewel code** per CLAUDE.md, so
      this gets a threat-model read, not just a green suite. Touches the
      manifest, the lockfile, and the test helper. Nothing irreversible.
- [x] Characterized before changing, and it reframed the whole problem:
      `cargo tree -i` showed all three "unmaintained" advisories are ONE chain —
      `wasmtime -> wasm-compose -> im-rc -> {bitmaps, sized-chunks}` — so four
      advisories were one dependency, not four decisions. Then
      `grep -c "component" wasm_sandbox.rs` returned **0**: the sandbox never
      calls the component-model API that drags `wasm-compose` in.
- [x] Verification defined up front: `cargo deny check advisories` reports
      `advisories ok`; all seven sandbox tests pass **including the three
      invariant tests** (fuel trap, memory cap, result cap); the FFI staticlib
      still builds, since Swift links it.

## 2. Build
- [x] `wasmtime = { version = "47", default-features = false,
      features = ["cranelift", "runtime", "std"] }`
- [x] Clean as you go: no old version left beside the new; the stale
      `Module::new parses WAT` comment removed with the behavior it described.
- [x] Security question — this IS the sandbox. Both directions checked:
      * Does it weaken anything? No. It REMOVES reachable code: 32 crates gone,
        and the shipped sandbox can no longer parse text-format wasm at all.
        The three limits are untouched and still proven by their own tests.
      * Does it break a legitimate path? The real loader reads compiled `.wasm`
        from `~/.mac-security/rules/`, which is unaffected. Only the TEST
        helper relied on wasmtime parsing WAT; it now compiles fixtures itself.

## 3. Debug — N/A (not a defect fix), but one failure was run down
- [x] Reproduced: 3 of 7 sandbox tests failed after the change with
      `LoadFailed("Compile: failed to parse WebAssembly module")`.
- [x] Read the actual error rather than assuming a wasmtime-47 regression: the
      fixtures are WAT text, and `wat` was a DEFAULT feature I had just removed.
      The library was fine; the test helper was leaning on a parser that
      production should never have had.
- [x] Class: **a test that depends on a production capability it does not need
      keeps that capability alive in the shipped binary.** Fixed by giving the
      tests their own `wat` dev-dependency, which also makes them more honest —
      they now exercise the binary `.wasm` path a real plugin takes.

## 4. Verify
- [x] Sandbox suite, all 7 green, invariants included:
      `oversized_result_is_rejected`, `infinite_loop_traps_on_fuel_not_hangs`,
      `loads_and_runs_a_real_plugin`.
- [x] Whole gate watched, not claimed: `./scripts/smoke.sh` end to end.
- [x] FFI staticlib rebuilt (`cargo build --release -p security-core-ffi`) —
      Swift links this, so a Rust-only green is not sufficient evidence.
- [x] Regression guard: the invariant tests now run against binary `.wasm`. They
      failed loudly during this change when the module could not be parsed,
      which is the proof they are wired to the real path.

## 5. Close Out
- [x] Full gate green. Smoke summary, verbatim:
      `RESULT: 9 passed, 0 failed, 5 skipped — GREEN`
- [x] Scrap Sweep: `/tmp/cargo.bak` (the manifest backup) deleted; no probe
      scripts survive the session.
- [x] Knowledge layer updated in the same change: CLAUDE.md now says wasmtime
      **47, default features off**, and records WHY, so the next person who
      "just re-enables defaults" sees the cost first.
- [x] Commit message explains WHY; record committed with the change.

## Skipped items — visible, never silent
- **`swift build` not run.** The Rust staticlib and the cbindgen header both
  rebuild clean and the FFI surface is unchanged by a dependency swap, so the
  risk is low — but "the app compiles and runs" is a claim this record does not
  make. Worth one `./build-rust.sh release && swift build -c release` before
  the next release gate.

## Evidence log
```
DEPENDENCY CHAIN (before) — four advisories, one root:
  wasmtime 43.0.2 -> wasm-compose 0.245.1 -> im-rc 15.1.0 -> bitmaps 2.1.0
                                                          -> sized-chunks 0.6.5
  grep -c "component" wasm_sandbox.rs  ->  0     (the API is never called)

AFTER:
  wasmtime v47.0.3
  wasm-compose / im-rc / bitmaps / sized-chunks — "did not match any packages"
  crates in lockfile: 552 -> 520   (32 removed)

  cargo deny check advisories  ->  advisories ok

  test wasm_sandbox::tests::plugin_loader_handles_missing_dir ... ok
  test wasm_sandbox::tests::plugin_result_serde ... ok
  test wasm_sandbox::tests::plugin_loader_discovers_wasm_files ... ok
  test wasm_sandbox::tests::invalid_wasm_fails_gracefully ... ok
  test wasm_sandbox::tests::oversized_result_is_rejected ... ok
  test wasm_sandbox::tests::loads_and_runs_a_real_plugin ... ok
  test wasm_sandbox::tests::infinite_loop_traps_on_fuel_not_hangs ... ok
  test result: ok. 7 passed; 0 failed

  RESULT: 9 passed, 0 failed, 5 skipped — GREEN
```
