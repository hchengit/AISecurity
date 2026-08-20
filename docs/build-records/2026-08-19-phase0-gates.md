# Build Record — Phase 0 gates: smoke script + pre-commit secret scan

| | |
|---|---|
| **Date** | 2026-08-19 |
| **Author / session** | Claude Fable 5 (Claude Code) |
| **Branch** | main |
| **Commits** | see close-out |
| **Status** | COMPLETE (with findings raised, not fixed here) |

## 1. Plan
- [x] One-sentence statement: close the three open Phase 0 gaps named in
      CLAUDE.md — a smoke script, pre-commit hooks with a secret scan, and the
      red-test drill.
- [x] Blast radius: no product code. Adds `scripts/smoke.sh`,
      `scripts/hooks/pre-commit`, `scripts/install-hooks.sh`,
      `.pre-commit-config.yaml`. Sets `core.hooksPath`. Nothing irreversible;
      the hook is bypassable with `--no-verify` by design.
- [x] Current behavior characterized first: CI exists and gates hard
      (clippy `-D warnings`, `cargo deny`, workspace tests, parity). No smoke
      script, no hooks, no secret scan, no ratchet — confirmed by inspection
      before writing anything.
- [x] Verification defined up front: the smoke script must go RED on a planted
      failure and GREEN on removal; the hook must actually refuse a commit
      containing a planted secret. Both proven below, not asserted.

## 2. Build
- [x] Self-contained hook rather than a `.pre-commit-config.yaml` alone —
      neither `gitleaks` nor `pre-commit` is installed on this machine, and a
      config pointing at an absent binary is an inert gate. The config ships
      too, for when the binary exists; the hook calls `gitleaks` if present.
- [x] Clean as you go: every drill artifact removed in the same session
      (`leak_TEMP.py`, `secret_TEMP.pem`, `bad_TEMP.py`, `allow_TEMP.rs`,
      `tests/test_red_drill_TEMP.py`). `git status` verified clean of them.
- [x] Security question: this change IS a security gate. It touches no auth,
      money, exec or private-data path at runtime. It adds one: staged content
      is scanned for secret-shaped strings before it can enter history.

## 3. Debug — N/A as a defect fix, but two false readings were run down
- [x] Reproduced before concluding, twice, and BOTH were the tool, not the system:
      1. `intent_verifier ALLOWED 'rm -rf /'` — read the actual response
         rather than the symptom: `{"_bypass":true,"matched_rule":"bypass"}`.
         The bypass file is present and the daemon is loud about it. The
         assertion was wrong, not the fail-closed contract. Smoke is now
         bypass-aware and asserts the *declaration* instead.
      2. `cargo test/clippy --workspace` failing — `libdbus-1-dev` is absent on
         macOS, which only the Linux daemon crate needs. CI covers it on
         ubuntu. Smoke now excludes `security-linux` on Darwin and says so.
- [x] Root cause class named: **a gate that reports a defect that isn't one
      gets ignored, and then it guards nothing.** Both fixes make the gate
      report what is true on the platform it is running on.
- [x] Swept for siblings: found a third instance in my own script — the test
      gate used `tail -3` on `test result:` lines and reported "7 passed" for a
      run of 339 across 8 suites. That is exactly how a whole crate silently
      not running would still look green. Now aggregated across all suites.

## 4. Verify
- [x] Red-test drill (Iceman, same script shape): planted a failing test ->
      `RESULT: RED`, exit 1; removed it -> `RESULT: GREEN`, exit 0.
- [x] Hook proven to refuse, three ways: AWS-shaped key, private-key header,
      and (AISecurity) a new `#[allow(...)]` with no justification comment.
      Each printed BLOCKED and the commit did not happen.
- [x] Watched it work against the RUNNING system: daemon on 127.0.0.1:7459
      probed live — `/health`, `/intent/verify` (both deny-path and the
      benign-path mirror), `/privacy/evaluate`.
- [x] Regression guard proven to fail on the old behavior: the smoke script's
      own `tail -3` bug was caught by comparing its summary against
      `cargo test -p security-core` directly (312 tests) — the aggregate
      version reports 339 and the old one reported 7.

## 5. Close Out
- [x] Full gate run. Smoke summary, verbatim:
      `RESULT: 8 passed, 1 failed, 5 skipped — RED`
      The single failure is `cargo deny` advisories — PRE-EXISTING, surfaced by
      this gate, and raised below rather than silently fixed.
- [x] Scrap Sweep done: all TEMP drill files deleted, `git status` clean of them.
- [x] Knowledge layer updated in the same change: CLAUDE.md's "Phase 0 status"
      paragraph is rewritten to match reality.
- [x] Commit message explains WHY; record committed with the change.

## Skipped items — visible, never silent
- **Debt ratchet: NOT built.** Phase 0 names it and it does not exist here.
  It needs baselines the owner should agree to (which counters, what floors),
  so it is a separate change, not a silent omission.
- **Agent binaries not probed live** — `aisec-mcp`, `intent-hook`,
  `privacy-router`, `ai-exec` are not on PATH on this machine (`./install.sh`
  has not been run). Smoke SKIPs them with that reason rather than passing.
- **`--no-api` / `--fast` paths exist** so the gate stays runnable when the
  daemon is down; a fast run is not a full run and the RESULT line says which.

## Evidence log
```
RED-TEST DRILL (smoke gate, Iceman — same script shape)
  FAIL  pytest — 1 failed, 1484 passed        RESULT: 4 passed, 1 failed — RED   exit 1
  PASS  pytest — 1484 passed                  RESULT: 5 passed, 0 failed — GREEN exit 0

PRE-COMMIT HOOK DRILLS (both repos)
  BLOCKED: possible secret in leak_TEMP.py            2:AKIA…EXAMPLE  (canonical AWS doc key, redacted here)
  BLOCKED: possible secret in secret_TEMP.pem         2:-----BEGIN RSA PRIVATE …  (header only, redacted here)
  BLOCKED: syntax error in bad_TEMP.py                SyntaxError: invalid syntax
  BLOCKED: new #[allow(...)] in allow_TEMP.rs without a one-line justification

AISECURITY FULL SMOKE (after fixes)
  PASS  cargo test --workspace --exclude security-linux — 8 suites, 339 passed, 0 failed
  PASS  clippy --workspace --exclude security-linux -D warnings
  FAIL  cargo deny — advisories FAILED, bans ok, sources ok
  PASS  cross_validation (Rust/Swift parity)
  PASS  GET /health -> ok:true
  PASS  POST /intent/verify returns a decision
  SKIP  deny-path assertion — bypass is ACTIVE and the decision says so
  PASS  intent_verifier permits 'git status'
  PASS  POST /privacy/evaluate returns an action
  PASS  privacy_router did not pass the secret through untouched
  RESULT: 8 passed, 1 failed, 5 skipped — RED

FALSE READING RUN DOWN (not a defect):
  {"_bypass":true,"decision":"allow","matched_rule":"bypass",
   "reason":"bypass active (bypass:file=/Users/hchome/.mac-security/bypass)"}
```

## Findings raised for a separate change
`cargo deny check advisories` is RED with four entries. **Not fixed here** —
a dependency change is its own concern with its own record:

| advisory | crate | status |
|---|---|---|
| RUSTSEC-2026-0258 (vulnerability) | h2 0.4.13 | **fixed** — `cargo update -p h2` -> 0.4.17, verified green |
| "Stores can mix up type indices between engines" (vulnerability) | wasmtime 43.0.2 | **OPEN** — no semver-compatible fix; needs a major bump (43 -> 44+). CLAUDE.md flags the WASM sandbox's fuel metering, linear-memory cap and result-size cap as invariants any bump must preserve. |
| RUSTSEC-2026-0247 (unmaintained) | bitmaps | OPEN — decide: swap, or accept in `deny.toml` with a reason + tracking note |
| RUSTSEC-2026-0250 (unmaintained) | im-rc | OPEN — same |
| RUSTSEC-2026-0252 (unmaintained) | sized-chunks | OPEN — same |
