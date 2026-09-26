# Build Record — the smoke gate reads its own environment, not the caller's

| | |
|---|---|
| **Date** | 2026-09-25 |
| **Author / session** | Claude Opus 4.8 (Claude Code session), owner hchengit |
| **Branch** | `fix/smoke-gate-fail-closed` |
| **Commits** | (fill at close-out) |
| **Status** | COMPLETE |
| **Change type** | fix |

## 0. Intent — the owner's words, approved before design
- [x] Problem: the 2026-09-23 record left a residual — because the gate
      trusted the caller's environment to locate the toolchain, a caller could
      make it report GREEN with zero tests executed (e.g. via a home-directory
      or PATH redirect, or a variable that tells the real toolchain to run a
      substitute). The gate's own terminal runs are truthful; the threat is a
      polluted environment inherited by the process that runs the gate.
- [x] Outcome: the gate reduces the inherited environment to a fixed allowlist
      before running anything, so no inherited variable can choose which
      toolchain runs or change what it does once running.
- [x] Who/what it affects: `scripts/smoke.sh`, a new sourced
      `scripts/lib/harden-env.sh`, and the two gate self-tests. No product code.
- [x] Open questions (answered): closing only the home-directory vector would
      leave the others open, so the design closes the class with an allowlist.
- [x] Owner approved: chat, 2026-09-25 — reviewed the choice between an
      absolute-path pin and provenance-checking, agreed neither alone suffices,
      and said "Ok, yes try isolation."

## 0b. Spec — requirements + design, policy applied up front
- [x] Requirements:
      R1. No caller-exported variable survives into the gate or its children.
      R2. The gate derives the account home from the account database, not the
          inherited HOME; PATH is the gate's own, not a prefix on the caller's.
      R3. Applies however the documented entry point is reached, before the
          first external command and before the working-directory change.
      R4. A legitimate machine still runs green (full suite, deny included).
      R5. Isolation is provable by a BENIGN test — a caller-set marker must not
          survive — with no adversarial fixtures.
- [x] Design: a sourced `scripts/lib/harden-env.sh` that (a) resolves the user
      via absolute `/usr/bin/id` and the home via `~user` (getpwnam, which
      ignores a hostile HOME), (b) unsets every exported variable except a tiny
      allowlist (HOME, USER, LOGNAME, TERM), (c) exports a fixed HOME and PATH.
      `smoke.sh` sources it FIRST — ahead of `cd` — using a builtin-only
      directory expansion (`${0%/*}`) so no PATH lookup is needed before PATH
      is trusted. Its shebang becomes `#!/bin/bash -p`, which additionally
      prevents BASH_ENV and shell functions from taking effect before line 1.
      Allowlist, not denylist: an unknown variable is dropped by default, so a
      future redirect variable is covered without being named.
      Rejected — pin the toolchain path only: leaves variables that redirect
      what the real toolchain does, and the ones the guard section consumes.
      Rejected — re-exec under a clean env guarded by a marker variable: the
      marker is itself caller-settable, so it could skip the isolation. The
      in-script allowlist has no flag to forge.
- [x] Policy applied: stricter-only, with ONE named, reversible behaviour
      change — MACSEC_* environment overrides are dropped, so the gate reflects
      on-disk `~/.mac-security/config.toml` rather than a caller's transient
      environment. For a security gate this is the safer default; reverse by
      adding MACSEC_* to the allowlist. No MACSEC_* is set on this machine, so
      no current run changes behaviour.
- [x] Flagged concerns resolved (stated, not implied):
      - A caller who runs `bash scripts/smoke.sh` bypasses the `-p` shebang and
        executes their own interpreter; that is outside what any in-script
        measure can constrain, and such a caller can fabricate a result without
        the gate anyway. The allowlist scrub still runs and still drops env
        vars in that path; only the BASH_ENV/function protection depends on -p.
      - This changes `smoke.sh`'s contract: the existing zero-suite self-test
        induced "no toolchain" by emptying HOME/PATH, which isolation now
        (correctly) ignores. That test is reworked to use the isolation
        mechanism to present a toolchain-free environment (the "no Rust
        installed" case), a benign scenario, not env trickery.

## 1. Plan
- [x] One-sentence statement: the gate scrubs its inherited environment to an
      allowlist, via a sourced helper, before it runs anything.
- [x] Blast radius: `scripts/smoke.sh`, new `scripts/lib/harden-env.sh`,
      `scripts/tests/test-smoke.sh` (reworked), new
      `scripts/tests/test-hardening.sh`. No auth/funds/exec/private-data path.
      Reversible by checkout.
- [x] Current behavior characterized: see Evidence log, BEFORE — one variable
      turned the real gate GREEN with zero real tests.
- [x] Files that change, and order: (1) write `test-hardening.sh`, SEE IT FAIL
      (no helper yet); (2) create `harden-env.sh`; (3) change `smoke.sh`;
      (4) rework `test-smoke.sh` for the changed contract.
- [x] Risks — riskiest: the scrub removing something a legitimate run needs, or
      breaking the RESULT-line-last contract. Mitigated — a full gate run must
      stay GREEN, and the self-tests must all pass.
- [x] Verification: `test-hardening.sh` proves a caller-set marker does not
      survive and PATH/HOME are the fixed values; it FAILS when the scrub is
      disabled; the full gate is GREEN; both other self-tests pass.

## 2. Build
- [x] New code meets the bar: `harden-env.sh` uses only builtins and absolute
      `/usr/bin/id`; allowlist is exact-match (verifier confirmed casing/prefix
      near-misses like `home`, `HOMEBREW`, `USERNAME` are all dropped).
- [x] Clean as you go: the old `export PATH=$HOME/.cargo/bin:$PATH` line is
      removed — `harden-env.sh` now owns the whole environment, not a prefix.
- [x] Security question — touches auth / money / exec / private data? **No
      product path**, but this IS the integrity of a security gate: the change
      removes the caller's environment as an input that could fabricate a green.
      No crown-jewel file touched (verifier confirmed shell-only diff). Both
      directions checked: a legitimate run stays GREEN (339 tests); a polluted
      environment can no longer select or redirect the toolchain.

## 3. Debug
- [x] Reproduced before fixing: the 2026-09-23 record established the residual
      (one inherited variable → green with zero tests); reconfirmed here.
- [x] Failing test written and SEEN failing: `test-hardening.sh` seen FAILING
      before the helper existed (no helper) and again against a no-op helper
      (all 7 assertions NOT OK). fix-lock engaged during the helper + smoke.sh
      work; released (owner-approved) to rework `test-smoke.sh` for the changed
      contract — a necessary test adaptation, not a weakening. The verifier
      independently confirmed the reworked test still catches the original
      defect, which is the invariant fix-lock exists to protect.
- [x] Root cause is a CLASS: **treating the caller's environment as trusted
      input to a security decision.** The prior fixes closed "verdict without a
      measurement"; this closes "the caller chooses the measurement's tools".
- [x] Swept for siblings: `smoke.sh` is the toolchain gate and is fixed.
      `ratchet.sh` is pure shell over fixed paths (no toolchain selection); a
      PATH-shadow of its `grep`/`find` is a narrower vector — noted under
      Skipped as a candidate for the same treatment, not fixed here.

## 4. Verify
- [x] Unit tests added/updated, including failure paths: `test-hardening.sh`
      (7 assertions) added; `test-smoke.sh` reworked (4 assertions). Product
      suite unchanged: 339 passed.
- [x] Watched it actually work: full gate GREEN; the direct isolation probe
      shows a caller marker `<gone>`, HOME reset to the account home despite a
      decoy HOME, PATH the fixed value.
- [x] Recovery/fallback path triggered live: the toolchain-free case reads RED
      naming zero suites; the isolation failure path (no-op helper) reads FAILED.
- [x] Regression guard proven to FAIL on the old code: `test-hardening.sh`
      fails against a no-op helper; `test-smoke.sh` fails against the pre-fix
      (ac867d0~1) gate, observing "PASS … 0 suites".
- [x] Independent verification — `verifier`: VERDICT PASS. It added an
      allowlist casing/prefix evasion check (held) and confirmed the diff is
      exactly the planned set with no crown-jewel files.
- [x] Diff matches the §1 plan: smoke.sh + new harden-env.sh + reworked
      test-smoke.sh + new test-hardening.sh + this record. Nothing else.

## 5. Close Out
- [x] Full gate green: `RESULT: 12 passed, 0 failed, 5 skipped — GREEN`.
- [x] Scrap Sweep: all `/tmp/*.sh` probes and mktemp trees removed; the tests
      clean their own `mktemp -d` via trap. `git status` shows only the five
      intended paths.
- [x] Reviewed per `REVIEW.md`: Bugs / Security / Compliance passes run;
      verifier supplied independent evidence. Findings recorded, not
      self-approved — owner decides on the residual and the ratchet follow-up.
- [x] Lesson loop: the lesson (a gate must not trust its caller's environment)
      is a gate — `test-hardening.sh` fails if the scrub is removed, and it runs
      in CI. No new CLAUDE.md line — Law 1 / "fail closed" already cover it.
- [x] Knowledge layer: the WHY lives in `harden-env.sh`'s header (including the
      one behaviour change and how to reverse it) and both test headers.
- [x] Commit message explains WHY; record committed with the change.

## Skipped items — visible, never silent
- **`ratchet.sh` environment hardening: NOT done here.** It is pure shell over
  fixed discovery paths, so it has no toolchain to redirect; the residual
  vector is a PATH-shadow of `grep`/`find`/`wc`. Sourcing `harden-env.sh` there
  too would close it, but changing the ratchet's environment also touches the
  pre-commit hook and CI job that call it, so it wants its own change. Named
  here so it is not lost.
- **Out of scope by design (stated, not silent):** a caller who runs
  `bash scripts/smoke.sh` bypasses the `-p` shebang and executes their own
  interpreter before line 1. The allowlist scrub still drops env vars in that
  path; only the BASH_ENV/function protection depends on `-p`. Such a caller
  can fabricate a result without the gate at all, so it is not the gate's
  threat to counter.

## Evidence log
```
ISOLATION PROVEN DIRECTLY (benign) — subshell with decoys, then source helper
  SOME_MARKER=<gone>
  HOME=/Users/hchome            (real account home, not the decoy /tmp/xyz)
  PATH=/Users/hchome/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin  (fixed)
  evasion: home/HOMEBREW/HOME_EXTRA/term/TERMINATOR/user/USERNAME/LOGNAME_X
           all -> <gone>   (allowlist is exact-match, held)

REGRESSION GUARDS — both fail when weakened
  test-hardening.sh <no-op helper>   -> 7/7 NOT OK, FAILED, exit 1
  test-smoke.sh <pre-fix ac867d0~1>  -> observed "PASS … 0 suites", FAILED, exit 1

SELF-TESTS + CI RUNNER
  test-hardening.sh PASS ; test-ratchet.sh PASS ; test-smoke.sh PASS
  gate-selftests runner: found 3, exit 0

FULL GATE (real toolchain)
  PASS  toolchain — cargo=/Users/hchome/.cargo/bin/cargo rustc=1.98.1
  PASS  cargo test --workspace --exclude security-linux — 8 suites, 339 passed, 0 failed
  RESULT: 12 passed, 0 failed, 5 skipped — GREEN
```
