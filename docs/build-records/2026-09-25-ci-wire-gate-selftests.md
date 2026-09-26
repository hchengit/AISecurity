# Build Record — the gate self-tests run in CI, not only by hand

| | |
|---|---|
| **Date** | 2026-09-25 |
| **Author / session** | Claude Opus 4.8 (Claude Code session), owner hchengit |
| **Branch** | `fix/smoke-gate-fail-closed` |
| **Commits** | (fill at close-out) |
| **Status** | COMPLETE |
| **Change type** | ops |

## 0. Intent — the owner's words, approved before design
- [x] Problem: the two gate self-tests (`test-smoke.sh` zero-suite guard,
      `test-ratchet.sh` empty-discovery guard) only run when invoked by hand.
      A guard that stands watch only when someone remembers is not standing
      watch. Both prior records list this CI wiring under Skipped.
- [x] Outcome: both self-tests run automatically in CI on every change that
      touches `scripts/**`, and a regression in either fails the build.
- [x] Who/what it affects: `.github/workflows/ci.yml` (a new job) and the
      location of `scripts/test-smoke.sh`. No product code.
- [x] Open questions: none.
- [x] Owner approved: chat, 2026-09-25, "Go ahead with 2 and then 1."

## 0b. Spec — requirements + design, policy applied up front
- [x] Requirements:
      R1. Both self-tests run in CI on a `scripts/**` change.
      R2. A regression in either fails the CI job (non-zero exit).
      R3. The job needs no Rust/Swift toolchain — the self-tests are pure shell
          over a throwaway tree, so the job is seconds and needs no cache.
      R4. The self-tests live together, discoverable as "the gate self-tests".
- [x] Design: consolidate `scripts/test-smoke.sh` → `scripts/tests/` (next to
      `test-ratchet.sh`), then add a `gate-selftests` job to `ci.yml` that runs
      every `scripts/tests/*.sh`. `ci.yml` already triggers on `scripts/**`, so
      no trigger change is needed.
      Rejected — put the job in `claude-guard.yml`: that workflow triggers only
      on `.claude/**`, so it would NOT fire when `scripts/smoke.sh` or
      `scripts/ratchet.sh` change — exactly the changes these tests guard. The
      original `test-smoke.sh` header suggested that workflow; this record
      corrects that reasoning.
      Rejected — a bash loop hard-coding two paths: globbing `scripts/tests/*.sh`
      means a third self-test is picked up with no CI edit.
- [x] Policy applied: `.github/workflows/*` is a guard-protected path — the
      owner approves the workflow edit. No behaviour-changing product default.
- [x] Flagged concerns resolved: moving `test-smoke.sh` changes the path named
      in the 2026-09-23 record; that record is point-in-time and stays as-is.
      The move updates the script's own `cd` depth and usage lines.

## 1. Plan
- [x] One-sentence statement: move `test-smoke.sh` beside `test-ratchet.sh` and
      add a toolchain-free CI job that runs both.
- [x] Blast radius: `.github/workflows/ci.yml`, `scripts/test-smoke.sh` (moved).
      No auth / funds / exec / private-data path. Reversible by checkout.
- [x] Current behavior characterized: both self-tests pass standalone today;
      neither runs in CI (grep of both workflows finds no reference). Evidence.
- [x] Files that change, and order: (1) `git mv scripts/test-smoke.sh
      scripts/tests/`; (2) fix its `cd` depth + usage/CI comments; (3) add the
      `gate-selftests` job to `ci.yml`.
- [x] Risks: the CI job passing vacuously (globbing zero files, or a test
      exiting 0 without running). Mitigated — the job asserts it found at least
      one test and uses a strict runner that fails on any non-zero.
- [x] Verification: run both self-tests from the new location; lint the CI job
      with the same runner logic locally; confirm the job would have caught
      each shipped defect (both tests fail on their pre-fix targets).

## 2. Build
- [x] New code meets the bar: the CI job globs `scripts/tests/*.sh`, fails on
      any non-zero, and errors if the glob is empty (no vacuous pass). No
      hard-coded test list — a third self-test is picked up automatically.
- [x] Clean as you go: `test-smoke.sh` moved (not copied) so there is one
      home for the gate self-tests; its `cd` depth and usage/CI comments were
      corrected for the new location. While there, a pre-existing false-FAIL
      surfaced by the verifier was fixed — see §4 deviation.
- [x] Security question — touches auth / money / exec / private data? **No.**
      CI wiring plus a test move. `.github/workflows/*` is guard-protected, so
      the workflow edit was owner-approved. No crown-jewel or product code.

## 3. Debug — N/A (CI wiring, not a defect fix)
- [x] N/A: the defects were fixed in the two prior commits; this makes their
      guards run automatically. One incidental cleanup is logged in §4.

## 4. Verify
- [x] Unit tests added/updated: no new test; the two existing self-tests now
      run in CI. Both pass from the new location.
- [x] Watched it actually work: ran the job's exact `run:` block locally —
      found 2 tests, both PASS, job exit 0. YAML parses; jobs now include
      `gate-selftests`.
- [x] Recovery/fallback path triggered live: drove the runner's empty-glob
      guard in a temp dir with no tests — it exits non-zero with the
      "no gate self-tests found" error, rather than passing vacuously.
- [x] Regression guard proven to FAIL on the old code: both self-tests fail
      against their pre-fix targets (smoke via an absolute path after the fix
      below; ratchet directly), so the job would go RED on either regression.
- [x] Independent verification — `verifier` subagent: VERDICT PASS. It proved
      the empty-glob guard, the strict runner, the moved `cd` depth, and both
      regression catches. It surfaced one real issue (next line).
- [x] Diff matches the §1 plan; deviations explained here:
      **Deviation (in-scope cleanup): `test-smoke.sh` ran its target as
      `"./$TARGET"`, which mangles an ABSOLUTE A/B-drill argument into
      `.//abs/path` and silently fails to find it — a FALSE FAIL, the same
      "verdict without running the thing" class this whole series eliminates.**
      It is pre-existing (from the 2026-09-23 commit, untouched by the move)
      and does not affect CI, which uses the default relative target. But it
      lives in the file this change relocates, and it broke the A/B drill the
      series depends on, so it was fixed here: invoke `bash "$TARGET"` and
      guard with `-f` not `-x`. Proven: an absolute-path pre-fix target now
      genuinely drives the gate and reports FAILED, where before it reported
      "no cargo test line at all".

## 5. Close Out
- [x] Full gate green: `RESULT: 12 passed, 0 failed, 5 skipped — GREEN`.
- [x] Scrap Sweep: all `/tmp/old-*.sh` and mktemp trees removed; `git status`
      shows only the intended paths.
- [x] Reviewed per `REVIEW.md`: Bugs / Security / Compliance passes run; the
      verifier supplied independent evidence. Findings recorded, not
      self-approved — owner decides.
- [x] Lesson loop: the lesson (a guard that runs only by hand is not standing
      watch) is now itself a CI job. The false-FAIL fix keeps the A/B-drill
      mechanism honest. No new CLAUDE.md line — Phase 0 already documents CI as
      the hard gate.
- [x] Knowledge layer: the WHY lives in the `gate-selftests` job comment and
      the corrected `test-smoke.sh` header/invocation comment.
- [x] Commit message explains WHY; record committed with the change.

## Skipped items — visible, never silent
- (none — the CI wiring named in both prior records' Skipped sections is done
  here for both self-tests.)

## Evidence log
```
BEFORE — neither self-test runs in CI
  grep -l test-smoke   .github/workflows/*  -> (no match)
  grep -l test-ratchet .github/workflows/*  -> (no match)
  both pass standalone: test-smoke.sh rc=0, test-ratchet.sh rc=0

AFTER — ci.yml jobs
  ['test-linux', 'clippy', 'supply-chain', 'ratchet', 'gate-selftests']

JOB RUNNER LOGIC, run locally
  found 2: scripts/tests/test-ratchet.sh scripts/tests/test-smoke.sh
  both PASS -> job exit 0
  empty scripts/tests/ -> "::error::no gate self-tests found ..." exit 1
  a test exiting 3     -> "::error::<t> FAILED" exit 1   (fails on any non-zero)

REGRESSION CATCH — both self-tests fail on their pre-fix gates
  test-smoke.sh <pre-fix smoke, absolute path> -> observed "0 suites, 0 passed", RESULT FAILED, rc=1
  test-ratchet.sh <pre-fix ratchet>            -> 6/6 NOT OK, RESULT FAILED, rc=1

FALSE-FAIL FIX (test-smoke.sh A/B arg)
  before: absolute-path target -> "<no cargo test line at all>" (never ran)
  after : absolute-path target -> drives the gate, observes its real output

FULL GATE
  RESULT: 12 passed, 0 failed, 5 skipped — GREEN
```
