# Build Record — the ratchet refuses to trust an empty measurement

| | |
|---|---|
| **Date** | 2026-09-25 |
| **Author / session** | Claude Opus 5.5 (Claude Code session), owner hchengit |
| **Branch** | `fix/smoke-gate-fail-closed` |
| **Commits** | (fill at close-out) |
| **Status** | COMPLETE |
| **Change type** | fix |

## 0. Intent — the owner's words, approved before design
- [x] Problem: if the ratchet's file discovery finds nothing (a crate dir
      renamed or moved), every counter reads 0. 0 is below baseline, so the
      ratchet reports "a counter improved" and — outside `--check-only` —
      rewrites the baseline to 0, silently erasing the mechanism.
- [x] Outcome: an empty or impossibly-small file discovery is a hard FAIL in
      every mode, never an improvement and never written to the baseline.
- [x] Who/what it affects: `scripts/ratchet.sh` only. No product code.
- [x] Open questions: none. This repo always has .rs and .swift files, so
      "zero files found" is unambiguously a measurement failure, not progress.
- [x] Owner approved: chat, 2026-09-25, "Go ahead with 2 and then 1."

## 0b. Spec — requirements + design, policy applied up front
- [x] Requirements:
      R1. Zero discovered Rust files ⇒ FAIL (repo is a Rust workspace).
      R2. Zero discovered Swift files ⇒ FAIL (repo has a Swift app).
      R3. The check runs in ALL modes — auto, `--check-only`, `--update` —
          before any counter is computed or any baseline is written.
      R4. A legitimate run (files present) is unchanged and still GREEN.
- [x] Design: an `assert_discovery()` that counts RS_FILES and SW_FILES and
      exits non-zero with a named reason if either is 0. Called immediately
      after the file-producer functions are defined, ahead of every mode
      branch.
      Rejected — a minimum file-count floor in the baseline: file count can
      legitimately fall when files are deleted, so a floor would false-alarm.
      Zero is the only value that is unambiguously "could not measure".
- [x] Policy applied: stricter-only; no behaviour-changing default. Law 4 —
      alert on the absence of success; an empty measurement is absence.
- [x] Flagged concerns resolved: the `deny.toml` advisory counter uses `grep`
      not `find`; a missing file yields 0, which equals its baseline of 0, so
      it neither false-alarms nor hides. Left as-is; noted here.

## 1. Plan
- [x] One-sentence statement: the ratchet asserts it found files before it
      trusts any count.
- [x] Blast radius: `scripts/ratchet.sh`, plus a new test. Reversible.
- [x] Current behavior characterized: see Evidence log, BEFORE.
- [x] Files that change: `scripts/ratchet.sh`; new `scripts/tests/test-ratchet.sh`.
- [x] Risks: the assertion firing on a legitimate run. Mitigated — discovery
      matches tracked files exactly today (50 rs, 43 swift).
- [x] Verification: the test drives the ratchet with discovery pointed at an
      empty tree and asserts FAIL + baseline untouched; and a normal run stays
      GREEN.

## 2. Build
- [x] New code meets the bar: one small function, `assert_discovery()`, called
      once at top level ahead of every mode branch. No new dependency.
- [x] Clean as you go: no old code to remove; the fix is purely additive.
- [x] Security question — touches auth / money / exec / private data? **No.**
      `scripts/ratchet.sh` is a debt gate. The relevant property is integrity of
      the gate itself: an empty measurement must not be able to erase the
      baseline. No crown-jewel file touched.

## 3. Debug
- [x] Reproduced before fixing: the regression test, run against the pre-fix
      ratchet, showed the baseline overwritten with zeros. Evidence log.
- [x] Failing test written and SEEN failing, then fix-lock engaged:
      `scripts/tests/test-ratchet.sh` seen FAILING (all assertions) against the
      current code; `fix-lock` engaged for this record before the code changed;
      released at close-out to add the `--update` assertion (Spec R3), which
      strengthens the guard rather than weakening it.
- [x] Root cause is a CLASS: **an aggregator whose empty input is
      indistinguishable from — here, better than — its success case.** Empty
      discovery yields 0, which reads as debt eliminated. Same family as the
      2026-09-23 smoke false-green; this is its sibling, named in that record.
- [x] Swept for siblings: the two `find`-based producers (`RS_FILES`,
      `SW_FILES`) are the only discovery in the file and are both covered by
      the one assertion. `count_advisories` uses `grep` on a fixed path; a
      missing file yields 0 = its baseline, so it neither false-alarms nor
      hides. Noted in Spec.

## 4. Verify
- [x] Unit tests added/updated, including failure paths:
      `scripts/tests/test-ratchet.sh`, six assertions across auto,
      `--check-only`, and `--update`. Product suite unchanged: 339 passed.
- [x] Watched it work in the running system: full smoke gate GREEN with the
      ratchet step PASS.
- [x] Recovery/fallback path triggered live: the failure path IS the change —
      drove it with an empty tree and watched it FAIL with the baseline intact,
      where the old code zeroed the baseline.
- [x] Regression guard proven to FAIL on the old code:
      `./scripts/tests/test-ratchet.sh /tmp/old-ratchet.sh` (pre-fix file) fails
      all six assertions; the fixed code passes all six. Evidence log.
- [x] Independent verification — `verifier` subagent: VERDICT PASS. Its one
      actionable finding — the test omitted the `--update` mode named in Spec
      R3 — was accepted and fixed here (two `--update` assertions added, proven
      to fail on old code). Its other notes were close-out bookkeeping.
- [x] Diff matches the §1 plan: `scripts/ratchet.sh` + new
      `scripts/tests/test-ratchet.sh` + this record. Nothing else. No
      crown-jewel or product code touched (verifier confirmed).

## 5. Close Out
- [x] Full gate green: `RESULT: 12 passed, 0 failed, 5 skipped — GREEN`.
- [x] Scrap Sweep: `/tmp/old-ratchet.sh` and all mktemp trees removed; the test
      cleans its own `mktemp -d` via trap. `git status` shows only the three
      intended paths.
- [x] Reviewed per `REVIEW.md`: Bugs / Security / Compliance passes run; the
      verifier supplied independent Security and Compliance evidence. Findings
      recorded here, not self-approved — the owner decides.
- [x] Lesson loop: the lesson is a gate — `scripts/tests/test-ratchet.sh` fails
      on the old behaviour. This is the same class as 2026-09-23; the two
      records cross-reference. No new CLAUDE.md line — Law 4 already covers it.
- [x] Knowledge layer: the WHY lives in the `assert_discovery()` comment and
      the test header, both naming the baseline-zeroing concretely.
- [x] Commit message explains WHY; record committed with the change.

## Skipped items — visible, never silent
- **CI wiring of `scripts/tests/test-ratchet.sh`: deferred to item 1**, the
  next change in this session, which wires both gate self-tests
  (`test-smoke.sh` zero-suite, `test-ratchet.sh`) into `ci.yml`. Until then the
  test runs by hand. Named here so it is not lost.

## Evidence log
```
DISCOVERY MATCHES TRACKED FILES (2026-09-25) — tightening breaks nothing
  rs    tracked=50  discovered=50
  swift tracked=43  discovered=43

BEFORE — regression test against the pre-fix ratchet (all assertions fail)
  NOT OK  auto mode exits 0 on empty discovery
  NOT OK  reports improvement/GREEN on empty discovery
  NOT OK  baseline was OVERWRITTEN (zeroed) on empty discovery
  NOT OK  --check-only greens on empty discovery
  NOT OK  --update greens on empty discovery
  NOT OK  --update OVERWROTE the baseline (zeroed) on empty discovery
  RESULT: FAILED

AFTER — same test against the fixed ratchet
  ok  auto mode exits non-zero
  ok  does not report improvement
  ok  baseline left intact
  ok  --check-only exits non-zero
  ok  --update exits non-zero
  ok  --update left baseline intact
  RESULT: PASSED

NORMAL RUN — real tree, unaffected
  ./scripts/ratchet.sh --check-only  ->  RATCHET: GREEN  (every counter == baseline)

FULL GATE
  RESULT: 12 passed, 0 failed, 5 skipped — GREEN
```
