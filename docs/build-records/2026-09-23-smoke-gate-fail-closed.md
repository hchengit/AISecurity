# Build Record — smoke gate fails closed on a toolchain it cannot run

| | |
|---|---|
| **Date** | 2026-09-23 |
| **Author / session** | Claude Opus 5 (Claude Code session), owner hchengit |
| **Branch** | `fix/smoke-gate-fail-closed` |
| **Commits** | (fill at close-out) |
| **Status** | COMPLETE |
| **Change type** | fix |

## 0. Intent — the owner's words, approved before design
- [x] Problem (as the owner would say it): the session-exit gate said
      `PASS  cargo test --workspace --exclude security-linux — 0 suites, 0 passed, 0 failed`.
      It reported success for a test run that never happened. Separately it
      claimed cargo and cargo-deny were missing when both are installed.
- [x] Outcome — what is true when this is done: the tests step FAILS when zero
      suites ran, and the gate resolves its own toolchain instead of inheriting
      the caller's PATH. A missing or broken toolchain reads RED, never green.
- [x] Who/what it affects: `scripts/smoke.sh` only. No product code, no
      detection logic, no Rust, no Swift. Affects what the gate reports, not
      what the system does.
- [x] Open questions (answered, or listed here): should the gate also assert a
      MINIMUM suite count, to catch one crate silently dropping out? Deferred —
      see Skipped items. Zero-suites is unambiguous; a hand-maintained floor is
      the kind of counter CLAUDE.md warns gets ignored and then guards nothing.
- [x] Owner approved the intent (how — message / date): chat, 2026-09-23,
      Intent quoted back and answered "Yes, take it."

## 0b. Spec — requirements + design, policy applied up front
- [x] Requirements derived from the intent:
      R1. Zero collected `test result:` lines ⇒ FAIL, never PASS.
      R2. cargo's own exit status participates in the verdict.
      R3. The gate resolves its own toolchain rather than inheriting whatever
          PATH the calling shell happened to have. NOTE: corrected during
          Verify — an earlier draft of R3 claimed the gate finds the toolchain
          "regardless of the invoking shell". That was overstated and is now
          withdrawn: resolution goes through $HOME, which the caller controls.
          See the residual under Verify. Recorded rather than quietly reworded.
      R4. The failure message names the real cause, not a symptom.
- [x] Design (and the alternatives rejected, one line each):
      Count `^test result:` lines into `NSUITES` and branch on zero before the
      pass test; capture `$?` from the cargo run into `TRC`; add
      `export PATH="$HOME/.cargo/bin:$PATH"` near the top, matching
      `build-rust.sh:35`.
      Rejected — dropping the `awk` aggregate for a `tail -1`: that is the
      exact bug the existing comment records fixing (339 tests showing as 7).
      Rejected — `set -e`: would abort the gate mid-run and lose the RESULT
      summary line the header promises is always last.
      Rejected — requiring a minimum suite count: see Open questions.
- [x] Policy applied — first principle, design rules, security gates: no
      behaviour-changing default is introduced; the change only makes an
      existing gate stricter. Law 1 (nothing is silent) and Law 4 (alert on the
      absence of success) are the governing rules — this defect is Law 4
      literally, a check that stopped firing looking identical to a clean run.
- [x] Flagged concerns resolved (or routed to the owner): the RED the owner saw
      was entirely a PATH artifact — clippy and cross_validation failed and
      cargo deny skipped because `cargo` was not on PATH, not because the tree
      is broken. Confirmed: `~/.cargo/bin/` holds cargo, rustc, cargo-deny.

## 1. Plan
- [x] One-sentence statement of the change: make `scripts/smoke.sh` fail closed
      when it cannot run the tests it gates on.
- [x] Blast radius: one file, `scripts/smoke.sh`. No auth / funds / exec /
      private-data path touched. Nothing irreversible. Reverting is a checkout.
- [x] Current behavior characterized before changing (how — evidence): ran the
      unmodified script with the toolchain hidden
      (`env PATH=/usr/bin:/bin:/usr/sbin:/sbin`) — tests step printed PASS with
      0 suites. See Evidence log, BEFORE.
- [x] Files that change, and the order of work: `scripts/smoke.sh` — PATH
      export near the top, then the tests-step verdict.
- [x] Risks — what could break; which step is riskiest: riskiest is the verdict
      rewrite making a legitimately green run read RED (a hardening pass that
      breaks the legitimate path is also a defect — BUILD-PROCEDURE step 2).
      Mitigated by running the real gate with a working toolchain and requiring
      GREEN, not only by running the broken-toolchain case.
- [x] Verification defined up front — "I will know this works when": with the
      toolchain hidden the tests step reads FAIL and names zero suites; with the
      toolchain present the full gate reads GREEN including cargo deny.

## 2. Build
- [x] New code meets the bar: the verdict now branches on a counted quantity
      (`NSUITES`) and the subprocess exit status (`TRC`) rather than on the
      shape of a string. Failure messages name the cause (`cargo exit 127`),
      not the symptom.
- [x] Clean as you go: the dead `${TSUM:-no result line}` fallback is removed —
      `TSUM` could never be empty, which is what made the bug invisible. The
      A/B drill copies (`scripts/.smoke-old.sh`, `scripts/.old-smoke.sh`) and
      the sandbox HOME were deleted in the same session; `git status` is clean
      apart from the intended three paths.
- [x] Security question answered explicitly — touches auth / money / exec /
      private data? **No.** `scripts/smoke.sh` is a reporting gate; it changes
      what is reported, never what the product enforces. No crown-jewel file is
      touched, so no threat-model note is owed under REVIEW.md. The relevant
      security property is indirect but real: this gate is what a session trusts
      before declaring itself done, so a gate that reports success for work it
      did not do is a control that has silently stopped existing. The change
      also closes one evasion route — under the old inherited-PATH behaviour a
      caller who controlled PATH could shadow `cargo` and green the gate;
      prepending the real toolchain now defeats that (verified).

## 3. Debug
- [x] Reproduced before fixing (how): isolated the predicate and fed it a
      `command not found` string — returned PASS. Then end-to-end with the
      toolchain hidden. Both in Evidence log.
- [x] Failing test written and SEEN failing: `scripts/test-smoke.sh` drives the
      gate with a deliberately absent toolchain. Seen FAILING against the
      pre-fix file and PASSING against the fix — both transcripts in the
      Evidence log. fix-lock NOT engaged: the guard hook shipped in `ee95859`
      is registered in `.claude/settings.json` but was not loaded by this
      session (the file arrived in the same pull, after the session started),
      so `fix-lock` could not have been enforced here and claiming it would be
      a false receipt. Listed under Skipped.
- [x] Root cause is a CLASS, named here: **an aggregator whose empty case is
      indistinguishable from its success case.** awk's `END` block runs on empty
      input, so `grep | awk` over zero matches emits a well-formed
      `0 suites, 0 passed, 0 failed`. The `[ -n "$TSUM" ]` guard written to
      catch "no result line" could never fire, because `TSUM` is never empty.
      General form: deriving a verdict from parsed output without first
      asserting that any output was parsed.
- [x] Swept for siblings of the class (where else it lived):
      - `scripts/smoke.sh` — the tests step was the only `grep | awk` aggregate.
        Every other verdict is driven by an exit status or an explicit presence
        check in the alarm-on-absence direction; the guard step was already
        correct and is what the fix was modelled on.
      - **One sibling FOUND, in `scripts/ratchet.sh` — reported, NOT fixed
        here.** The counters derive from `find`-based discovery
        (`RS_FILES()` / `SW_FILES()`, lines 31-32). If discovery returns nothing
        — a crate directory renamed or moved — every counter reads `0`, which is
        `-lt` baseline, so the ratchet reports **GREEN, "a counter improved"**,
        and outside `--check-only` rewrites the baseline to zero. Empty is not
        merely indistinguishable from success there; it reads as *progress*.
        Verified empirically: a counter over an empty file set returns `0`.
        Blast radius is smaller than the smoke bug (a zeroed baseline turns
        loudly RED afterwards, so it self-reveals rather than staying blind),
        but the `--check-only` path used by the smoke gate does green on a
        measurement that never happened. Fixing it is outside this change's
        approved Intent and needs its own — routed to the owner.

## 4. Verify
- [x] Unit tests added/updated, including failure paths: `scripts/test-smoke.sh`
      added, asserting all four properties (names zero suites; does not report
      PASS; non-zero exit; RESULT reads RED). Product test suite unchanged and
      green: **8 suites, 339 passed, 0 failed**.
- [x] Watched it actually work in the running system: full gate run end to end,
      including live :7459 probes — `RESULT: 12 passed, 0 failed, 5 skipped —
      GREEN`.
- [x] Recovery/fallback path triggered live: the failure path IS this change.
      Drove it with an absent toolchain and watched it report RED naming
      `cargo exit 127`, where the old code reported PASS under identical
      conditions.
- [x] Regression guard proven to FAIL on the old code: `./scripts/test-smoke.sh
      scripts/.old-smoke.sh` (pre-fix file from `git show HEAD:`) exits 1 with
      two NOT OK assertions. Transcript in Evidence log; the temp copy was
      deleted immediately after.
- [x] Independent verification — `verifier` subagent report: run under
      `.claude/agents/verifier.md`, reporting only, no edits. **VERDICT: PASS**
      on the acceptance test, with two open items it declined to clear, both
      accepted as accurate and acted on:
      1. *"Spec R3 as written is overstated"* — correct. R3 withdrawn and
         rewritten above rather than silently reworded.
      2. *"the only tell is `rustc not found`, an informational echo, not a
         PASS/FAIL/SKIP, so it does not move the verdict"* — correct, and the
         same class one line up. **Fixed in this change**: toolchain provenance
         is now a verdict-moving step that names the resolved cargo path.
      **RESIDUAL, OPEN, OWNER'S CALL:** `HOME` is caller-controlled, so a fake
      toolchain at `$HOME/.cargo/bin/cargo` that prints plausible
      `test result:` lines still produces a fully green gate. This is **not a
      regression** — the pre-change gate inherited the caller's PATH, so the
      same attack worked one env var earlier and more easily, and PATH-shadowing
      is now actively defeated (verified: a fake `cargo` placed first on PATH
      loses to the real one). It is narrowed, not closed. Closing it properly
      means pinning the toolchain to an absolute path or verifying its
      provenance, which is a separate Intent. Mitigation shipped here: the
      toolchain step writes the resolved path into the transcript, so a
      redirected HOME is visible in the output instead of silent.
- [x] Diff matches the §1 plan; deviations explained here: the Plan named
      `scripts/smoke.sh` only. Two additions, both inside the approved Intent
      rather than widening it:
      - the toolchain provenance step — the Intent's own words are "a missing
        or broken toolchain reads RED, never green", and an echo that cannot
        fail did not meet that;
      - `scripts/test-smoke.sh` — the template mandates a regression guard at
        §4, and Law 5 requires the lesson become a gate.
      Verifier confirmed independently: no unplanned file changed, no planned
      file failed to change, no crown-jewel file touched.

## 5. Close Out
- [x] Full gate green: `RESULT: 12 passed, 0 failed, 5 skipped — GREEN`
      (11 before this change; +1 is the new toolchain step).
- [x] Scrap Sweep done per the taxonomy: deleted `scripts/.smoke-old.sh`,
      `scripts/.old-smoke.sh`, and the sandbox HOME directories. The A/B drill
      copies existed only for the duration of the drill. `git status` shows
      exactly three paths: the modified gate, the new test, this record.
- [x] Reviewed per `REVIEW.md`: Bugs / Security / Compliance passes run; the
      independent verifier supplied the Security and Compliance evidence above.
      Findings are recorded here as evidence — **not self-approved**, per the
      separation-of-duties rule. The owner decides on the two open items
      (the HOME residual, and the `ratchet.sh` sibling).
- [x] Lesson loop: the lesson is encoded as a gate rather than as prose —
      `scripts/test-smoke.sh` fails on the old behaviour, so this defect cannot
      return quietly. No CLAUDE.md line added: the governing rule (Law 4, alert
      on the absence of success) already exists and was already correctly
      applied in the same file's guard step; the failure was one step not
      following it, which a test catches better than another sentence.
- [x] Knowledge layer updated in the same change: the WHY lives in
      `scripts/test-smoke.sh`'s header and in the two comments in
      `scripts/smoke.sh`, both naming the false-green concretely so the next
      reader sees why the code is shaped this way.
- [x] Commit message explains WHY; record committed with the change.

## Skipped items — visible, never silent
- **CI wiring of `scripts/test-smoke.sh`: NOT DONE, needs owner approval.**
  It belongs beside the guard tests in `.github/workflows/claude-guard.yml`,
  but `.github/workflows/*` is an approval-gated path in
  `.claude/hooks/guard-config.json`. Until wired, the regression guard only
  runs when invoked by hand — it exists but does not yet stand watch. One line
  for the owner to approve.
- **`scripts/ratchet.sh` empty-discovery sibling: NOT FIXED.** Found, verified
  and documented under §3. Outside this change's approved Intent; needs its own.
- **Minimum-suite floor: NOT BUILT.** Zero-suites is fixed; a per-crate
  expected-suite floor would also catch one crate silently dropping out, but
  needs hand-maintenance on every crate add or removal — the kind of counter
  CLAUDE.md warns gets ignored and then guards nothing. Revisit if a crate ever
  does drop out unnoticed.
- **`fix-lock` NOT engaged during Debug.** The guard hook arrived in the same
  pull that this session started before, so `.claude/settings.json` was not
  loaded and the hook could not have enforced anything. Recorded rather than
  ticked falsely. Applies from the next session onward.

## Evidence log
```
BEFORE — unmodified scripts/smoke.sh, toolchain hidden
  $ env PATH=/usr/bin:/bin:/usr/sbin:/sbin ./scripts/.smoke-old.sh
  rustc       not found
  PASS  cargo test --workspace --exclude security-linux — 0 suites, 0 passed, 0 failed   <-- FALSE GREEN
  FAIL  clippy
  SKIP  cargo deny (cargo-deny not installed)
  RESULT: 8 passed, 2 failed, 6 skipped — RED

PREDICATE IN ISOLATION — old logic, input is a "command not found" string
  TSUM = [0 suites, 0 passed, 0 failed]     (awk END runs on empty input)
  verdict: PASS                              <-- the bug, reproduced standalone

TOOLCHAIN IS PRESENT — the "not found" was a PATH artifact, not a missing install
  $ ls ~/.cargo/bin/
  cargo  cargo-audit  cargo-clippy  cargo-deny  cargo-fmt  cargo-miri  cbindgen
  clippy-driver  rls  rust-analyzer  rust-gdb  rust-gdbgui  rust-lldb  rustc
  rustdoc  rustfmt  rustup

AFTER — fixed scripts/smoke.sh, toolchain genuinely absent (empty HOME + stripped PATH)
  FAIL  cargo test --workspace --exclude security-linux — NO suites ran (cargo exit 127); the gate could not run the tests it gates on
  RESULT: 7 passed, 3 failed, 6 skipped — RED
  ...same conditions, old file, for contrast:
  PASS  cargo test --workspace --exclude security-linux — 0 suites, 0 passed, 0 failed

REGRESSION GUARD — proven in both directions
  $ ./scripts/test-smoke.sh                          # the fix
     ok    names zero suites ran
     ok    does not report PASS for tests that never ran
     ok    gate exits non-zero (RED)
     ok    RESULT line reads RED
  RESULT: regression test PASSED
  exit 0

  $ ./scripts/test-smoke.sh scripts/.old-smoke.sh    # pre-fix file
     observed  PASS  cargo test ... — 0 suites, 0 passed, 0 failed
     NOT OK names zero suites ran
     NOT OK does not report PASS for tests that never ran
  RESULT: regression test FAILED — the gate reported success for work it did not do
  exit 1

FULL GATE — healthy toolchain, after the change
  PASS  toolchain — cargo=/Users/hchome/.cargo/bin/cargo rustc=1.98.1
  PASS  cargo test --workspace --exclude security-linux — 8 suites, 339 passed, 0 failed
  PASS  clippy --workspace --exclude security-linux -D warnings
  PASS  cargo deny (advisories bans sources)
  PASS  cross_validation (Rust/Swift parity)
  RESULT: 12 passed, 0 failed, 5 skipped — GREEN

RATCHET SIBLING — empty discovery reads as improvement (reported, not fixed)
  counter body over an empty file set returns: 0
  0 < baseline  =>  "(lower the baseline)"  =>  RATCHET: GREEN
```
