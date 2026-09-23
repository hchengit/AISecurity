# Build Record — <one-line change name>

> Copy this file to `docs/build-records/YYYY-MM-DD-<slug>.md` when PLANNING
> begins. Check boxes AS the work happens, with evidence — never afterward
> from memory. Commit the record WITH the change. An unchecked box without a
> SKIPPED entry means the change is not done.

| | |
|---|---|
| **Date** | YYYY-MM-DD |
| **Author / session** | |
| **Branch** | |
| **Commits** | (fill at close-out) |
| **Status** | IN PROGRESS / COMPLETE / ABANDONED |
| **Change type** | feature / fix / refactor / ops |

## 0. Intent — the owner's words, approved before design
<!-- Small change: one line each is enough. Anything touching funds, auth,
     exec, or private data: never skipped. -->
- [ ] Problem (as the owner would say it):
- [ ] Outcome — what is true when this is done:
- [ ] Who/what it affects:
- [ ] Open questions (answered, or listed here):
- [ ] Owner approved the intent (how — message / date):

## 0b. Spec — requirements + design, policy applied up front
- [ ] Requirements derived from the intent:
- [ ] Design (and the alternatives rejected, one line each):
- [ ] Policy applied — first principle (every behaviour-changing default is
      an explicit, reversible owner choice), design rules, security gates:
- [ ] Flagged concerns resolved (or routed to the owner):

## 1. Plan — detailed enough that a new session could build from it alone
- [ ] One-sentence statement of the change:
- [ ] Blast radius (modules, data, auth/funds/exec paths touched, anything irreversible):
- [ ] Current behavior characterized before changing (how — evidence):
- [ ] Files that change, and the order of work:
- [ ] Risks — what could break; which step is riskiest:
- [ ] Verification defined up front — "I will know this works when":

## 2. Build
- [ ] New code meets the bar: typed, boundary-validated, size-capped
- [ ] Clean as you go: old version removed in the same change
- [ ] Security question answered explicitly — touches auth / money / exec /
      private data? If yes, which gate covers it and which test proves it:

## 3. Debug (only if this change fixes a defect — else mark N/A)
- [ ] Reproduced before fixing (how):
- [ ] Failing test written and SEEN failing, then fix-lock engaged
      (`python3 .claude/hooks/guard.py fix-lock on <this record>`) — tests
      and baselines are read-only until the owner approves `fix-lock off`:
- [ ] Root cause is a CLASS, named here:
- [ ] Swept for siblings of the class (where else it lived):

## 4. Verify
- [ ] Unit tests added/updated, including failure paths (suite result):
- [ ] Watched it actually work in the running system (what was probed, result):
- [ ] Recovery/fallback path triggered live, if this change touches one:
- [ ] Regression guard proven to FAIL on the old code:
- [ ] Independent verification — `verifier` subagent report (it runs,
      exercises, reports; never fixes), or N/A for no running surface:
- [ ] Diff matches the §1 plan; deviations explained here:

## 5. Close Out
- [ ] Full gate green — build / typecheck / unit tests / ratchet / smoke
      (paste the smoke summary line):
- [ ] Scrap Sweep done per the taxonomy (what was deleted):
- [ ] Reviewed per `REVIEW.md` (bugs / security / plan-compliance passes);
      Important findings fixed or listed under Skipped:
- [ ] Lesson loop — a mistake the AI made twice became a CLAUDE.md line;
      a rule it broke became a guard-config.json entry (or N/A):
- [ ] Knowledge layer updated in the same change (docs / RAG / runbooks / help):
- [ ] Commit message explains WHY; record committed with the change

## Skipped items — visible, never silent
<!-- Every unchecked box above MUST have a line here: which box, why skipped,
     and when it will be done. "To save time" is not a reason. -->
- (none)

## Evidence log
<!-- Paste the receipts: test totals, smoke RESULT line, probe outputs,
     before/after values. Claims without receipts don't count. -->
```
```
