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

## 1. Plan
- [ ] One-sentence statement of the change:
- [ ] Blast radius (modules, data, auth/funds/exec paths touched, anything irreversible):
- [ ] Current behavior characterized before changing (how — evidence):
- [ ] Verification defined up front — "I will know this works when":

## 2. Build
- [ ] New code meets the bar: typed, boundary-validated, size-capped
- [ ] Clean as you go: old version removed in the same change
- [ ] Security question answered explicitly — touches auth / money / exec /
      private data? If yes, which gate covers it and which test proves it:

## 3. Debug (only if this change fixes a defect — else mark N/A)
- [ ] Reproduced before fixing (how):
- [ ] Root cause is a CLASS, named here:
- [ ] Swept for siblings of the class (where else it lived):

## 4. Verify
- [ ] Unit tests added/updated, including failure paths (suite result):
- [ ] Watched it actually work in the running system (what was probed, result):
- [ ] Recovery/fallback path triggered live, if this change touches one:
- [ ] Regression guard proven to FAIL on the old code:

## 5. Close Out
- [ ] Full gate green — build / typecheck / unit tests / ratchet / smoke
      (paste the smoke summary line):
- [ ] Scrap Sweep done per the taxonomy (what was deleted):
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
