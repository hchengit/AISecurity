# Build Record — a session cannot switch the guard off without the owner (AISecurity)

| | |
|---|---|
| **Date** | 2026-09-25 |
| **Author / session** | Claude (Opus 5.5) with Henry |
| **Branch** | main |
| **Commits** | the commit that adds this record |
| **Status** | COMPLETE |
| **Change type** | fix (developer tooling: the AI-session guard policy) |

**Primary record** (intent, spec, plan, evidence, independent verification):
`rikurinode/docs/build-records/2026-09-25-guard-self-disable-hole.md`.
One logical change across rikurinode, Iceman and AISecurity. This record lists
what is specific to AISecurity.

## AISecurity-specific
- [x] Change: `.claude/hooks/guard-config.json` protects `.claude`, `.claude/settings.local.json`, `.claude/hooks` and `.claude/state`, with six worked examples (24 → 30), plus `.claude/settings*` and `.claude/state/*` with two more after the independent verifier (→ 32).
- [x] Reproduced before the fix: the five new ask-examples failed against the old policy (`FAILED (failures=5)`, each `'allow' != 'ask'`); the read example passed.
- [x] Round 2 reproduced too: the two new examples failed (`FAILED (failures=2)`) before those globs.
- [x] After the fix: Python 3.12 and 3.9, `Ran 16 tests … OK`. Independent verifier: `VERDICT: PASS` (see the primary record).
- [x] Threat-model note (REVIEW.md: changes to the guard get one): the attacker is a prompt-injected session that wants its later tool calls unguarded. Before this change it could write `disableAllHooks` into the git-ignored `.claude/settings.local.json`, or delete `.claude/hooks`, and nothing asked. Now both ask, as do wildcard deletes of `.claude/state/*` and `.claude/settings*`. Out of reach of this policy: user-level `~/.claude/settings.json` (outside the repository), and the shared guard's documented tripwire limits (`python -c` writes, `cd X && rm Y`).
- [x] `guard.py` and `test_guard.py` unchanged by this change. They still carry the separate, uncommitted lesson-gates change; commit that on its own.
- [x] Knowledge layer: N/A, developer tooling.
