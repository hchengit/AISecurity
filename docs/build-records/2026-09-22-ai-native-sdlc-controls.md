# Build Record — AI-native SDLC controls (AISecurity)

| | |
|---|---|
| **Date** | 2026-09-22 |
| **Author / session** | Claude (Opus 5.5) with Henry |
| **Branch** | main |
| **Commits** | the commit that adds this record (owner-requested 2026-09-22) |
| **Status** | COMPLETE |
| **Change type** | ops (developer tooling) |

**Primary record** (intent, spec, plan, the full evidence, mutation tests,
live probes): `rikurinode/docs/build-records/2026-09-22-ai-native-sdlc-controls.md`.
One logical change across three repos. This record lists what is specific
to AISecurity.

## 0. Intent
- [x] Owner: "implement Claude SDLC's procedure from now on for projects that
      make sense." AISecurity is full tier (owner decision 2026-09-22).

## 1. Plan — files that change here
- [x] `.claude/hooks/guard.py`, `test_guard.py` (identical to rikurinode, `cmp`-checked)
- [x] `.claude/hooks/guard-config.json`: this repo's policy + worked examples
- [x] `.claude/settings.json` (wires the hook), `.claude/agents/verifier.md`
- [x] `.gitignore`: un-ignore the shared `.claude` files; state/ and `__pycache__` stay ignored
- [x] `REVIEW.md`, `CLAUDE.md` pointer, build-record template (Intent/Spec sections)
- [x] `docs/BUILD-PROCEDURE.md` + `docs/build-records/TEMPLATE.md`: the
      INTENT+SPEC / plan-detail / fix-lock / verifier / REVIEW.md additions and
      the "Deterministic gates" section, on top of the 2026-08-19 adoption
      (additions only: +69/-0 and +30/-1)
- [x] `scripts/smoke.sh`: new "AI-session guard" section (wired + tests green)
- [x] `.github/workflows/claude-guard.yml`: NEW, because `ci.yml` only triggers
      on `SecurityCore/**` and a guard change must not skip CI

## Policy specific to AISecurity
- ask on edits to crown-jewel code (`bypass.rs`, `privacy_router.rs`,
  `intent_verifier.rs`, `command_policy.rs`, `local_services.rs`, `aisec-mcp`,
  `intent-hook`, `security-core-ffi`) and `SecurityCore/deny.toml`
- ask on edits to `scripts/hooks/*` (pre-commit secret scan) and `scripts/install-hooks.sh`
- ask on `install.sh` / `uninstall.sh`, `launchctl` changes, `claude mcp add/remove`
- fix-lock read-only set includes `scripts/ratchet-baseline.txt`
- secrets include signing material (`*.p12`, `*.cer`, `*.mobileprovision`) and `vault.db`

## 4. Verify
- [x] `python3 -m unittest discover -s .claude/hooks`: Ran 12 tests OK (24 examples)
- [x] `./scripts/smoke.sh --fast` (Linux box): `RESULT: 2 passed, 0 failed, 7 skipped — GREEN`.
      Ratchet + guard PASS. The 7 SKIPs are the Rust gates (--fast) and the
      Mac-only agent binaries / :7459 daemon, which are not installed on this box.
- [x] Live: `claude -p` in this repo refused Read of canary `zz-probe.token`

## Skipped items — visible, never silent
- **Rebase, not a clean push**: this Linux clone was 10 commits behind GitHub
  (the 2026-08-19 Mac session had already adopted the procedure and closed the
  Phase 0 gaps: smoke, ratchet, pre-commit scan). The first draft of this
  change wrongly called those gaps "missing". It was rebased onto `1aac7d9`
  before pushing: the upstream CLAUDE.md section was kept and the controls
  block added to it; the procedure and template carry only additions. Lesson:
  `git fetch` + compare before characterizing a repo's state (BUILD 1).
- Full Rust/Swift gates not run: no Rust/Swift file changed; the full smoke belongs on the Mac.
