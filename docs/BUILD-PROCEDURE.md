# BUILD PROCEDURE — Standard Work for Every Project

This document governs how software gets built here: planning, building,
debugging, testing, review, and the periodic loops that keep a system honest
over time. It is portable — copy it into any new project's repo and follow it
from day one. AI assistants working in a repo containing this file are bound
by it.

The goal is Toyota-style quality: not "never make mistakes," but **a system
where mistakes cannot travel** — every defect is caught by the nearest gate,
made loud, and converted into a permanent tripwire.

---

## The Five Laws (apply to every section below)

1. **Nothing is silent.** Every component either runs and is gated by a test,
   or it is deleted. A fallback that engages is an ALERT, never just a save.
   (Case study: a watchdog's primary restart path was dead for weeks while the
   sudo fallback quietly recovered everything — the audit trail even recorded
   the dead mechanism as having run.)
2. **Stop the line.** A red gate (build, typecheck, test, smoke) halts all
   other work until green. No "I'll fix it after this feature." No skipped,
   excluded, or `@ts-nocheck`'d code without a counted, scheduled debt entry.
3. **Standard work.** The checklists below are walked mechanically, every
   time, regardless of how small the change feels. Quality must not depend on
   anyone being sharp that day.
4. **Alert on the absence of success, not just the presence of failure.**
   Heartbeats over error handlers. "The upgrade checker must see a repo push
   within 90 days or complain." (Case study: a pinned Docker repo died at
   exactly the running version — the checker reported "up to date" for 18
   months because it only compared against what the dead repo published.)
5. **Encode every lesson as a gate.** A bug fixed is a bug class still alive.
   Every incident ends with a tripwire — a test, a ratchet, a monitor, a
   refusal-to-boot — that makes the whole CLASS impossible or loud.

---

## Phase 0 — Project Bootstrap (before the first feature)

Do these once, at project start. A project without them is a prototype, not
a product.

- [ ] **Version control** with a protected main branch; work happens on
      branches; every merge has a green CI run.
- [ ] **CI that actually gates**: build + typecheck + unit tests + lint +
      secret scan, none marked continue-on-error. Prove it with a
      **red-test drill**: plant a failing test, confirm CI goes red, remove it.
- [ ] **Pre-commit hooks**: typecheck + secret scan (gitleaks or equivalent)
      minimum.
- [ ] **A smoke script** (`scripts/smoke.sh` or equivalent): one command that
      probes every service, port, and page the system claims to provide, with
      distinct content markers (not just "port answers"), and echoes the
      active configuration. This is the session-exit gate forever after.
- [ ] **A debt ratchet**: counted metrics that may only go down
      (`@ts-nocheck` count, `any` count, TODO count, script-style tests…).
      Baselines committed; CI fails on any rise.
- [ ] **Secrets hygiene**: no secret in the repo, ever; secrets live in
      env files/keychains outside the tree; document where each one lives.
- [ ] **Version pinning policy**: every dependency and container image pinned
      to an exact version. `:latest` and floating branch tags are forbidden —
      a float is how a 3.5-year-old EOL Tor daemon hides in plain sight.
- [ ] **Runtime truth over declared truth**: version/status displays must
      probe the running process, never trust a tag, a cache, or a config.

---

## The Per-Change Loop (every feature, every fix — no exceptions)

### 1. PLAN (before writing code)
- [ ] State the change in one sentence. If you can't, split it.
- [ ] Identify the blast radius: which modules, which data, which auth/funds/
      exec paths does this touch? Anything irreversible?
- [ ] **Characterize before you change**: read the current behavior and prove
      your understanding (run it, log it, test it). Plans built on assumed
      behavior produce fixes for bugs that don't exist and miss the ones that
      do. (Case study: three "big delete" refactor phases found the deletions
      already done — and one "dead" module that was load-bearing.)
- [ ] Decide the verification BEFORE building: "I will know this works when
      ___." If the answer is "it compiles," you don't have a plan yet.

### 2. BUILD
- [ ] Smallest coherent increment; one concern per commit.
- [ ] New code meets the bar: typed (no new `any`/`@ts-nocheck`), validated
      at its boundaries (schema-check every input that crosses a trust line),
      size-capped (~800 LOC/file), documented where non-obvious.
- [ ] **Clean as you go**: the old version of anything you replace is removed
      in the same change. Scaffolding and probe scripts die with the session.
- [ ] Security question, asked explicitly every time: *does this change touch
      authentication, money, execution, or private data?* If yes: which
      existing gate covers it, and is there a test proving the gate holds?
      A hardening pass that breaks a legitimate path is also a defect —
      check both directions. (Case study: a loginless-mode hardening
      accidentally gated the login endpoint itself behind login.)

### 3. DEBUG (when something is wrong)
- [ ] Reproduce first. A fix without a reproduction is a guess.
- [ ] Read the actual error/log — not what you expect it to say. The clue is
      usually verbatim in there. (Case study: a "stuck" node was printing
      `bad-version-reduced_data` — a consensus rejection, not a hang; every
      restart-style "fix" would have been wrong.)
- [ ] Fix the CLASS, not the instance: after the fix works, ask "where else
      does this exact pattern exist?" and sweep. (Case study: one raw-template
      copy bug appeared in three different install scripts.)
- [ ] Before any state-changing remediation (restart, delete, config change):
      does the evidence support THIS action, or does the symptom just
      pattern-match a known failure?

### 4. TEST / VERIFY
- [ ] Unit tests for the logic you added — including the failure paths.
      A test that only covers the happy path certifies nothing.
- [ ] **Watch it actually work** in the running system — the real page, the
      real endpoint, the real container. "Tests pass" and "it works" are
      different claims; make both.
- [ ] If the change alters recovery/fallback behavior: **trigger it**. A
      recovery path that has never been exercised is a hope, not a feature.
- [ ] Regression guard: for any bug you just fixed, prove the test fails on
      the OLD code (revert briefly if needed). A guard that never failed
      guards nothing.

### 5. CLOSE OUT (end of every change/session)
- [ ] Run the full gate: build → typecheck → unit tests → ratchet → smoke.
      All green or the session isn't over.
- [ ] **The Scrap Sweep** (every session, no exceptions — see the taxonomy
      below): `git status` plus a look at the working directories. Everything
      present is the real change or a deliberate, load-bearing new file.
- [ ] Update the knowledge layer IN THE SAME CHANGE: docs / RAG / runbooks /
      user-facing help for whatever behavior changed. Stale docs are silent
      failures too.
- [ ] Commit with a message that explains WHY (the incident, the class, the
      decision) — the diff already shows the what.
- [ ] Deploy = build: one scripted path from source to running system. Never
      hand-copy artifacts; drift between source and running code is a
      slow-motion outage.

---

## The Scrap Taxonomy — what "clean" means, precisely

Scrap is anything that helped you get to the change but is not the change.
It is removed **the same session it was created** — scrap left overnight
becomes "maybe load-bearing" by next week and permanent by next month. The
rule in both directions: **if it's junk, dump it (prove it first — zero
importers/callers/unit/systemd/runbook references); if it should exist, wire
it in and gate it. "Sitting there quietly" is never a third state.**

Delete on sight, every session:
- [ ] **Scaffolding & probe scripts** — debug scripts, curl/test one-liners
      saved as files, temporary harnesses. If it was the road to the fix and not
      the fix, it dies with the session (scratchpad if worth keeping, never
      the repo).
- [ ] **One-shot scripts that have been applied** — migration/apply/fixup
      scripts are DANGEROUS after they run: re-running them reinstalls the
      old state. (Case study: an applied one-shot would have reinstalled a
      renamed-away systemd unit; a different one actually DID install a raw
      config template and silently killed the watchdog for four days.)
      Their knowledge lives on in the commit message and runlog; the script
      does not.
- [ ] **The old version beside the new** — a replaced function, route, file,
      or config left "just in case." The version control system is the
      just-in-case; the working tree is not.
- [ ] **Orphans** — code with zero reachable callers from real entry points.
      Prove it (imports, shell scripts, systemd units, runbooks, tool
      registrations, dynamic loading), then delete. Beware: a dead barrel
      can re-export LIVE children — verify per child.
- [ ] **Debug residue in real code** — console.log/print left from
      diagnosis, commented-out blocks, temporarily-loosened checks,
      `.skip`'d tests, hardcoded test values.
- [ ] **Stray files** — `.bak`, `.old`, `.deleted`, editor swap/lock files
      (these have leaked SECRETS from config dirs before), untracked files
      nobody can name a purpose for, stale build artifacts (sweep with a
      CLEAN build — stale artifacts make deleted code look alive).
- [ ] **Stale state** — expired cache files, failure records from bugs since
      fixed, stashes older than a day, branches whose work landed.

Quarantine is never a resting state: anything excluded from CI, `@ts-nocheck`'d,
or `.skip`'d is a **counted, ratcheted, scheduled** debt with a named phase in
which it becomes running-and-gated or deleted.

---

## Periodic Loops (calendar-driven, not mood-driven)

Silent failures are found by time and use, never by the build loop. Schedule
these; do not rely on remembering.

### Weekly (~15 minutes)
- [ ] Run smoke; skim service/upgrade/notification pages.
- [ ] Grep logs for engaged FALLBACKS and repeated warnings — a fallback
      firing weekly is a primary path dying quietly.
- [ ] `git status` on all machines: no uncommitted drift older than a week.

### Monthly (one session) — DRILL, on rotation
Pick one; rotate through all of them over the quarter:
- [ ] **Restart drill**: clean reboot; zero manual interventions allowed.
- [ ] **Failover drill**: kill the primary of something (process, container,
      config); verify detection, recovery, AND that the recovery was loud.
- [ ] **Mode-switch drill**: exercise every supported configuration
      round-trip (engines, networks, feature flags), verifying state and
      funds/data integrity at each hop.
- [ ] **Restore drill**: restore a real backup into a scratch environment.
      An unrestored backup is Schrödinger's backup.
After every drill: findings become fixes become tripwires (Law 5).

### Quarterly (one to two sessions) — ADVERSARIAL REVIEW
- [ ] **Security pass** over auth/funds/exec paths: walk every mutation route
      and name its gate; try the obvious bypasses; verify rate limits and
      lockouts fire.
- [ ] **Dead-code sweep**: import-reachability from real entry points; every
      orphan proven-then-deleted. Verify with a CLEAN build — stale build
      artifacts hide deletions.
- [ ] **Dependency & image audit**: every pin still from a LIVING source
      (check last-publish dates, not just versions); EOL check on every
      runtime (language, OS, daemons).
- [ ] **Architecture check**: do the docs still describe the system? Is every
      documented invariant still tested? One impl per concern still true?
- [ ] **Fresh-eyes review**: automated multi-agent code review of recent
      changes, plus — before any public exposure — a human external audit of
      the security-critical paths.

---

## Incident Procedure (when something breaks in production)

1. **Stabilize** with the least destructive action that evidence supports.
2. **Capture** the state before "fixing" erases it (logs, files, versions).
3. **Root-cause to the class**: "the dashboard 502'd" is a symptom;
   "compose-managed containers lose their network endpoint when the network
   is recreated under them" is a class.
4. **Tripwire it** (Law 5): a test, monitor, guard, or refusal that makes the
   class loud or impossible.
5. **Record it** where the next session will find it: incident log / runbook /
   project memory — including what the false leads were.
6. **Sweep for siblings**: the same class usually lives in more than one place.

---

## Working with AI Assistants (how this document gets enforced)

- Point every AI session at this file; its checklists are binding.
- Demand **verification, not claims**: "tests pass" must come with the test
  run; "it works" must come with the probe of the running system.
- The AI must report failures verbatim — a session that only reports
  successes is hiding the interesting parts.
- AI-written code follows the same ratchets, the same gates, the same
  clean-as-you-go rule. Speed is not an exemption; it is the reason the
  gates exist.
- Multi-session hygiene: sessions do not commit each other's in-flight work;
  uncommitted changes older than a day get dispositioned (finished, stashed,
  or deleted), never left ambient.

---

## Release Gate — Definition of Done for public exposure

A project may be shown, shipped, or opened to others only when:

- [ ] N× clean restart drill passes with zero manual steps.
- [ ] Fresh-clone deploy on a clean machine works from documentation alone
      and comes back as the same system (same identities, same data).
- [ ] CI is fully gating; the ratchet baselines are at their floor targets.
- [ ] Every mutation endpoint has a named gate and a test proving it.
- [ ] No secrets in history (full-history scan), all credentials rotated.
- [ ] Docs describe the system as it IS; a stranger can operate it from them.
- [ ] The system has run unattended through a soak period (48h+) with every
      scheduled job, backup, and monitor verified to have fired.
- [ ] An adversarial review (automated + human for security-critical paths)
      has run against the release candidate.

Until every box is checked, the honest label is "prototype" — and prototypes
don't take deposits, hold keys, or accept strangers' trust.
