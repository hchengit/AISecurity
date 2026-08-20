# Build Record — pin the Rust deployment target to Package.swift's

| | |
|---|---|
| **Date** | 2026-08-19 |
| **Author / session** | Claude Fable 5 (Claude Code) |
| **Branch** | main |
| **Status** | COMPLETE |

## 1. Plan
- [x] One-sentence statement: stop shipping a `.a` whose objects are marked as
      needing a newer macOS than the app declares support for.
- [x] Blast radius: `build-rust.sh` only. No source change. Affects what the
      linked binary claims it can run on — so it is a compatibility fix, not
      cosmetic.
- [x] Characterized before changing, and it moved the diagnosis: the previous
      record blamed "the Rust toolchain default". Reading the actual objects
      showed **Rust's own codegen was never the problem** — its `.rcgu.o`
      objects are `minos 11.0`, comfortably under 13.0. The offenders are the
      C/asm objects that ride in through build scripts (aws-lc/ring crypto,
      sqlite3), compiled by `cc`, which defaults to the HOST SDK: `minos 26.5`.
- [x] Verification defined up front: the C object reports `minos 13.0`, and a
      forced relink emits zero deployment-target warnings.

## 2. Build
- [x] `MACOSX_DEPLOYMENT_TARGET` exported before `cargo build`, **derived from
      `Package.swift`** rather than hardcoded, so the two cannot drift. If the
      platform line stops parsing the script says so loudly on stderr instead
      of silently reverting to host defaults.
- [x] Security question: this is a correctness/compatibility fix, and it makes
      the shipped artifact's claim TRUE. The crypto objects (aws-lc, ring) were
      the ones mismarked — precisely the code you least want the loader
      guessing about on an older OS.

## 3. Debug
- [x] Reproduced: ~20 `ld: warning: object file ... was built for newer 'macOS'
      version (26.5) than being linked (13.0)` on every link.
- [x] Read the actual objects rather than the warning's wording:
      `otool -l` on both a C object and a Rust object separated the two, which
      is what corrected the diagnosis.
- [x] Class: **a build that inherits the host's SDK ships a binary whose
      declared minimum is a guess.** It reproduces on any machine whose macOS
      differs from the declared target — i.e. it would have looked "fine" on a
      macOS 13 build box and broken silently on this one.

## 4. Verify
- [x] `minos` on the C object: **26.5 -> 13.0**.
- [x] Forced relink (removed the binary, touched a source): `Build complete!
      (18.54s)` with **0** deployment-target warnings and **0** `ld` warnings
      of any kind, down from ~20.
- [x] Regression guard: the warnings themselves are the guard — they return the
      moment the export is removed, and `build-rust.sh` now prints the target
      it used on every run, so a silent revert is visible.

## 5. Close Out
- [x] Full gate green: `./scripts/smoke.sh` -> `9 passed, 0 failed, 5 skipped — GREEN`
- [x] Scrap Sweep: `/tmp/ffiprobe`, `/tmp/p2` probe dirs removed.
- [x] Knowledge layer: this record corrects the previous one's diagnosis
      (which named the Rust toolchain); the earlier record's addendum stands as
      written but the cause is stated correctly here.

## Skipped items — visible, never silent
- **Not verified on an actual macOS 13 machine.** This makes the metadata
  honest; it does not prove the binary runs there. That belongs to the release
  gate's fresh-clone-on-a-clean-machine step.

## Evidence log
```
BEFORE
  C/asm object  (cpucap.o, aws-lc)      platform 1   minos 26.5   sdk 26.5
  Rust object   (addr2line .rcgu.o)     platform 1   minos 11.0   sdk n/a
  Package.swift                         platforms: [.macOS(.v13)]
  swift build -c release                ~20x "built for newer 'macOS' version"

AFTER  (MACOSX_DEPLOYMENT_TARGET=13.0, derived from Package.swift)
  C/asm object  (cpucap.o)              minos 13.0   sdk 26.5
  ==> Deployment target: macOS 13.0 (from Package.swift)
  swift build -c release                Build complete! (18.54s)
  deployment-target warnings: 0
  other ld warnings: 0
```
