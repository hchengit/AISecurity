#!/bin/bash
# Regression test for the smoke gate's zero-suite guard (defect: 2026-09-23).
#
# THE DEFECT: smoke.sh reported
#   PASS  cargo test --workspace --exclude security-linux — 0 suites, 0 passed, 0 failed
# for a run in which no test executed. awk's END block runs on empty input, so
# `grep '^test result:' | awk` over zero matches still printed a well-formed
# "0 suites, 0 passed, 0 failed" that the pass test accepted. The class:
# deriving a verdict from parsed output without first asserting any output was
# parsed. The gate must read RED when no suite ran. Law 4 / Law 5.
#
# HOW (post-isolation): the gate now reduces its environment to a fixed
# allowlist (scripts/lib/harden-env.sh), so a toolchain can no longer be hidden
# by emptying HOME/PATH — that is the isolation working. To reach the "no suite
# can run" condition legitimately, this copies the gate into a throwaway tree
# with its own minimal harden-env.sh that presents a toolchain-free PATH, i.e.
# a machine with no Rust installed, and asserts the gate fails closed. No fake
# tools are planted and nothing is hijacked — it is the fresh-machine scenario.
#
#   scripts/tests/test-smoke.sh            test scripts/smoke.sh
#   scripts/tests/test-smoke.sh <path>     test another copy (A/B drills)
#
# Not run by smoke.sh — a gate testing its own copy is circular. CI runs it via
# the gate-selftests job in .github/workflows/ci.yml.
set -uo pipefail
cd "$(dirname "$0")/../.."
TARGET="${1:-scripts/smoke.sh}"
[ -f "$TARGET" ] || { echo "FAIL  no target at $TARGET"; exit 1; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"
mkdir -p "$ROOT/scripts/lib" "$ROOT/SecurityCore" "$ROOT/home"
cp "$TARGET" "$ROOT/scripts/smoke.sh" && chmod +x "$ROOT/scripts/smoke.sh"
# Present a toolchain-free environment through the SAME mechanism the gate
# uses. If the target sources harden-env.sh (the current gate does), it gets
# this cargo-free PATH; if it does not (an older A/B target), it inherits the
# runner's env and still runs cargo test against this empty SecurityCore, which
# yields zero result lines just the same. Either way: no suite can run.
cat > "$ROOT/scripts/lib/harden-env.sh" <<HE
builtin export HOME="$ROOT/home"
builtin export PATH="/usr/bin:/bin:/usr/sbin:/sbin"
HE

OUT=$(cd "$ROOT" && bash scripts/smoke.sh 2>&1); RC=$?
TESTLINE=$(printf '%s\n' "$OUT" | grep -E 'cargo test --workspace' | head -1 \
  | sed 's/\x1b\[[0-9;]*m//g; s/^ *//')

FAILED=0
say(){ printf '   %-8s %s\n' "$1" "$2"; }
ok(){  say ok "$1"; }
no(){  say "NOT OK" "$1"; FAILED=1; }

echo "== smoke-gate zero-suite regression test =="
echo "   target     $TARGET"
echo "   condition  no Rust toolchain reachable (cargo not on PATH)"
echo "   observed   ${TESTLINE:-<no cargo test line at all>}"
case "$TESTLINE" in
  *"NO suites ran"*) ok "names zero suites ran";;
  *)                 no "does not name zero suites ran";;
esac
case "$TESTLINE" in
  PASS*) no "reports PASS for tests that never ran";;
  *)     ok "does not report PASS";;
esac
[ "$RC" -ne 0 ] && ok "gate exits non-zero (RED)" || no "gate exits 0"
printf '%s\n' "$OUT" | grep -q 'RESULT:.*RED' && ok "RESULT line reads RED" || no "RESULT does not read RED"

echo
if [ "$FAILED" -ne 0 ]; then
  echo "RESULT: regression test FAILED — the gate did not fail closed with no toolchain."
  echo "        A gate that greens without running its tests is the 2026-09-23 defect."
  exit 1
fi
echo "RESULT: PASSED — no toolchain => the gate reads RED, not a false green"
