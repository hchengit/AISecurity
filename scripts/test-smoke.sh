#!/usr/bin/env bash
# Regression test for the smoke gate's OWN verdict logic.
#
# WHY THIS EXISTS: on 2026-09-23 scripts/smoke.sh reported
#   PASS  cargo test --workspace --exclude security-linux — 0 suites, 0 passed, 0 failed
# for a run in which cargo was not on PATH and no test ever executed. awk's
# END block runs on empty input, so `grep | awk` over zero matches still
# printed a well-formed summary containing " 0 failed", which the pass test
# accepted. The class: deriving a verdict from parsed output without first
# asserting that any output was parsed. Law 4 — alert on the absence of
# success. Law 5 — encode the lesson as a gate, so it cannot come back.
#
# WHAT IT DOES: drives the gate with a deliberately absent toolchain and
# asserts it reads RED and names zero suites. On the pre-fix smoke.sh this
# test FAILS, which is the point.
#
#   ./scripts/test-smoke.sh                     test scripts/smoke.sh
#   ./scripts/test-smoke.sh scripts/.other.sh   test another copy (A/B drills)
#
# NOT run by smoke.sh itself — that would recurse. Wire it into CI beside the
# guard tests (.github/workflows/claude-guard.yml) — owner-approved change.
set -uo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:-scripts/smoke.sh}"
[ -x "$TARGET" ] || { echo "FAIL  no executable target at $TARGET"; exit 1; }

SANDBOX_HOME=$(mktemp -d)
trap 'rm -rf "$SANDBOX_HOME"' EXIT

echo "== smoke-gate regression test =="
echo "   target        $TARGET"
echo "   condition     toolchain absent (empty HOME, PATH without cargo)"

OUT=$(env HOME="$SANDBOX_HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        "./$TARGET" 2>&1); RC=$?
TESTLINE=$(echo "$OUT" | grep -E 'cargo test --workspace' | head -1 | sed 's/\x1b\[[0-9;]*m//g; s/^ *//')

FAILED=0
check() { # check <description> <condition-result>
  if [ "$2" -eq 0 ]; then printf '   \033[32mok\033[0m    %s\n' "$1"
  else printf '   \033[31mNOT OK\033[0m %s\n' "$1"; FAILED=1; fi
}

echo "   observed      ${TESTLINE:-<no cargo test line at all>}"

echo "$TESTLINE" | grep -q 'NO suites ran'; check "names zero suites ran" $?
echo "$TESTLINE" | grep -qv '^PASS'; check "does not report PASS for tests that never ran" $?
[ "$RC" -ne 0 ]; check "gate exits non-zero (RED)" $?
echo "$OUT" | grep -q 'RESULT:.*RED'; check "RESULT line reads RED" $?

echo
if [ "$FAILED" -eq 0 ]; then
  echo "RESULT: regression test PASSED — the gate fails closed on a toolchain it cannot run"
  exit 0
else
  echo "RESULT: regression test FAILED — the gate reported success for work it did not do"
  echo "        this is the 2026-09-23 defect, back again. Do not paper over it."
  exit 1
fi
