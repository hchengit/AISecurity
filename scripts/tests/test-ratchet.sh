#!/bin/bash
# Regression test for the debt ratchet's empty-discovery bug (2026-09-25).
#
# THE BUG: the counters derive from find-based discovery (RS_FILES/SW_FILES).
# If discovery returns nothing — a crate directory renamed or moved — every
# counter reads 0. 0 is below baseline, so the ratchet reports "a counter
# improved" and, outside --check-only, rewrites the baseline to 0. Empty is
# not merely indistinguishable from success there; it reads as PROGRESS, and
# the mechanism erases itself. Law 4 — alert on the absence of success.
#
# HOW THIS TESTS IT: copy the ratchet and a baseline into a throwaway tree
# whose SecurityCore/ and Sources/ are EMPTY, so discovery finds nothing.
# A correct ratchet must FAIL there and must NOT overwrite the baseline.
#
#   scripts/tests/test-ratchet.sh            test scripts/ratchet.sh
#   scripts/tests/test-ratchet.sh <path>     test another copy (A/B drills)
set -uo pipefail
cd "$(dirname "$0")/../.."
TARGET="${1:-scripts/ratchet.sh}"
[ -f "$TARGET" ] || { echo "RESULT: FAILED — no target at $TARGET"; exit 1; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
# a tree with the directories the ratchet searches, all EMPTY of source
mkdir -p "$WORK/scripts" "$WORK/SecurityCore/crates" "$WORK/Sources"
cp "$TARGET" "$WORK/scripts/ratchet.sh" && chmod +x "$WORK/scripts/ratchet.sh"
# a real, non-zero baseline — the value the bug would overwrite with zeros
BASE="$WORK/scripts/ratchet-baseline.txt"
cat > "$BASE" <<'BEOF'
# baseline
rust_allow=11
rust_unsafe_outside_ffi=0
rust_unwrap_prod=45
rust_accepted_advisories=0
rust_files_over_800=5
rust_max_loc=1456
swift_try_optional=160
swift_files_over_800=3
swift_max_loc=1686
BEOF
BEFORE=$(cat "$BASE")

FAILED=0
say()  { printf '   %-8s %s\n' "$1" "$2"; }
pass() { say "ok" "$1"; }
fail() { say "NOT OK" "$1"; FAILED=1; }

echo "== ratchet empty-discovery regression test =="
echo "   target  $TARGET"
echo "── discovery finds no source files — this is a measurement failure, not progress"

# default (auto) mode: this is the dangerous path — it auto-lowers on a drop
OUT=$(cd "$WORK" && ./scripts/ratchet.sh 2>&1); RC=$?
AFTER=$(cat "$BASE")

[ "$RC" -ne 0 ] && pass "auto mode exits non-zero" || fail "auto mode exits 0 on empty discovery"
printf '%s\n' "$OUT" | grep -qiE 'improved|GREEN' && fail "reports improvement/GREEN on empty discovery" || pass "does not report improvement"
[ "$BEFORE" = "$AFTER" ] && pass "baseline left intact" || fail "baseline was OVERWRITTEN (zeroed) on empty discovery"

# --check-only mode: used by CI and the smoke gate
OUT2=$(cd "$WORK" && ./scripts/ratchet.sh --check-only 2>&1); RC2=$?
[ "$RC2" -ne 0 ] && pass "--check-only exits non-zero" || fail "--check-only greens on empty discovery"

# --update mode: the MOST dangerous path — it rewrites the baseline. Spec R3
# requires the assertion here too. This is the exact case that zeroed the
# baseline before the fix, so the test must lock it in.
OUT3=$(cd "$WORK" && ./scripts/ratchet.sh --update 2>&1); RC3=$?
AFTER3=$(cat "$BASE")
[ "$RC3" -ne 0 ] && pass "--update exits non-zero" || fail "--update greens on empty discovery"
[ "$BEFORE" = "$AFTER3" ] && pass "--update left baseline intact" || fail "--update OVERWROTE the baseline (zeroed) on empty discovery"

echo
if [ "$FAILED" -ne 0 ]; then
  echo "RESULT: FAILED — the ratchet trusted a measurement that never happened."
  echo "        Empty discovery read as debt eliminated. Do not paper over it."
  exit 1
fi
echo "RESULT: PASSED — empty discovery is a hard failure, baseline untouched"
