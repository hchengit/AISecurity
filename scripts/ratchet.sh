#!/usr/bin/env bash
# Debt ratchet — counted metrics that may only go DOWN
# (docs/BUILD-PROCEDURE.md, Phase 0).
#
# Baselines live in scripts/ratchet-baseline.txt, committed. Any RISE fails.
# A DROP is reported and the baseline should be lowered in the same change —
# that is the whole mechanism: debt is allowed to shrink, never to grow back.
#
#   ./scripts/ratchet.sh              check; AUTO-LOWERS the baseline on a drop
#   ./scripts/ratchet.sh --check-only  check only, never write (CI, smoke)
#   ./scripts/ratchet.sh --update      rewrite ALL baselines, including UP
#
# THE DROP SELF-CORRECTS, THE RISE NEVER DOES. That asymmetry is not a
# convenience — it is what a ratchet IS. Lowering the baseline when a number
# falls is always safe: it locks in the improvement. Raising it silently would
# erase the mechanism, so a rise is always RED and always needs a human to say
# why. The pre-commit hook runs this and stages the lowered baseline, so the
# improvement lands in the same commit that earned it without anyone having to
# remember.
#
# WHAT IS DELIBERATELY NOT COUNTED, and why (a counter that is mostly
# legitimate noise gets ignored the first time it blocks someone, and then it
# guards nothing):
#   * total `unsafe` — all of it lives in security-core-ffi, the C ABI
#     boundary, where it is structural. We count unsafe OUTSIDE that crate.
#   * total unwrap/expect — 85% sit inside #[cfg(test)], where they are
#     idiomatic. We count only what precedes the first #[cfg(test)].
set -uo pipefail
cd "$(dirname "$0")/.."
BASE="scripts/ratchet-baseline.txt"
RS_FILES() { find SecurityCore/crates -name '*.rs' -not -path '*/target/*'; }
SW_FILES() { find Sources -name '*.swift' 2>/dev/null; }

count_allow()      { RS_FILES | tr '\n' '\0' | xargs -0 grep -h '#\[allow(' 2>/dev/null | wc -l | tr -d ' '; }
count_unsafe_out() { RS_FILES | grep -v 'security-core-ffi' | tr '\n' '\0' | xargs -0 grep -h 'unsafe' 2>/dev/null | wc -l | tr -d ' '; }
# grep -c prints 0 AND exits 1 when there are no matches, so `|| echo 0`
# would emit a second line. Take the first line and nothing else.
count_advisories() { grep -cE '^\s*"RUSTSEC' SecurityCore/deny.toml 2>/dev/null | head -1; }
count_swift_try()  { SW_FILES | tr '\n' '\0' | xargs -0 grep -h 'try?' 2>/dev/null | wc -l | tr -d ' '; }

count_unwrap_prod() {
  local tot=0
  while IFS= read -r f; do
    local cut n
    cut=$(grep -n '#\[cfg(test)\]' "$f" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "$cut" ]; then n=$(head -n "$cut" "$f" | grep -cE '\.(unwrap|expect)\(')
    else n=$(grep -cE '\.(unwrap|expect)\(' "$f" 2>/dev/null); fi
    tot=$((tot + n))
  done < <(RS_FILES)
  echo "$tot"
}
big_files() { # $1 = producer fn
  local n big=0
  while IFS= read -r f; do n=$(wc -l < "$f" | tr -d ' '); [ "$n" -gt 800 ] && big=$((big+1)); done < <($1)
  echo "$big"
}
max_loc() {
  local n max=0
  while IFS= read -r f; do n=$(wc -l < "$f" | tr -d ' '); [ "$n" -gt "$max" ] && max=$n; done < <($1)
  echo "$max"
}

declare -a NAMES=(
  rust_allow rust_unsafe_outside_ffi rust_unwrap_prod rust_accepted_advisories
  rust_files_over_800 rust_max_loc swift_try_optional swift_files_over_800 swift_max_loc
)
current() {
  case "$1" in
    rust_allow)                echo "$(count_allow)" ;;
    rust_unsafe_outside_ffi)   echo "$(count_unsafe_out)" ;;
    rust_unwrap_prod)          echo "$(count_unwrap_prod)" ;;
    rust_accepted_advisories)  echo "$(count_advisories)" ;;
    rust_files_over_800)       echo "$(big_files RS_FILES)" ;;
    rust_max_loc)              echo "$(max_loc RS_FILES)" ;;
    swift_try_optional)        echo "$(count_swift_try)" ;;
    swift_files_over_800)      echo "$(big_files SW_FILES)" ;;
    swift_max_loc)             echo "$(max_loc SW_FILES)" ;;
  esac
}

MODE="${1:-auto}"
if [ "$MODE" = "--update" ]; then
  { echo "# Debt ratchet baselines — these may only go DOWN."
    echo "# Regenerate with ./scripts/ratchet.sh --update, in the SAME change that"
    echo "# reduced the number, and say which counter moved in the commit message."
    for n in "${NAMES[@]}"; do echo "$n=$(current "$n")"; done
  } > "$BASE"
  echo "baseline written to $BASE:"; grep -v '^#' "$BASE" | sed 's/^/  /'
  exit 0
fi

[ -f "$BASE" ] || { echo "no baseline — run ./scripts/ratchet.sh --update"; exit 1; }
FAIL=0; DROPPED=0
printf "  %-28s %8s %8s\n" "counter" "base" "now"
for n in "${NAMES[@]}"; do
  b=$(grep -E "^$n=" "$BASE" | cut -d= -f2)
  c=$(current "$n")
  b=${b:-0}
  if [ "$c" -gt "$b" ]; then
    printf "  \033[31m%-28s %8s %8s  +%s RISEN\033[0m\n" "$n" "$b" "$c" "$((c-b))"; FAIL=1
  elif [ "$c" -lt "$b" ]; then
    printf "  \033[32m%-28s %8s %8s  -%s (lower the baseline)\033[0m\n" "$n" "$b" "$c" "$((b-c))"; DROPPED=1
  else
    printf "  %-28s %8s %8s\n" "$n" "$b" "$c"
  fi
done
if [ "$FAIL" -ne 0 ]; then
  echo; echo "RATCHET: RED — a counter rose. Reduce it, or state in the commit why the"
  echo "debt is accepted and raise the baseline deliberately (never silently)."
  exit 1
fi
if [ "$DROPPED" -ne 0 ] && [ "$MODE" != "--check-only" ]; then
  # lock the improvement in, now, so it cannot quietly re-inflate later
  { echo "# Debt ratchet baselines — these may only go DOWN."
    echo "# Lowered automatically when a counter falls; a RISE is always RED and"
    echo "# needs a human to say why. Regenerate deliberately with --update."
    for n in "${NAMES[@]}"; do echo "$n=$(current "$n")"; done
  } > "$BASE"
  echo
  echo "RATCHET: GREEN — a counter improved, baseline LOWERED automatically."
  echo "  $BASE is updated; commit it with this change."
elif [ "$DROPPED" -ne 0 ]; then
  echo; echo "RATCHET: GREEN — a counter improved (baseline not written: --check-only)."
else
  echo; echo "RATCHET: GREEN"
fi
exit 0
