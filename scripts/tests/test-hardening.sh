#!/bin/bash
# Benign proof that scripts/lib/harden-env.sh isolates the smoke gate from the
# caller's environment (docs/build-records/2026-09-25-smoke-gate-env-isolation.md).
#
# No adversarial fixtures. It sets harmless decoy values in a subshell, sources
# the helper, and confirms the decoys do NOT survive and that HOME/PATH are the
# account's own fixed values. Because the scrub is allowlist-based, proving one
# arbitrary variable is dropped proves every non-allowlisted variable is —
# the named decoys below are illustrative, not exhaustive.
#
#   scripts/tests/test-hardening.sh            test scripts/lib/harden-env.sh
#   scripts/tests/test-hardening.sh <path>     test another copy (A/B drills)
set -uo pipefail
cd "$(dirname "$0")/../.."
HELPER="${1:-scripts/lib/harden-env.sh}"
[ -f "$HELPER" ] || { echo "RESULT: FAILED — no helper at $HELPER"; exit 1; }

FAILED=0
say(){ printf '   %-8s %s\n' "$1" "$2"; }
ok(){  say ok "$1"; }
no(){  say "NOT OK" "$1"; FAILED=1; }

ACCT_HOME=$(eval "echo ~$(/usr/bin/id -un)")

# Source the helper in a subshell seeded with benign decoys. The decoys are
# non-existent paths; the only thing under test is whether they survive.
OUT=$(
  export MARKER_CANARY="present" \
         RUSTUP_TOOLCHAIN="/nonexistent/decoy" \
         CARGO_HOME="/nonexistent/decoy" \
         PYTHONPATH="/nonexistent/decoy" \
         CDPATH="/nonexistent/decoy" \
         HOME="/nonexistent/decoy-home" \
         PATH="/nonexistent/decoy-bin:/usr/bin:/bin"
  . "$HELPER" >/dev/null 2>&1
  printf 'MARKER=%s\n'     "${MARKER_CANARY:-<gone>}"
  printf 'RUSTUP=%s\n'     "${RUSTUP_TOOLCHAIN:-<gone>}"
  printf 'CARGO_HOME=%s\n' "${CARGO_HOME:-<gone>}"
  printf 'PYTHONPATH=%s\n' "${PYTHONPATH:-<gone>}"
  printf 'CDPATH=%s\n'     "${CDPATH:-<gone>}"
  printf 'HOME=%s\n'       "$HOME"
  printf 'PATH=%s\n'       "$PATH"
)

echo "== harden-env isolation test =="
echo "   helper  $HELPER"
echo "$OUT" | grep -q 'MARKER=<gone>'     && ok "a caller-set marker does not survive"   || no "marker survived the scrub"
echo "$OUT" | grep -q 'RUSTUP=<gone>'     && ok "RUSTUP_TOOLCHAIN does not survive"       || no "RUSTUP_TOOLCHAIN survived"
echo "$OUT" | grep -q 'CARGO_HOME=<gone>' && ok "CARGO_HOME does not survive"             || no "CARGO_HOME survived"
echo "$OUT" | grep -q 'PYTHONPATH=<gone>' && ok "PYTHONPATH does not survive"             || no "PYTHONPATH survived"
echo "$OUT" | grep -q 'CDPATH=<gone>'     && ok "CDPATH does not survive"                 || no "CDPATH survived"
echo "$OUT" | grep -q "HOME=$ACCT_HOME"   && ok "HOME reset to the account home"          || no "HOME not reset ($(echo "$OUT" | grep '^HOME='))"
echo "$OUT" | grep -qE "PATH=$ACCT_HOME/\.cargo/bin:/usr/bin:/bin" && ok "PATH reset to the fixed gate PATH" || no "PATH not fixed ($(echo "$OUT" | grep '^PATH='))"

echo
if [ "$FAILED" -ne 0 ]; then
  echo "RESULT: FAILED — the caller's environment leaked into the gate."
  exit 1
fi
echo "RESULT: PASSED — the gate's environment is the account's, not the caller's"
