#!/bin/bash -p
# AISecurity smoke test — the session-exit gate (docs/BUILD-PROCEDURE.md Phase 0).
#
# Probes every surface the system claims to provide with DISTINCT CONTENT
# MARKERS, not "the port answered", and echoes the active configuration so a
# green run cannot hide a wrong-config run. Exits non-zero on any failure; the
# last line is always a RESULT summary.
#
#   ./scripts/smoke.sh          full gate (tests + clippy + deny + probes)
#   ./scripts/smoke.sh --fast   probes only, skip the slow Rust gates
#
# ISOLATE FROM THE CALLER'S ENVIRONMENT FIRST — before cd and before any
# external command. The `-p` on the shebang additionally blocks BASH_ENV and
# imported shell functions from taking effect before this line. Sourced by a
# builtin-only path expansion (${0%/*}) so it needs no PATH lookup — PATH is
# not trusted until the helper resets it. Scope: the documented
# `./scripts/smoke.sh` entry point.
. "${0%/*}/lib/harden-env.sh"
set -uo pipefail
cd "$(dirname "$0")/.."

# The toolchain PATH is now set by lib/harden-env.sh (sourced above), which
# owns the whole environment — not just a PATH prefix. A gate whose verdict
# depends on which shell invoked it is not a gate.

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$1"; SKIP=$((SKIP+1)); }

FAST=0; [ "${1:-}" = "--fast" ] && FAST=1
# security-linux needs libdbus, which exists on the Linux daemon's platform and
# not on macOS. CI builds the whole workspace on ubuntu; locally on a Mac the
# honest gate is "everything that can build here", so the Linux crate is
# excluded rather than reported as a failure it isn't.
WS_ARGS=""
if [ "$(uname -s)" = "Darwin" ]; then
  WS_ARGS="--exclude security-linux"
  echo "  platform    macOS — excluding security-linux (needs libdbus; CI covers it on ubuntu)"
fi
CFG="$HOME/.mac-security/config.toml"
PORT=7459

echo "── configuration (runtime truth, not declared truth) ──────"
echo "  branch      $(git rev-parse --abbrev-ref HEAD) @ $(git rev-parse --short HEAD)"
echo "  rustc       $(rustc --version 2>/dev/null || echo 'not found')"
if [ -f "$CFG" ]; then
  MODE=$(grep -E '^\s*mode\s*=' "$CFG" | head -1 | sed 's/.*=\s*//; s/"//g')
  echo "  config      $CFG (mode=${MODE:-unset})"
else
  echo "  config      $CFG  (ABSENT — running on defaults)"
fi
BYP="$HOME/.mac-security/bypass"
[ -f "$BYP" ] && echo "  bypass      PRESENT — enforcement is relaxed by design; note it, do not 'fix' it"

echo "── Rust core ──────────────────────────────────────────────"
if [ "$FAST" -eq 1 ]; then
  skip "cargo test / clippy / deny (--fast)"
else
  # PROVENANCE IS A VERDICT, NOT A FOOTNOTE. The configuration block echoes a
  # rustc line for a human to read, but an echo cannot fail a gate — "rustc
  # not found" scrolled past while the step below reported PASS. Name the
  # cargo this run will actually use and fail when there is none, so a
  # toolchain resolving somewhere unexpected (HOME is caller-controlled, so
  # $HOME/.cargo/bin is not automatically the real one) lands in the
  # transcript instead of passing silently. Residual noted in
  # docs/build-records/2026-09-23-smoke-gate-fail-closed.md.
  CARGO_BIN=$(command -v cargo 2>/dev/null || true)
  if [ -z "$CARGO_BIN" ]; then
    bad "toolchain — no cargo on PATH; the Rust gates below cannot run"
  else
    ok "toolchain — cargo=$CARGO_BIN rustc=$(rustc --version 2>/dev/null | awk '{print $2}' || echo '?')"
  fi
  # AGGREGATE every result line — do not tail them. A run of 339 tests across
  # six crates showed as "7 passed" when this took the last line only, which
  # is precisely how a whole crate silently not running would look green.
  TOUT=$( (cd SecurityCore && cargo test --workspace $WS_ARGS 2>&1) ); TRC=$?
  # COUNT THE SUITES BEFORE TRUSTING THE SUMMARY. awk's END block runs even on
  # EMPTY input, so `grep | awk` over zero matches still prints a well-formed
  # "0 suites, 0 passed, 0 failed" — which satisfied the old ' 0 failed' test
  # and reported PASS for a run that never happened. A missing cargo did
  # exactly that. The `[ -n "$TSUM" ]` guard meant to catch it could never
  # fire, because TSUM is never empty. Absence of success is the alarm.
  NSUITES=$(echo "$TOUT" | grep -cE '^test result:')
  TSUM=$(echo "$TOUT" | grep -E '^test result:' \
    | awk '{p+=$4; f+=$6; n++} END {printf "%d suites, %d passed, %d failed", n, p, f}')
  if [ "$NSUITES" -eq 0 ]; then
    bad "cargo test --workspace $WS_ARGS — NO suites ran (cargo exit $TRC); the gate could not run the tests it gates on"
    echo "$TOUT" | grep -E 'command not found|^error' | head -4 | sed 's/^/        /'
  elif [ "$TRC" -eq 0 ] && echo "$TSUM" | grep -q ' 0 failed' && ! echo "$TOUT" | grep -q 'FAILED'; then
    ok "cargo test --workspace $WS_ARGS — $TSUM"
  else
    bad "cargo test --workspace $WS_ARGS — $TSUM (cargo exit $TRC)"
    echo "$TOUT" | grep -E '^(test .* FAILED|error)' | head -8 | sed 's/^/        /'
  fi
  if (cd SecurityCore && cargo clippy --workspace $WS_ARGS -- -D warnings >/tmp/cl.$$ 2>&1); then
    ok "clippy --workspace $WS_ARGS -D warnings"
  else bad "clippy"; tail -12 /tmp/cl.$$ | sed 's/^/        /'; fi
  rm -f /tmp/cl.$$
  if command -v cargo-deny >/dev/null 2>&1 || (cd SecurityCore && cargo deny --version >/dev/null 2>&1); then
    if (cd SecurityCore && cargo deny check advisories bans sources >/tmp/dn.$$ 2>&1); then
      ok "cargo deny (advisories bans sources)"
    else bad "cargo deny"; tail -12 /tmp/dn.$$ | sed 's/^/        /'; fi
    rm -f /tmp/dn.$$
  else
    skip "cargo deny (cargo-deny not installed)"
  fi
fi

echo "── Rust↔Swift parity ──────────────────────────────────────"
if [ "$FAST" -eq 1 ]; then skip "cross_validation (--fast)"
elif (cd SecurityCore && cargo test --test cross_validation >/tmp/cv.$$ 2>&1); then
  ok "cross_validation (Rust/Swift parity)"
else bad "cross_validation"; tail -10 /tmp/cv.$$ | sed 's/^/        /'; fi
rm -f /tmp/cv.$$ 2>/dev/null

echo "── agent binaries ─────────────────────────────────────────"
for b in aisec-mcp intent-hook privacy-router ai-exec; do
  P=$(command -v "$b" 2>/dev/null || true)
  if [ -n "$P" ]; then ok "$b on PATH ($P)"; else skip "$b not installed (run ./install.sh)"; fi
done

echo "── loopback policy service :$PORT ─────────────────────────"
if ! curl -s -m 3 "http://127.0.0.1:${PORT}/health" | grep -q '"ok"' ; then
  skip "daemon not answering /health on 127.0.0.1:${PORT} (start the app / LaunchAgent)"
else
  ok "GET /health -> ok:true"
  # NOTE: /intent/verify answers 403 on a DENY, so -f (fail-on-4xx) must not
  # be used here — it would turn a correctly-working gate into a smoke failure.
  IV=$(curl -s -m 5 -X POST "http://127.0.0.1:${PORT}/intent/verify" \
        -H 'content-type: application/json' \
        -d '{"current_task":"clean up","proposed_action":"rm -rf /","kind":"shell","agent":"smoke"}' 2>/dev/null || echo "")
  if echo "$IV" | grep -q '"decision"'; then
    ok "POST /intent/verify returns a decision"
    # BYPASS IS A LEGITIMATE STATE, and the daemon is loud about it: the
    # response carries "_bypass":true and matched_rule "bypass". Asserting the
    # deny against an active bypass would be a smoke test reporting a defect
    # that isn't one — read the response, don't pattern-match the symptom.
    if echo "$IV" | grep -q '"_bypass":true'; then
      if echo "$IV" | grep -q '"matched_rule":"bypass"'; then
        skip "deny-path assertion — bypass is ACTIVE and the decision says so"
      else
        bad "allowed under bypass but the decision does not declare it — a silent bypass"
      fi
    elif echo "$IV" | grep -qE '"decision":"(deny|ask)"'; then
      ok "intent_verifier refuses 'rm -rf /'"
    else
      bad "intent_verifier ALLOWED 'rm -rf /' with no bypass — fail-closed is broken"
    fi
  else
    bad "POST /intent/verify gave no decision: ${IV:0:140}"
  fi
  # the mirror: a benign action must NOT be denied. A hardening pass that
  # blocks legitimate work is also a defect (BUILD-PROCEDURE, step 2).
  IV2=$(curl -s -m 5 -X POST "http://127.0.0.1:${PORT}/intent/verify" \
        -H 'content-type: application/json' \
        -d '{"current_task":"check git state","proposed_action":"git status","kind":"shell","agent":"smoke"}' 2>/dev/null || echo "")
  if echo "$IV2" | grep -q '"decision":"deny"'; then
    bad "intent_verifier DENIED 'git status' — legitimate path is gated"
  elif echo "$IV2" | grep -q '"decision"'; then
    ok "intent_verifier permits 'git status'"
  else
    bad "POST /intent/verify (benign) gave no decision"
  fi
  PR=$(curl -s -m 5 -X POST "http://127.0.0.1:${PORT}/privacy/evaluate" \
        -H 'content-type: application/json' \
        -d '{"host":"api.anthropic.com","body":"my aws key is AKIAIOSFODNN7EXAMPLE"}' 2>/dev/null || echo "")  # pragma: allowlist secret
  if echo "$PR" | grep -q '"action"'; then
    ok "POST /privacy/evaluate returns an action"
    if echo "$PR" | grep -q '"action":"allow"' && echo "$PR" | grep -q 'AKIAIOSFODNN7EXAMPLE'; then  # pragma: allowlist secret
      bad "privacy_router ALLOWED a body containing a live-shaped AWS key, unredacted"
    else
      ok "privacy_router did not pass the secret through untouched"
    fi
  else
    bad "POST /privacy/evaluate gave no action: ${PR:0:140}"
  fi
fi

echo "── debt ratchet ───────────────────────────────────────────"
if [ -x scripts/ratchet.sh ]; then
  if scripts/ratchet.sh --check-only >/tmp/rt.$$ 2>&1; then
    ok "ratchet — $(grep -E '^RATCHET' /tmp/rt.$$ | head -1)"
  else
    bad "ratchet — a counted metric rose"; grep -E 'RISEN' /tmp/rt.$$ | sed 's/^/      /'
  fi
  rm -f /tmp/rt.$$
else
  skip "scripts/ratchet.sh missing"
fi

echo "── AI-session guard ───────────────────────────────────────"
# Absence of success is the alarm: if settings.json stops naming guard.py,
# every hook-enforced rule has silently become advisory again.
if grep -q 'guard.py' .claude/settings.json 2>/dev/null; then
  if python3 -m unittest discover -s .claude/hooks -p 'test_*.py' >/tmp/gd.$$ 2>&1; then
    ok "guard wired + $(grep -oE 'Ran [0-9]+ tests' /tmp/gd.$$) green"
  else
    bad "guard tests FAILING: $(grep -E '^(FAIL|ERROR):' /tmp/gd.$$ | head -1)"
  fi
  rm -f /tmp/gd.$$
else
  bad "guard NOT wired — .claude/settings.json does not run .claude/hooks/guard.py"
fi

echo "───────────────────────────────────────────────────────────"
echo "RESULT: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped — $( [ "$FAIL" -eq 0 ] && echo GREEN || echo RED )"
[ "$FAIL" -eq 0 ]
