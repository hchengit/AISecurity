# scripts/lib/harden-env.sh — environment isolation for the smoke gate.
# Sourced from scripts/smoke.sh (see the header and cross-references there and
# in docs/build-records/2026-09-25-smoke-gate-env-isolation.md).
#
# The caller's environment is untrusted input to a security gate: inherited
# variables can otherwise select which toolchain runs (HOME, PATH, RUSTUP_*)
# or change what the real toolchain does once running (e.g. a substitute test
# runner). Reduce the environment to a fixed allowlist so an unknown variable
# is dropped by default — a future redirect variable is covered without being
# named. Allowlist, never denylist.
#
# Uses only shell builtins and absolute /usr/bin/id, so it needs no PATH lookup
# before PATH is trusted. The account home comes from getpwnam via ~user, which
# ignores a hostile inherited HOME.
#
# ONE DELIBERATE, REVERSIBLE BEHAVIOUR CHANGE: MACSEC_* env overrides are
# dropped, so the gate reflects on-disk ~/.mac-security/config.toml rather than
# a caller's transient environment. For a security gate this is the safer
# default; reverse by adding MACSEC_* to the allowlist below.
__he_user=$(/usr/bin/id -un)
eval "__he_home=~${__he_user}"
for __he_v in $(compgen -e 2>/dev/null); do
  case "$__he_v" in
    HOME|USER|LOGNAME|TERM) : ;;
    *) builtin unset "$__he_v" 2>/dev/null || true ;;
  esac
done
builtin export HOME="$__he_home" USER="$__he_user" LOGNAME="$__he_user"
builtin export PATH="$__he_home/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin"
builtin unset __he_user __he_home __he_v
