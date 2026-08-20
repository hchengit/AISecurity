#!/usr/bin/env bash
# Build the Rust SecurityCore static library and copy artifacts to CSecurityCore/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$SCRIPT_DIR/SecurityCore"
OUT_DIR="$SCRIPT_DIR/CSecurityCore"

PROFILE="${1:-release}"
if [ "$PROFILE" = "debug" ]; then
    CARGO_FLAG=""
    TARGET_DIR="$RUST_DIR/target/debug"
else
    CARGO_FLAG="--release"
    TARGET_DIR="$RUST_DIR/target/release"
fi

# MATCH SWIFT'S DEPLOYMENT TARGET, derived from Package.swift so the two
# cannot drift. Without this, the C/asm objects that ride in through build
# scripts (aws-lc/ring's crypto, sqlite3) are compiled by `cc` against the
# HOST SDK: on this machine that stamped them `minos 26.5` while Package.swift
# declares .macOS(.v13). Rust's own codegen was never the problem (it defaults
# to 11.0) — the C dependencies were, and the app would have claimed macOS 13
# support while carrying objects marked as needing 26.5.
SWIFT_MIN="$(sed -n 's/.*\.macOS(\.v\([0-9][0-9]*\)).*/\1/p' "$SCRIPT_DIR/Package.swift" | head -1)"
if [ -n "$SWIFT_MIN" ]; then
    export MACOSX_DEPLOYMENT_TARGET="${SWIFT_MIN}.0"
    echo "==> Deployment target: macOS $MACOSX_DEPLOYMENT_TARGET (from Package.swift)"
else
    echo "==> WARNING: could not read .macOS(.vNN) from Package.swift —" >&2
    echo "    building against the host SDK, which will mismatch at link time." >&2
fi

echo "==> Building SecurityCore ($PROFILE)..."
export PATH="$HOME/.cargo/bin:$PATH"
(cd "$RUST_DIR" && cargo build $CARGO_FLAG -p security-core-ffi)

echo "==> Generating C header..."
(cd "$RUST_DIR" && cbindgen --crate security-core-ffi --output "$OUT_DIR/include/security_core.h")

echo "==> Copying static library..."
mkdir -p "$OUT_DIR/lib" "$OUT_DIR/include"
cp "$TARGET_DIR/libsecurity_core_ffi.a" "$OUT_DIR/lib/"

# Force the Swift build to relink against the new .a. SPM does NOT treat this prebuilt
# static library as a tracked input, so a `swift build` with no Swift-source changes will
# happily reuse a cached link against the OLD .a — silently shipping stale Rust logic.
# Removing the linked product guarantees the next `swift build` relinks.
echo "==> Invalidating stale Swift link (forces relink against new .a)..."
rm -f "$SCRIPT_DIR/.build/release/AISecurity" "$SCRIPT_DIR/.build/debug/AISecurity" 2>/dev/null || true

echo "==> Done."
echo "    Header:  $OUT_DIR/include/security_core.h"
echo "    Library:  $OUT_DIR/lib/libsecurity_core_ffi.a"
