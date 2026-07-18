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
