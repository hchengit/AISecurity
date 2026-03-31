#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  AISecurity — Installer
#  Builds, installs the .app bundle, and sets up a LaunchAgent for auto-start.
#
#  Usage: bash install.sh [--install-dir /path/to/dir]
#
#  Options:
#    --install-dir DIR   Install .app to DIR instead of /Applications
#
#  Environment variables:
#    MACSEC_INSTALL_DIR  Same as --install-dir (flag takes precedence)
# ─────────────────────────────────────────────────────────────────────────────

set -e

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()     { echo -e "${BLUE}[install]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── Parse arguments ──────────────────────────────────────────────────────────
INSTALL_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        *)
            warn "Unknown option: $1"
            shift
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DIR="${MACSEC_SECURITY_DIR:-$HOME/.mac-security}"
INSTALL_DIR="${INSTALL_DIR:-${MACSEC_INSTALL_DIR:-/Applications}}"
APP_NAME="AISecurity.app"
AGENT_LABEL="com.aisecurity.menubar"
AGENT_PLIST="$HOME/Library/LaunchAgents/${AGENT_LABEL}.plist"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║     AISecurity — Installer                   ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
log "Install dir: $INSTALL_DIR"
log "Security dir: $SECURITY_DIR"

# Stop existing instance
log "Stopping any running instance..."
launchctl unload "$AGENT_PLIST" 2>/dev/null || true
pkill -f "AISecurity-bin" 2>/dev/null || true
sleep 1
success "Cleared"

# Create security directories
log "Creating security directories..."
mkdir -p "$SECURITY_DIR/logs" "$SECURITY_DIR/quarantine"
success "Directories: $SECURITY_DIR"

# Generate default config.toml if it doesn't exist
CONFIG_FILE="$SECURITY_DIR/config.toml"
if [ ! -f "$CONFIG_FILE" ]; then
    log "Generating default config.toml..."
    if [ -f "$SCRIPT_DIR/config.toml.example" ]; then
        cp "$SCRIPT_DIR/config.toml.example" "$CONFIG_FILE"
        success "Config: $CONFIG_FILE (from template)"
    else
        warn "config.toml.example not found — using built-in defaults"
    fi
else
    success "Config: $CONFIG_FILE (existing, not overwritten)"
fi

# Build Rust security-core static library
log "Building Rust security-core (Release)..."
cd "$SCRIPT_DIR"
bash build-rust.sh release 2>&1 | tail -5

# Build Swift app
log "Building AISecurity (Release)..."
swift build -c release 2>&1 | tail -5
BUILD_PATH="$SCRIPT_DIR/.build/release/AISecurity"
[ -f "$BUILD_PATH" ] || error "Build failed — binary not found at $BUILD_PATH"
success "Built: $BUILD_PATH"

# Create .app bundle
log "Creating app bundle..."
APP_BUNDLE="$INSTALL_DIR/$APP_NAME"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"
cp "$BUILD_PATH" "$APP_BUNDLE/Contents/MacOS/AISecurity-bin"
chmod +x "$APP_BUNDLE/Contents/MacOS/AISecurity-bin"

cp "$SCRIPT_DIR/Sources/AISecurity/Info.plist" "$APP_BUNDLE/Contents/"
if [ -f "$SCRIPT_DIR/Sources/AISecurity/AppIcon.icns" ]; then
    cp "$SCRIPT_DIR/Sources/AISecurity/AppIcon.icns" "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
    success "App icon copied"
fi
xattr -cr "$APP_BUNDLE"

# Code-sign the bundle with entitlements so macOS recognises it for FDA
log "Code-signing app bundle..."
# Prefer Apple Development cert (stable identity keeps FDA grants across rebuilds).
# Falls back to ad-hoc if no cert is found.
SIGN_ID=$(security find-identity -v -p codesigning 2>/dev/null | head -1 | sed 's/.*"\(.*\)"/\1/')
if [ -n "$SIGN_ID" ]; then
    codesign --force --deep --sign "$SIGN_ID" \
        --entitlements "$SCRIPT_DIR/AISecurity.entitlements" \
        "$APP_BUNDLE" 2>&1 || warn "Signing with '$SIGN_ID' failed"
    success "Signed with: $SIGN_ID"
else
    codesign --force --deep --sign - \
        --entitlements "$SCRIPT_DIR/AISecurity.entitlements" \
        "$APP_BUNDLE" 2>&1 || warn "Ad-hoc signing failed — FDA may not persist across rebuilds"
    warn "No developer cert found — using ad-hoc signing (FDA grants won't survive rebuilds)"
fi
success "Installed: $APP_BUNDLE"

# Create LaunchAgent — uses `open -W -a` so macOS launches it as a proper
# .app bundle (reads Info.plist, honours LSUIElement, registers for FDA).
# Running the binary directly causes procRole="Non UI" and the menu bar
# icon disappears.
log "Setting up LaunchAgent..."
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$AGENT_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/open</string>
        <string>-W</string>
        <string>-a</string>
        <string>${APP_BUNDLE}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>StandardOutPath</key>
    <string>${SECURITY_DIR}/logs/launchagent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${SECURITY_DIR}/logs/launchagent-stderr.log</string>
</dict>
</plist>
EOF
success "LaunchAgent: $AGENT_PLIST"

# Load and start
log "Starting AISecurity..."
launchctl load "$AGENT_PLIST" 2>/dev/null
launchctl start "$AGENT_LABEL" 2>/dev/null
sleep 3

if pgrep -f "AISecurity" > /dev/null 2>&1; then
    success "AISecurity is running"
else
    warn "Process not detected — try: open -a AISecurity"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Installation complete!                                  ║"
echo "║                                                          ║"
echo "║  The shield icon should appear in your menu bar.         ║"
echo "║  AISecurity will auto-start on login.                    ║"
echo "║                                                          ║"
echo "║  Config:  $SECURITY_DIR/config.toml"
echo "║  Logs:    $SECURITY_DIR/logs/"
echo "║                                                          ║"
echo "║  Commands:                                               ║"
echo "║    Start:  launchctl start $AGENT_LABEL"
echo "║    Stop:   launchctl stop $AGENT_LABEL"
echo "║                                                          ║"
echo "║  IMPORTANT: Grant Full Disk Access to AISecurity.app in  ║"
echo "║  System Settings > Privacy & Security > Full Disk Access ║"
echo "║  for Mail and Messages scanning to work.                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
