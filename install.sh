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
AGENT_LABEL="com.aisecurity.shield"
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

# Bundle the portable vault decryptor so "Export Portable Vault..." has a
# canonical copy to ship alongside .vault files. Getting signed into the
# bundle means Fix #6's startup signature check will detect tampering.
if [ -f "$SCRIPT_DIR/Sources/AISecurity/Resources/vault-decrypt.py" ]; then
    cp "$SCRIPT_DIR/Sources/AISecurity/Resources/vault-decrypt.py" "$APP_BUNDLE/Contents/Resources/vault-decrypt.py"
    chmod 0644 "$APP_BUNDLE/Contents/Resources/vault-decrypt.py"
    success "Portable vault decryptor bundled"
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
    warn "To get a stable signing identity: enroll at developer.apple.com"
fi

# Verify code signature
if codesign -v "$APP_BUNDLE" 2>/dev/null; then
    success "Installed: $APP_BUNDLE (signature valid)"
else
    warn "Installed: $APP_BUNDLE (signature INVALID — FDA and menu bar may not work)"
fi

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
    success "AISecurity is running (PID: $(pgrep -f AISecurity-bin | head -1))"
    # Verify the process was launched via open -a (proper GUI role)
    if launchctl list | grep -q "$AGENT_LABEL"; then
        success "LaunchAgent active: $AGENT_LABEL"
    else
        warn "LaunchAgent not in launchctl list — menu bar icon may not appear"
    fi
else
    warn "Process not detected — try: open -a AISecurity"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Phase 15: AI-agent integration (MCP server + Claude Code PreToolUse hook)
#
#  Installs two release binaries under $SECURITY_DIR/bin/:
#    - aisec-mcp       : MCP server relaying tool calls to the daemon on :7459
#    - intent-hook     : Claude Code PreToolUse hook
#
#  Then, if the `claude` CLI is available, registers the MCP server at user
#  scope and merges a PreToolUse hook into ~/.claude/settings.json. Both
#  steps are idempotent — re-running install.sh will not duplicate them.
# ─────────────────────────────────────────────────────────────────────────────
log "Phase 15: Building AI-agent binaries (aisec-mcp, intent-hook)..."
cd "$SCRIPT_DIR/SecurityCore"
if ~/.cargo/bin/cargo build --release -p aisec-mcp -p intent-hook 2>&1 | tail -3; then
    AGENT_BINDIR="$SECURITY_DIR/bin"
    mkdir -p "$AGENT_BINDIR"
    cp "$SCRIPT_DIR/SecurityCore/target/release/aisec-mcp"   "$AGENT_BINDIR/"
    cp "$SCRIPT_DIR/SecurityCore/target/release/intent-hook" "$AGENT_BINDIR/"
    chmod +x "$AGENT_BINDIR/aisec-mcp" "$AGENT_BINDIR/intent-hook"
    # User-facing CLI (bypass on/off/status, daemon status, audit log tail)
    cp "$SCRIPT_DIR/SecurityCore/crates/aisec-mcp/aisec" "$AGENT_BINDIR/aisec"
    chmod +x "$AGENT_BINDIR/aisec"
    success "Installed AI-agent binaries: $AGENT_BINDIR/"
    cd "$SCRIPT_DIR"
else
    warn "AI-agent binary build failed — MCP server + PreToolUse hook not installed."
    warn "AISecurity.app will still protect outbound API calls via 127.0.0.1:7459."
    AGENT_BINDIR=""
fi

# ── MCP server registration (Claude Code) ──
if [ -n "$AGENT_BINDIR" ] && command -v claude >/dev/null 2>&1; then
    MCP_BIN="$AGENT_BINDIR/aisec-mcp"
    # Remove any stale entry (e.g. pointing at target/debug/) before adding fresh.
    claude mcp remove aisec --scope user >/dev/null 2>&1 || true
    if claude mcp add --scope user aisec "$MCP_BIN" >/dev/null 2>&1; then
        success "MCP server registered: aisec → $MCP_BIN"
    else
        warn "MCP registration failed — run manually: claude mcp add --scope user aisec $MCP_BIN"
    fi
else
    if [ -n "$AGENT_BINDIR" ]; then
        warn "claude CLI not found — skipping MCP registration."
        warn "After installing Claude Code, run: claude mcp add --scope user aisec $AGENT_BINDIR/aisec-mcp"
    fi
fi

# ── MCP registration for other agents that read JSON config files ──
# Cursor, Windsurf, Continue.dev, and Cline all follow a similar pattern:
# a JSON file with an "mcpServers" key. We write/merge an "aisec" entry
# into each one we find. Missing files are left alone — no creation if
# the product isn't installed, so we don't pollute the user's home.
if [ -n "$AGENT_BINDIR" ] && command -v python3 >/dev/null 2>&1; then
    MCP_BIN="$AGENT_BINDIR/aisec-mcp"
    python3 - "$MCP_BIN" <<'PY' 2>&1 | sed 's/^/    /'
import json, os, sys
from pathlib import Path
mcp_bin = sys.argv[1]
home = Path(os.path.expanduser("~"))

# (label, path, mcpServers-containing-shape).
# `shape` is "top" → root object has mcpServers at the top
#          "nested" → config under "mcp" → "servers" (Continue.dev)
targets = [
    ("Cursor",      home / ".cursor" / "mcp.json",                          "top"),
    ("Windsurf",    home / ".codeium" / "windsurf" / "mcp_config.json",     "top"),
    ("Continue",    home / ".continue" / "config.json",                     "nested"),
]

entry = {"command": mcp_bin}

def merge_top(cfg, entry):
    ms = cfg.setdefault("mcpServers", {})
    existing = ms.get("aisec")
    if existing == entry:
        return False  # unchanged
    ms["aisec"] = entry
    return True

def merge_nested(cfg, entry):
    mcp = cfg.setdefault("mcp", {})
    servers = mcp.setdefault("servers", {})
    if servers.get("aisec") == entry:
        return False
    servers["aisec"] = entry
    return True

any_registered = False
for label, path, shape in targets:
    if not path.exists():
        # Don't create config files for products that aren't installed.
        continue
    try:
        with open(path) as f:
            cfg = json.load(f)
    except json.JSONDecodeError:
        print(f"[!] {label}: {path} is not valid JSON — skipping")
        continue
    except Exception as e:
        print(f"[!] {label}: cannot read {path}: {e}")
        continue
    try:
        changed = (merge_top if shape == "top" else merge_nested)(cfg, entry)
    except Exception as e:
        print(f"[!] {label}: merge failed ({e})")
        continue
    if not changed:
        print(f"[=] {label}: aisec already registered")
    else:
        tmp = str(path) + ".tmp"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        print(f"[+] {label}: registered aisec → {mcp_bin}")
    any_registered = True

if not any_registered:
    print("[ ] No other MCP clients detected (Cursor, Windsurf, Continue.dev).")
    print("    Install the product, then re-run this installer to auto-register.")
PY
fi

# ── PreToolUse hook (Claude Code) ──
# Merges the hook into ~/.claude/settings.json using a tiny Python helper.
# Idempotent: if a PreToolUse entry with matcher="Bash|Write|Edit" already
# points at the intent-hook binary, we skip.
if [ -n "$AGENT_BINDIR" ] && command -v python3 >/dev/null 2>&1; then
    HOOK_BIN="$AGENT_BINDIR/intent-hook"
    SETTINGS_JSON="$HOME/.claude/settings.json"
    mkdir -p "$HOME/.claude"
    [ -f "$SETTINGS_JSON" ] || echo '{}' > "$SETTINGS_JSON"
    python3 - "$SETTINGS_JSON" "$HOOK_BIN" <<'PY' && success "PreToolUse hook: $HOOK_BIN" || warn "PreToolUse hook merge failed — $SETTINGS_JSON not modified"
import json, os, sys
path, hook_bin = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        cfg = json.load(f)
except json.JSONDecodeError:
    print(f"[!] {path} is not valid JSON — refusing to modify")
    sys.exit(1)
hooks = cfg.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])
# Look for an existing block that already points at this binary.
for block in pre:
    for h in block.get("hooks", []):
        if h.get("type") == "command" and h.get("command") == hook_bin:
            print(f"[=] PreToolUse hook already registered ({hook_bin})")
            sys.exit(0)
pre.append({
    "matcher": "Bash|Write|Edit",
    "hooks": [{"type": "command", "command": hook_bin}],
})
# Atomic write.
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
print(f"[+] Added PreToolUse hook → {hook_bin}")
PY
else
    if [ -n "$AGENT_BINDIR" ]; then
        warn "python3 not found — skipping PreToolUse hook merge."
        warn "See $AGENT_BINDIR/intent-hook for manual ~/.claude/settings.json setup."
    fi
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
echo "║  AI CLI:  $SECURITY_DIR/bin/{aisec-mcp, intent-hook}"
echo "║                                                          ║"
echo "║  Commands:                                               ║"
echo "║    Start:  launchctl start $AGENT_LABEL"
echo "║    Stop:   launchctl stop $AGENT_LABEL"
echo "║                                                          ║"
echo "║  AI-agent protection (auto-registered per installed app):║"
echo "║    - Claude Code: MCP tools + PreToolUse hook            ║"
echo "║    - Cursor / Windsurf / Continue.dev: MCP tools         ║"
echo "║    Restart the AI app to pick up new tools.              ║"
echo "║                                                          ║"
echo "║  Kill switch (user control):                             ║"
echo "║    aisec bypass on       disable all agent checks        ║"
echo "║    aisec bypass off      re-enable                       ║"
echo "║    aisec status          daemon + bypass state           ║"
echo "║  (add $SECURITY_DIR/bin to PATH for short form)"
echo "║                                                          ║"
echo "║  For agents without MCP/hook support (Aider, Codex CLI,  ║"
echo "║  raw Ollama, etc.), use these universal fallbacks:       ║"
echo "║    HTTPS_PROXY=http://127.0.0.1:7459  (outbound filter)  ║"
echo "║    ai-exec --agent <name> -- <cmd>    (sandbox wrapper)  ║"
echo "║                                                          ║"
echo "║  IMPORTANT: Grant Full Disk Access to AISecurity.app in  ║"
echo "║  System Settings > Privacy & Security > Full Disk Access ║"
echo "║  for Mail and Messages scanning to work.                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
