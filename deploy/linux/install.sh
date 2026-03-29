#!/usr/bin/env bash
set -euo pipefail

# SecurityCore Linux Daemon — Install Script
# Usage: ./install.sh [--install-dir DIR]

INSTALL_DIR="${1:-$HOME/.local/bin}"
SEC_DIR="$HOME/.mac-security"
SERVICE_DIR="$HOME/.config/systemd/user"

echo "╔══════════════════════════════════════════════════╗"
echo "║    SecurityCore Linux Daemon — Installer          ║"
echo "╚══════════════════════════════════════════════════╝"

# Check if binary exists
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$REPO_ROOT/SecurityCore/target/release/security-linux"

if [ ! -f "$BINARY" ]; then
    echo "Building SecurityCore..."
    cd "$REPO_ROOT/SecurityCore"
    cargo build --release -p security-linux
    BINARY="$REPO_ROOT/SecurityCore/target/release/security-linux"
fi

# Create directories
mkdir -p "$INSTALL_DIR"
mkdir -p "$SEC_DIR/logs"
mkdir -p "$SEC_DIR/quarantine"
mkdir -p "$SERVICE_DIR"

# Copy binary
cp "$BINARY" "$INSTALL_DIR/security-core-linux"
chmod +x "$INSTALL_DIR/security-core-linux"
echo "✅ Binary installed to $INSTALL_DIR/security-core-linux"

# Generate default config if none exists
if [ ! -f "$SEC_DIR/config.toml" ]; then
    cat > "$SEC_DIR/config.toml" << 'TOML'
[general]
mode = "PRODUCTION"

[paths]
security_dir = "~/.mac-security"
mail_dir = "~/.thunderbird"
messages_db = "~/.config/Signal/sql/db.sqlite"
quarantine_dir = "~/.mac-security/quarantine"
log_dir = "~/.mac-security/logs"

[file_watcher]
enabled = true
monitored_directories = ["~/Downloads", "~/Desktop", "~/Documents"]
max_scan_size_bytes = 5242880
debounce_ms = 300

[email_scanner]
enabled = true
startup_scan_limit = 50

[messages_scanner]
enabled = true

[scheduled_scan]
enabled = true
interval_hours = 6
scan_directories = ["~/Downloads", "~/Desktop", "~/Documents"]

[notifications]
enabled = true
critical_only = true
TOML
    echo "✅ Default config created at $SEC_DIR/config.toml"
else
    echo "ℹ️  Existing config preserved at $SEC_DIR/config.toml"
fi

# Install systemd service
cp "$SCRIPT_DIR/security-core.service" "$SERVICE_DIR/security-core.service"
echo "✅ systemd service installed"

# Enable and start
systemctl --user daemon-reload
systemctl --user enable security-core.service
systemctl --user start security-core.service
echo "✅ SecurityCore daemon started"

echo ""
echo "Commands:"
echo "  Status:  systemctl --user status security-core"
echo "  Logs:    journalctl --user -u security-core -f"
echo "  Stop:    systemctl --user stop security-core"
echo "  Config:  $SEC_DIR/config.toml"
echo "  Alerts:  $SEC_DIR/logs/alerts.log"
