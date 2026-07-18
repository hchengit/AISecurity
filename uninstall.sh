#!/bin/bash
# AISecurity — Uninstaller

AGENT_LABEL="com.aisecurity.shield"
AGENT_PLIST="$HOME/Library/LaunchAgents/${AGENT_LABEL}.plist"
INSTALL_DIR="${MACSEC_INSTALL_DIR:-/Applications}"

echo "Stopping AISecurity..."
launchctl stop "$AGENT_LABEL" 2>/dev/null
launchctl unload "$AGENT_PLIST" 2>/dev/null
pkill -f "AISecurity-bin" 2>/dev/null
sleep 1

# Also clean up old label if it exists (from buggy previous installs)
OLD_PLIST="$HOME/Library/LaunchAgents/com.aisecurity.agent.plist"
if [ -f "$OLD_PLIST" ]; then
    launchctl unload "$OLD_PLIST" 2>/dev/null
    rm -f "$OLD_PLIST"
    echo "Removed stale LaunchAgent (com.aisecurity.agent)"
fi

echo "Removing LaunchAgent..."
rm -f "$AGENT_PLIST"

echo "Removing app..."
rm -rf "$INSTALL_DIR/AISecurity.app"

echo "Done. Logs and quarantine remain at ~/.mac-security/"
