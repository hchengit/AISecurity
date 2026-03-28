#!/bin/bash
# AISecurity — Uninstaller

AGENT_LABEL="com.aisecurity.agent"
AGENT_PLIST="$HOME/Library/LaunchAgents/${AGENT_LABEL}.plist"

echo "Stopping AISecurity..."
launchctl unload "$AGENT_PLIST" 2>/dev/null
pkill -f "AISecurity-bin" 2>/dev/null
sleep 1

echo "Removing LaunchAgent..."
rm -f "$AGENT_PLIST"

echo "Removing app..."
rm -rf /Applications/AISecurity.app

echo "Done. Logs and quarantine remain at ~/.mac-security/"
