#!/usr/bin/env bash
# Install the repo's git hooks (docs/BUILD-PROCEDURE.md Phase 0).
set -euo pipefail
cd "$(dirname "$0")/.."
git config core.hooksPath scripts/hooks
chmod +x scripts/hooks/*
echo "hooks installed: core.hooksPath -> scripts/hooks"
echo "installed:"; ls -1 scripts/hooks | sed 's/^/  /'
