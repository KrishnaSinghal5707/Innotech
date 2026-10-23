#!/usr/bin/env bash
# Q-SHIELD Demo Launcher
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================="
echo "  🛡️  LAUNCHING Q-SHIELD AUTOMATED DEMO WORKFLOW"
echo "=========================================================="
python3 demo_workflow.py
