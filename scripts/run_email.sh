#!/bin/bash
# Email Sentinel runner wrapper
# Usage: ./run_email.sh [args passed to email_sentinel.py]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
LOG="/tmp/email-sentinel.log"

# Load .env if present
[ -f "$HOME/.env" ] && set -a && source "$HOME/.env" && set +a 2>/dev/null || true

echo "--- $(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
"$PYTHON" "$SCRIPT_DIR/email_sentinel.py" "$@" >> "$LOG" 2>&1
EXIT=$?
echo "exit: $EXIT" >> "$LOG"
exit $EXIT
