#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# launch-parser.sh – Start the SSH parser on the host machine
#
# This script launches the SSH parser in the foreground, monitoring system logs
# and writing metrics to a JSON file that the Docker-based Python exporter reads.
#
# The parser will monitor the appropriate log file based on OS:
#   - macOS: /var/log/system.log
#   - Linux: /var/log/auth.log
#
# Usage:
#   ./scripts/launch-parser.sh                                  # Auto-detect log file
#   ./scripts/launch-parser.sh /var/log/auth.log               # Custom log file
#   ./scripts/launch-parser.sh /var/log/system.log             # macOS specific
#
# Keybindings:
#   Ctrl+C – Stop the parser gracefully
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Detect the directory this script is in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PARSER_BIN="$PROJECT_ROOT/cpp-parser/ssh_parser"
METRICS_DIR="$PROJECT_ROOT/shared"
METRICS_FILE="$METRICS_DIR/ssh_metrics.json"

# Determine log file
if [ -z "${1:-}" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        LOG_FILE="/var/log/system.log"
    else
        LOG_FILE="/var/log/auth.log"
    fi
else
    LOG_FILE="$1"
fi

echo "╔══════════════════════════════════════════════════╗"
echo "║  SSH Parser Launcher                             ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Parser binary:  $PARSER_BIN"
echo "║  Log file:       $LOG_FILE"
echo "║  Output file:    $METRICS_FILE"
echo "║  Press Ctrl+C to stop"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Verify parser exists
if [ ! -f "$PARSER_BIN" ]; then
    echo "✗ ERROR: Parser binary not found at $PARSER_BIN"
    echo "  Please build it first:"
    echo "    ./scripts/build-parser.sh"
    exit 1
fi

# Verify log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo "✗ ERROR: Log file not found: $LOG_FILE"
    exit 1
fi

# Create metrics directory if it doesn't exist
mkdir -p "$METRICS_DIR"

# Launch the parser
echo "Starting parser..."
exec "$PARSER_BIN" --log "$LOG_FILE" --out "$METRICS_FILE"
