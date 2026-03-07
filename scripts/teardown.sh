#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# teardown.sh – Stop all SSH-Monitor services
#
# This script gracefully shuts down:
#   - C++ Parser (running on host)
#   - Docker Compose services (Python exporter, Prometheus, Grafana)
#
# Usage:
#   ./scripts/teardown.sh          # Stop all services with summary
#   ./scripts/teardown.sh --quiet  # Stop services silently (used internally)
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Detect the directory this script is in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PID_FILE="$PROJECT_ROOT/.parser.pid"

QUIET_MODE=false
if [ "${1:-}" = "--quiet" ]; then
    QUIET_MODE=true
fi

if [ "$QUIET_MODE" = false ]; then
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║        SSH-Monitor Teardown Starting...                        ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Stop C++ Parser
# ─────────────────────────────────────────────────────────────────────────────

if [ "$QUIET_MODE" = false ]; then
    echo -e "${BLUE}[1/2]${NC} Stopping C++ Parser..."
fi

PARSER_STOPPED=false

if [ -f "$PID_FILE" ]; then
    PARSER_PID=$(cat "$PID_FILE")
    
    if kill -0 $PARSER_PID 2>/dev/null; then
        kill $PARSER_PID 2>/dev/null || true
        
        # Give it a moment to shutdown gracefully
        sleep 1
        
        if kill -0 $PARSER_PID 2>/dev/null; then
            # Force kill if it didn't stop
            kill -9 $PARSER_PID 2>/dev/null || true
        fi
        
        PARSER_STOPPED=true
    fi
    
    rm -f "$PID_FILE"
fi

if [ "$QUIET_MODE" = false ]; then
    if [ "$PARSER_STOPPED" = true ]; then
        echo "      ✓ Parser stopped"
    else
        echo "      ✓ Parser not running"
    fi
fi

if [ "$QUIET_MODE" = false ]; then
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Stop Docker Services
# ─────────────────────────────────────────────────────────────────────────────

if [ "$QUIET_MODE" = false ]; then
    echo -e "${BLUE}[2/2]${NC} Stopping Docker services..."
fi

cd "$PROJECT_ROOT"

if docker compose down > /dev/null 2>&1; then
    if [ "$QUIET_MODE" = false ]; then
        echo "      ✓ Docker services stopped"
    fi
else
    if [ "$QUIET_MODE" = false ]; then
        echo "      ⚠  Docker services already stopped"
    fi
fi

if [ "$QUIET_MODE" = false ]; then
    echo ""
    echo -e "${GREEN}✓ All services shut down${NC}"
    echo ""
fi
