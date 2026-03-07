#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# deploy.sh – Deploy SSH-Monitor with all services running in the background
#
# This script:
#   1. Builds the C++ parser
#   2. Starts Docker Compose services (Python exporter, Prometheus, Grafana)
#   3. Launches the C++ parser in the background
#   4. Displays dashboard URLs
#
# Usage:
#   ./scripts/deploy.sh              # Start all services
#   ./scripts/deploy.sh --logs       # Also tail parser logs in foreground
#
# Services will remain running until stopped with:
#   ./scripts/teardown.sh
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Detect the directory this script is in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PARSER_BIN="$PROJECT_ROOT/cpp-parser/ssh_parser"
PARSER_LOG="$PROJECT_ROOT/.parser.log"
PID_FILE="$PROJECT_ROOT/.parser.pid"

# Determine log file based on OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    LOG_FILE="/var/log/system.log"
else
    LOG_FILE="/var/log/auth.log"
fi

# Parse arguments
SHOW_LOGS=false
if [ "${1:-}" = "--logs" ]; then
    SHOW_LOGS=true
fi

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        SSH-Monitor Deployment Starting...                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Build C++ Parser
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}[1/4]${NC} Building C++ Parser..."

if [ -x "$PARSER_BIN" ]; then
    echo "      ✓ Parser already built"
else
    if ! "$SCRIPT_DIR/build-parser.sh"; then
        echo -e "${RED}✗ Failed to build parser${NC}"
        exit 1
    fi
fi

# Verify the binary exists and is executable
if [ ! -x "$PARSER_BIN" ]; then
    echo -e "${RED}✗ Parser binary not found at $PARSER_BIN${NC}"
    exit 1
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Check if parser is already running
# ─────────────────────────────────────────────────────────────────────────────

if [ -f "$PID_FILE" ]; then
    EXISTING_PID=$(cat "$PID_FILE")
    if kill -0 "$EXISTING_PID" 2>/dev/null; then
        echo -e "${YELLOW}⚠  Parser already running (PID: $EXISTING_PID)${NC}"
        echo "    Stop it with: ./scripts/teardown.sh"
        echo ""
    else
        # PID file is stale
        rm -f "$PID_FILE"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Start Docker Services
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}[2/4]${NC} Starting Docker Compose services..."
echo "      (prometheus, python-exporter, grafana)"

cd "$PROJECT_ROOT"

if ! docker compose up --build -d > /dev/null 2>&1; then
    echo -e "${RED}✗ Failed to start Docker services${NC}"
    echo "  Make sure Docker Desktop is running"
    exit 1
fi

# Wait for services to be ready
echo "      Waiting for services to become ready..."
sleep 3

# Check if services are running
RUNNING_COUNT=$(docker compose ps --services --filter "status=running" 2>/dev/null | wc -l)
EXPECTED_COUNT=3  # python-exporter, prometheus, grafana

if [ "$RUNNING_COUNT" -ge "$EXPECTED_COUNT" ]; then
    echo "      ✓ Docker services started"
else
    echo -e "${YELLOW}⚠  Some services may still be starting${NC}"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Launch C++ Parser in Background
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}[3/4]${NC} Starting C++ Parser..."

# Kill any existing parser process if it exists
if [ -f "$PID_FILE" ]; then
    EXISTING_PID=$(cat "$PID_FILE")
    if kill -0 "$EXISTING_PID" 2>/dev/null; then
        kill "$EXISTING_PID" 2>/dev/null || true
        sleep 1
    fi
fi

# Start parser in background, redirecting output to log file
cd "$PROJECT_ROOT"

if [ "$SHOW_LOGS" = true ]; then
    # Run in foreground so user can see output
    echo "      Starting parser in foreground (Ctrl+C to stop all services)..."
    echo ""
    
    # Start Docker services in background, then run parser
    "$PARSER_BIN" --log "$LOG_FILE" --out ./shared/ssh_metrics.json &
    PARSER_PID=$!
    echo "$PARSER_PID" > "$PID_FILE"
    
    # Show output and handle cleanup
    trap "echo ''; echo -e '${YELLOW}Stopping all services...${NC}'; kill $PARSER_PID 2>/dev/null || true; '$SCRIPT_DIR/teardown.sh' --quiet; exit 0" INT TERM
    
    wait $PARSER_PID || true
    rm -f "$PID_FILE"
    exit 0
else
    # Run in background silently
    nohup "$PARSER_BIN" --log "$LOG_FILE" --out ./shared/ssh_metrics.json > "$PARSER_LOG" 2>&1 &
    PARSER_PID=$!
    
    # Give it a moment to start and verify
    sleep 1
    
    if kill -0 $PARSER_PID 2>/dev/null; then
        echo "$PARSER_PID" > "$PID_FILE"
        echo "      ✓ Parser started (PID: $PARSER_PID)"
    else
        echo -e "${RED}✗ Parser failed to start${NC}"
        echo "      Check logs:"
        echo "      cat $PARSER_LOG"
        exit 1
    fi
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Summary and Next Steps
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}[4/4]${NC} Deployment Complete!"
echo ""
echo -e "${GREEN}✓ All services are running${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Dashboard URLs:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  ${BLUE}Grafana Dashboard${NC}"
echo -e "    ${YELLOW}http://localhost:3000${NC}"
echo -e "    Login: ${YELLOW}admin / admin${NC}"
echo ""
echo -e "  ${BLUE}Prometheus${NC}"
echo -e "    ${YELLOW}http://localhost:9090${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Next Steps:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Open Grafana in your browser:"
echo "   → Visit http://localhost:3000"
echo ""
echo "2. Generate test attacks:"
echo "   → sudo ./scripts/simulate_attack.sh"
echo ""
echo "3. Watch metrics update in real-time on the dashboard"
echo ""
echo "4. Stop all services:"
echo "   → ./scripts/teardown.sh"
echo ""
echo "5. Check system status:"
echo "   → ./scripts/monitor.sh"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
