#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# monitor.sh – Check status of SSH-Monitor services and display real-time metrics
#
# This script:
#   - Shows Docker container status
#   - Shows C++ Parser status
#   - Displays recent parser logs
#   - Shows latest metrics
#   - Checks dashboard accessibility
#
# Usage:
#   ./scripts/monitor.sh              # Show complete status
#   ./scripts/monitor.sh --tail       # Show parser logs (tail -f)
#   ./scripts/monitor.sh --metrics    # Show latest metrics JSON
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Detect the directory this script is in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PID_FILE="$PROJECT_ROOT/.parser.pid"
PARSER_LOG="$PROJECT_ROOT/.parser.log"
METRICS_FILE="$PROJECT_ROOT/shared/ssh_metrics.json"

# Parse arguments
TAIL_MODE=false
METRICS_MODE=false

if [ "${1:-}" = "--tail" ]; then
    TAIL_MODE=true
elif [ "${1:-}" = "--metrics" ]; then
    METRICS_MODE=true
fi

# ─────────────────────────────────────────────────────────────────────────────
# Tail logs
# ─────────────────────────────────────────────────────────────────────────────

if [ "$TAIL_MODE" = true ]; then
    echo -e "${BLUE}Tailing C++ Parser logs (press Ctrl+C to stop)...${NC}"
    echo ""
    if [ -f "$PARSER_LOG" ]; then
        tail -f "$PARSER_LOG"
    else
        echo -e "${YELLOW}No logs found. Parser may not be running.${NC}"
    fi
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# Show metrics
# ─────────────────────────────────────────────────────────────────────────────

if [ "$METRICS_MODE" = true ]; then
    echo -e "${BLUE}Latest metrics from parser:${NC}"
    echo ""
    if [ -f "$METRICS_FILE" ]; then
        cat "$METRICS_FILE" | jq . 2>/dev/null || cat "$METRICS_FILE"
    else
        echo -e "${YELLOW}Metrics file not found. Parser may not be running.${NC}"
    fi
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# Full Status Report
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║             SSH-Monitor System Status Report                   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# C++ Parser Status
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}C++ Parser Status:${NC}"
echo "─────────────────────────────────────────────────────────────────"

if [ -f "$PID_FILE" ]; then
    PARSER_PID=$(cat "$PID_FILE")
    
    if kill -0 $PARSER_PID 2>/dev/null; then
        echo -e "  Status: ${GREEN}✓ Running${NC}"
        echo "  PID: $PARSER_PID"
        
        # Get CPU and memory usage
        if [[ "$OSTYPE" == "darwin"* ]]; then
            PS_INFO=$(ps -p $PARSER_PID -o %cpu,%mem,rss 2>/dev/null | tail -n 1 || echo "")
        else
            PS_INFO=$(ps -p $PARSER_PID -o %cpu,%mem,rss 2>/dev/null | tail -n 1 || echo "")
        fi
        
        if [ -n "$PS_INFO" ]; then
            echo "  Resources: $PS_INFO (CPU% MEM% RSS_KB)"
        fi
    else
        echo -e "  Status: ${RED}✗ Not Running${NC}"
    fi
else
    echo -e "  Status: ${RED}✗ Not Running${NC}"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Docker Services Status
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}Docker Services Status:${NC}"
echo "─────────────────────────────────────────────────────────────────"

cd "$PROJECT_ROOT"

DOCKER_AVAILABLE=$(command -v docker >/dev/null 2>&1 && echo "yes" || echo "no")

if [ "$DOCKER_AVAILABLE" != "yes" ]; then
    echo -e "  ${RED}✗ Docker not found${NC}"
else
    docker compose ps --no-trunc 2>/dev/null || {
        echo -e "  ${YELLOW}⚠  Docker services not running${NC}"
    }
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Metrics File Status
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}Metrics File Status:${NC}"
echo "─────────────────────────────────────────────────────────────────"

if [ -f "$METRICS_FILE" ]; then
    FILE_SIZE=$(wc -c < "$METRICS_FILE" | numfmt --to=iec 2>/dev/null || wc -c < "$METRICS_FILE")
    MODIFIED=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$METRICS_FILE" 2>/dev/null || stat -c %y "$METRICS_FILE" 2>/dev/null | cut -d. -f1)
    
    echo -e "  Location: ${CYAN}$METRICS_FILE${NC}"
    echo "  Size: $FILE_SIZE"
    echo "  Last updated: $MODIFIED"
    
    # Show key metrics
    if command -v jq >/dev/null 2>&1; then
        FAILED=$(jq -r '.total_failed_logins // 0' "$METRICS_FILE" 2>/dev/null || echo "N/A")
        SUCCESS=$(jq -r '.total_successful_logins // 0' "$METRICS_FILE" 2>/dev/null || echo "N/A")
        IPS=$(jq -r '.per_ip // {}' "$METRICS_FILE" 2>/dev/null | jq 'length' || echo "N/A")
        
        echo "  Failed logins: $FAILED"
        echo "  Successful logins: $SUCCESS"
        echo "  Unique IPs: $IPS"
    fi
else
    echo -e "  Location: ${CYAN}$METRICS_FILE${NC}"
    echo -e "  Status: ${YELLOW}✗ File not created yet${NC}"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard Accessibility
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}Dashboard Accessibility:${NC}"
echo "─────────────────────────────────────────────────────────────────"

# Check Grafana
if curl -s -o /dev/null --connect-timeout 2 http://localhost:3000 2>/dev/null; then
    echo -e "  Grafana: ${GREEN}✓ Accessible${NC} (http://localhost:3000)"
else
    echo -e "  Grafana: ${RED}✗ Not accessible${NC} (http://localhost:3000)"
fi

# Check Prometheus
if curl -s -o /dev/null --connect-timeout 2 http://localhost:9090 2>/dev/null; then
    echo -e "  Prometheus: ${GREEN}✓ Accessible${NC} (http://localhost:9090)"
else
    echo -e "  Prometheus: ${RED}✗ Not accessible${NC} (http://localhost:9090)"
fi

# Check Exporter
if curl -s -o /dev/null --connect-timeout 2 http://localhost:9101/metrics 2>/dev/null; then
    echo -e "  Exporter: ${GREEN}✓ Accessible${NC} (http://localhost:9101)"
else
    echo -e "  Exporter: ${RED}✗ Not accessible${NC} (http://localhost:9101)"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Recent Logs
# ─────────────────────────────────────────────────────────────────────────────

if [ -f "$PARSER_LOG" ]; then
    echo -e "${BLUE}Recent Parser Logs (last 10 lines):${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    tail -n 10 "$PARSER_LOG" | sed 's/^/  /'
    echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# Quick Actions
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}Quick Actions:${NC}"
echo "─────────────────────────────────────────────────────────────────"
echo "  Stop services:       ./scripts/teardown.sh"
echo "  Simulate attack:     sudo ./scripts/simulate_attack.sh"
echo "  View parser logs:    ./scripts/monitor.sh --tail"
echo "  View metrics:        ./scripts/monitor.sh --metrics"
echo ""
