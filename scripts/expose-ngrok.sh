#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# expose-ngrok.sh – Expose local Grafana via ngrok (fast & simple)
#
# This script uses ngrok to create a temporary public URL for your dashboard.
# Perfect for quick sharing with colleagues.
#
# Prerequisites:
#   - Free ngrok account at ngrok.com
#   - ngrok CLI installed
#
# Installation:
#   brew install ngrok   # macOS
#   # Or download from: https://ngrok.com/download
#
# Usage:
#   ./scripts/expose-ngrok.sh
#
# Note: Free tier gives you a temporary URL that changes each run.
#       Paid tier ($5-15/month) gives permanent URLs.
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Color codes
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         Exposing Dashboard via ngrok                           ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check if ngrok is installed
if ! command -v ngrok &> /dev/null; then
    echo -e "${RED}✗ ngrok not found${NC}"
    echo ""
    echo "Install it:"
    echo ""
    echo "  macOS:"
    echo "    brew install ngrok"
    echo ""
    echo "  Or download from: https://ngrok.com/download"
    echo ""
    exit 1
fi

# Check if Grafana is running
echo -e "${BLUE}Checking if Grafana is running...${NC}"
if ! curl -s -o /dev/null --connect-timeout 2 http://localhost:3000 2>/dev/null; then
    echo -e "${RED}✗ Grafana not accessible at http://localhost:3000${NC}"
    echo ""
    echo "Start it with:"
    echo "  ./scripts/deploy.sh"
    echo ""
    exit 1
fi
echo -e "${GREEN}✓ Grafana is running${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Start ngrok
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}Starting ngrok tunnel...${NC}"
echo ""
echo -e "${YELLOW}⚠  Your dashboard will be publicly accessible!${NC}"
echo "   Share the URL below carefully. Anyone with this URL can access."
echo ""
echo "Press Ctrl+C to stop the tunnel."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Start ngrok
ngrok http 3000 \
    --authtoken "${NGROK_AUTHTOKEN:-}" \
    --region us \
    --scheme https
