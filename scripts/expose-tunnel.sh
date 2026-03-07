#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# expose-tunnel.sh – Expose local Grafana to the internet via Cloudflare Tunnel
#
# This script uses Cloudflare Tunnel to create a secure public URL for your
# local Grafana dashboard without port forwarding or router config.
#
# Prerequisites:
#   - Cloudflare account (free at cloudflare.com)
#   - cloudflared CLI installed
#
# Installation:
#   brew install cloudflare/cloudflare/cloudflared   # macOS
#   curl -L https://pkg.cloudflare.com/cloudflared-linux-amd64.tgz | tar xz  # Linux
#
# Usage:
#   ./scripts/expose-tunnel.sh              # Start tunnel
#   ./scripts/expose-tunnel.sh --background # Run in background
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Color codes
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
DASHBOARD_URL="http://localhost:3000"
TUNNEL_NAME="ssh-monitor-dashboard"

# Check if cloudflared is installed
if ! command -v cloudflared &> /dev/null; then
    echo -e "${RED}✗ cloudflared not found${NC}"
    echo ""
    echo "Install it with:"
    echo ""
    echo "  macOS:"
    echo "    brew install cloudflare/cloudflare/cloudflared"
    echo ""
    echo "  Linux:"
    echo "    curl -L https://pkg.cloudflare.com/cloudflared-linux-amd64.tgz | tar xz"
    echo "    sudo mv ./cloudflared /usr/local/bin"
    echo ""
    exit 1
fi

# Parse arguments
RUN_BACKGROUND=false
if [ "${1:-}" = "--background" ]; then
    RUN_BACKGROUND=true
fi

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        Exposing Dashboard via Cloudflare Tunnel                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check if Grafana is running
echo -e "${BLUE}Checking if Grafana is running...${NC}"
if ! curl -s -o /dev/null --connect-timeout 2 "$DASHBOARD_URL" 2>/dev/null; then
    echo -e "${RED}✗ Grafana not accessible at $DASHBOARD_URL${NC}"
    echo ""
    echo "Make sure you've run:"
    echo "  ./scripts/deploy.sh"
    echo ""
    exit 1
fi
echo -e "${GREEN}✓ Grafana is running${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Start Tunnel
# ─────────────────────────────────────────────────────────────────────────────

echo -e "${BLUE}Starting Cloudflare Tunnel...${NC}"
echo "Exposing: $DASHBOARD_URL"
echo ""

if [ "$RUN_BACKGROUND" = true ]; then
    # Run in background
    nohup cloudflared tunnel --name "$TUNNEL_NAME" --url "$DASHBOARD_URL" > /dev/null 2>&1 &
    TUNNEL_PID=$!
    echo "$TUNNEL_PID" > ".tunnel.pid"
    
    echo -e "${GREEN}✓ Tunnel started in background (PID: $TUNNEL_PID)${NC}"
    echo ""
    echo "Your public dashboard URL will be displayed shortly..."
    sleep 2
    
    # Get the tunnel URL
    TUNNEL_URL=$(cloudflared tunnel list --output json 2>/dev/null | grep -o '"PublicURL":"[^"]*' | head -1 | cut -d'"' -f4 || echo "")
    
    if [ -z "$TUNNEL_URL" ]; then
        echo -e "${YELLOW}⚠  Tunnel created but URL not immediately available${NC}"
        echo "Check with: cloudflared tunnel list"
    else
        echo -e "${GREEN}Public URL: $TUNNEL_URL${NC}"
    fi
else
    # Run in foreground
    echo -e "${YELLOW}Press Ctrl+C to stop the tunnel${NC}"
    echo ""
    cloudflared tunnel --name "$TUNNEL_NAME" --url "$DASHBOARD_URL"
fi
