#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# expose-cloud.sh – Deploy to Render.com or Railway for remote access
#
# This script helps you deploy Prometheus + Grafana to a free cloud provider
# while keeping the C++ parser running locally.
#
# The setup:
#   Local:  C++ Parser → Python Exporter (port 9101)
#   Cloud:  Prometheus + Grafana (pull from local exporter)
#
# Prerequisites:
#   - Render.com account (free tier)
#   - Docker (for local testing)
#   - Local exporter exposed via port 9101
#
# See REMOTE-ACCESS.md for detailed cloud deployment instructions.
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Color codes
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      Cloud Deployment Guide                                    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

echo -e "${BLUE}This script helps deploy to Render.com or Railway.${NC}"
echo ""
echo "However, for the best experience with your local SSH parser,"
echo "we recommend using a tunnel instead (faster & simpler):"
echo ""
echo -e "${GREEN}Option 1: Cloudflare Tunnel (Recommended)${NC}"
echo "  ./scripts/expose-tunnel.sh"
echo ""
echo -e "${GREEN}Option 2: ngrok${NC}"
echo "  ./scripts/expose-ngrok.sh"
echo ""
echo "See ${YELLOW}REMOTE-ACCESS.md${NC} for detailed instructions."
echo ""
