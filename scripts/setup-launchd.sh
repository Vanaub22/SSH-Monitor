#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup-launchd.sh – Install macOS launchd service for auto-start
#
# This script installs SSH-Monitor as a launchd service that:
#   - Automatically starts when you log in
#   - Keeps services running if they crash
#   - Logs output to ~/Library/Logs/ssh-monitor.log
#
# Usage:
#   ./scripts/setup-launchd.sh install    # Install the service
#   ./scripts/setup-launchd.sh uninstall  # Remove the service
#   ./scripts/setup-launchd.sh status     # Check service status
#
# Once installed, manage with:
#   launchctl start local.ssh-monitor     # Start manually
#   launchctl stop local.ssh-monitor      # Stop manually
#   launchctl unload path/to/plist        # Disable auto-start
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PLIST_PATH="$HOME/Library/LaunchAgents/local.ssh-monitor.plist"
LOG_DIR="$HOME/Library/Logs"
LOG_FILE="$LOG_DIR/ssh-monitor.log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# Command: Install
# ─────────────────────────────────────────────────────────────────────────────

install() {
    echo -e "${BLUE}Installing SSH-Monitor launchd service...${NC}"
    echo ""
    
    # Create the plist file
    cat > "$PLIST_PATH" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>local.ssh-monitor</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>DEPLOY_SCRIPT_PATH</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>StandardOutPath</key>
    <string>LOG_FILE_PATH</string>
    
    <key>StandardErrorPath</key>
    <string>LOG_FILE_PATH</string>
    
    <key>WorkingDirectory</key>
    <string>PROJECT_ROOT_PATH</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
PLIST_EOF
    
    # Replace placeholders
    sed -i '' "s|DEPLOY_SCRIPT_PATH|$SCRIPT_DIR/deploy.sh|g" "$PLIST_PATH"
    sed -i '' "s|LOG_FILE_PATH|$LOG_FILE|g" "$PLIST_PATH"
    sed -i '' "s|PROJECT_ROOT_PATH|$PROJECT_ROOT|g" "$PLIST_PATH"
    
    # Load the service
    launchctl load "$PLIST_PATH" 2>/dev/null || {
        echo -e "${YELLOW}⚠  Plist already loaded${NC}"
    }
    
    echo -e "${GREEN}✓ Service installed${NC}"
    echo ""
    echo "The SSH-Monitor service is now installed and will:"
    echo "  • Start automatically when you log in"
    echo "  • Keep running and restart if it crashes"
    echo "  • Log output to: $LOG_FILE"
    echo ""
    echo "Status: $(launchctl list local.ssh-monitor 2>&1 | grep -q "^-" && echo "Running" || echo "Stopped")"
    echo ""
    echo "Useful commands:"
    echo "  launchctl start local.ssh-monitor    # Start manually"
    echo "  launchctl stop local.ssh-monitor     # Stop manually"
    echo "  launchctl unload \"$PLIST_PATH\"  # Disable auto-start"
    echo "  tail -f \"$LOG_FILE\"              # View logs"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Command: Uninstall
# ─────────────────────────────────────────────────────────────────────────────

uninstall() {
    echo -e "${BLUE}Removing SSH-Monitor launchd service...${NC}"
    echo ""
    
    if [ ! -f "$PLIST_PATH" ]; then
        echo -e "${YELLOW}Service not installed${NC}"
        return
    fi
    
    # Stop the service
    launchctl stop local.ssh-monitor 2>/dev/null || true
    
    # Unload the service
    launchctl unload "$PLIST_PATH" 2>/dev/null || {
        echo -e "${YELLOW}⚠  Service may already be unloaded${NC}"
    }
    
    # Remove the plist
    rm -f "$PLIST_PATH"
    
    echo -e "${GREEN}✓ Service uninstalled${NC}"
    echo "SSH-Monitor will no longer start automatically."
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Command: Status
# ─────────────────────────────────────────────────────────────────────────────

status() {
    echo -e "${BLUE}SSH-Monitor Service Status:${NC}"
    echo ""
    
    if [ ! -f "$PLIST_PATH" ]; then
        echo -e "  Status: ${YELLOW}Not installed${NC}"
        echo ""
        echo "To install the service, run:"
        echo "  ./scripts/setup-launchd.sh install"
        return
    fi
    
    echo -e "  Plist: ${YELLOW}$PLIST_PATH${NC}"
    
    if launchctl list local.ssh-monitor 2>&1 | grep -q "^-"; then
        echo -e "  Status: ${GREEN}✓ Running${NC}"
        
        # Get PID
        PID=$(launchctl list local.ssh-monitor 2>&1 | grep -o '"PID" = [0-9]*' | grep -o '[0-9]*' || echo "")
        if [ -n "$PID" ]; then
            echo "  PID: $PID"
        fi
    else
        echo -e "  Status: ${RED}✗ Stopped${NC}"
    fi
    
    echo -e "  Logs: ${YELLOW}$LOG_FILE${NC}"
    
    if [ -f "$LOG_FILE" ]; then
        LINES=$(wc -l < "$LOG_FILE")
        echo "  Log lines: $LINES"
    fi
    
    echo ""
    echo "Commands:"
    echo "  ./scripts/setup-launchd.sh uninstall   Remove service"
    echo "  launchctl start local.ssh-monitor      Start/restart service"
    echo "  launchctl stop local.ssh-monitor       Stop service"
    echo "  tail -f \"$LOG_FILE\"              View live logs"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      SSH-Monitor macOS Deployment Service Setup                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

COMMAND="${1:-status}"

case "$COMMAND" in
    install)
        install
        ;;
    uninstall)
        uninstall
        ;;
    status)
        status
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        echo ""
        echo "Usage:"
        echo "  ./scripts/setup-launchd.sh install    # Install the service"
        echo "  ./scripts/setup-launchd.sh uninstall  # Remove the service"
        echo "  ./scripts/setup-launchd.sh status     # Check service status"
        echo ""
        exit 1
        ;;
esac
