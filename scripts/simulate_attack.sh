#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# simulate_attack.sh – Generate fake SSH auth.log entries for testing
#
# This script appends realistic-looking failed and successful SSH login lines
# to /var/log/auth.log (or a custom path) so the C++ parser has data to ingest.
#
# Usage:
#   sudo ./simulate_attack.sh                     # default: /var/log/auth.log
#   sudo ./simulate_attack.sh /tmp/test_auth.log  # custom path
#
# ⚠  Requires root/sudo to write to /var/log/auth.log
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

LOG_FILE="${1:-/var/log/auth.log}"

# ── Fake attacker IPs ────────────────────────────────────────────────────────
ATTACKER_IPS=(
    "203.0.113.42"
    "198.51.100.7"
    "192.0.2.99"
    "10.0.0.55"
    "172.16.0.101"
)

# ── Usernames tried by attackers ─────────────────────────────────────────────
USERNAMES=(
    "root"
    "admin"
    "ubuntu"
    "test"
    "user"
    "guest"
    "deploy"
    "postgres"
)

HOSTNAME="ssh-monitor-host"

echo "╔══════════════════════════════════════════════════╗"
echo "║  SSH Brute-Force Attack Simulator                ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Target log:  ${LOG_FILE}"
echo "║  Press Ctrl+C to stop                            ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

round=0

while true; do
    round=$((round + 1))
    echo "[Round ${round}] Generating attack traffic..."

    # ── Burst of failed logins (simulates brute-force) ───────────────────
    num_failures=$((RANDOM % 15 + 5))   # 5–19 failures per round
    for ((i = 0; i < num_failures; i++)); do
        ip=${ATTACKER_IPS[$((RANDOM % ${#ATTACKER_IPS[@]}))]}
        user=${USERNAMES[$((RANDOM % ${#USERNAMES[@]}))]}
        ts=$(date "+%b %d %H:%M:%S")
        port=$((RANDOM % 50000 + 10000))

        echo "${ts} ${HOSTNAME} sshd[$$]: Failed password for ${user} from ${ip} port ${port} ssh2" >> "${LOG_FILE}"
        sleep 0.05
    done

    # ── Occasional invalid-user attempts ─────────────────────────────────
    num_invalid=$((RANDOM % 5))
    for ((i = 0; i < num_invalid; i++)); do
        ip=${ATTACKER_IPS[$((RANDOM % ${#ATTACKER_IPS[@]}))]}
        user="hacker${RANDOM}"
        ts=$(date "+%b %d %H:%M:%S")
        port=$((RANDOM % 50000 + 10000))

        echo "${ts} ${HOSTNAME} sshd[$$]: Invalid user ${user} from ${ip} port ${port}" >> "${LOG_FILE}"
        sleep 0.05
    done

    # ── A few successful logins (legitimate traffic) ─────────────────────
    num_success=$((RANDOM % 3))
    for ((i = 0; i < num_success; i++)); do
        ts=$(date "+%b %d %H:%M:%S")
        port=$((RANDOM % 50000 + 10000))

        echo "${ts} ${HOSTNAME} sshd[$$]: Accepted password for ubuntu from 10.0.1.1 port ${port} ssh2" >> "${LOG_FILE}"
        sleep 0.05
    done

    echo "  → wrote ${num_failures} failures, ${num_invalid} invalid-user, ${num_success} successes"
    sleep 2
done
