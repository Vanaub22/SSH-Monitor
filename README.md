# Hybrid C++ and Python Real-Time SSH Security Monitoring System

A production-style monitoring pipeline that detects SSH brute-force
attacks in real time using a **C++ log parser**, a **Python Prometheus
exporter**, and a **Grafana** dashboard --- all orchestrated with Docker
Compose.

------------------------------------------------------------------------

# Architecture Diagram

``` mermaid
flowchart LR

subgraph LINUX["Host Machine (Linux)"]
  LOG_LINUX["/var/log/auth.log"]
  CPP_LINUX["C++ SSH Parser
  • ifstream tail
  • regex matching
  • unordered_map
  • time bucketing"]
  LOG_LINUX -->|append by sshd| CPP_LINUX
end

subgraph MACOS["Host Machine (macOS)"]
  LOG_MAC["/var/log/system.log"]
  CPP_MAC["C++ SSH Parser
  • OS auto-detect
  • ifstream tail
  • regex matching
  • unordered_map"]
  LOG_MAC -->|append by sshd| CPP_MAC
end

subgraph DOCKER["Docker Compose Services"]
  JSON["Shared Volume
  /shared/ssh_metrics.json"]
  PY["Python Prometheus Exporter
  • prometheus_client
  • 5-min moving avg
  • alert evaluation
  • port 9101"]
  PROM["Prometheus
  • scrape every 5s
  • alert rules
  • port 9090"]
  GRAF["Grafana
  • auto provisioned
  • dashboards
  • port 3000"]
end

CPP_LINUX -->|write JSON| JSON
CPP_MAC -->|write JSON| JSON
JSON --> PY
PY -->|:9101/metrics| PROM
PROM -->|PromQL queries| GRAF
```

------------------------------------------------------------------------

# Data Flow

1. **sshd** writes authentication events to platform-specific logs:
   - **Linux (Ubuntu/Debian)**: `/var/log/auth.log`
   - **macOS**: `/var/log/system.log`
2. The **C++ parser** auto-detects the OS, tails the appropriate log file, parses each line for SSH events, and writes a JSON summary every second.
3. The **Python exporter** reads the JSON file and converts the data into Prometheus metrics exposed on `:9101/metrics`.
4. **Prometheus** scrapes the exporter every 5 seconds and evaluates alert rules.
5. **Grafana** queries Prometheus and renders dashboards.

------------------------------------------------------------------------

# Quick Start

## Prerequisites

- Docker & Docker Compose
- Linux host (Ubuntu/Debian/WSL) with `/var/log/auth.log`, OR
- macOS host with `/var/log/system.log`

## One-Command Deployment

Deploy and start all services with a single command:

``` bash
./scripts/deploy.sh
```

This automatically:
- ✓ Builds the C++ parser
- ✓ Starts Docker services (Prometheus, Grafana, Python exporter)
- ✓ Launches the C++ parser in the background
- ✓ Displays dashboard URLs

Then simulate an attack in another terminal:

``` bash
sudo ./scripts/simulate_attack.sh
```

Open your browser to **http://localhost:3000** (`admin`/`admin`) to view the real-time dashboard.

Stop all services with:

``` bash
./scripts/teardown.sh
```

**See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed setup and management options.**

### Remote Access (Share with Others)

Want someone on a different system to view your dashboard? Use a free tunnel:

```bash
# Option 1: Cloudflare Tunnel (permanent + free)
./scripts/expose-tunnel.sh

# Option 2: ngrok (quick demo)
./scripts/expose-ngrok.sh
```

**See [REMOTE-ACCESS.md](./REMOTE-ACCESS.md) for all options and setup.**


------------------------------------------------------------------------

# Platform-Specific Setup

Both Linux and macOS are auto-detected by the system. Just run `./scripts/deploy.sh` to get started!

**For detailed platform-specific instructions and advanced deployment options, see [DEPLOYMENT.md](./DEPLOYMENT.md).**

## Quick Commands by Platform

### Linux (Ubuntu/Debian/WSL)

``` bash
./scripts/deploy.sh
sudo ./scripts/simulate_attack.sh
```

### macOS

``` bash
./scripts/deploy.sh
sudo ./scripts/simulate_attack.sh
```

Both will automatically detect your OS and use the correct log file:
- **Linux**: `/var/log/auth.log`
- **macOS**: `/var/log/system.log`

------------------------------------------------------------------------

# Services

  Service      URL                             Credentials
  ------------ ------------------------------- ---------------
  Grafana      http://localhost:3000           admin / admin
  Prometheus   http://localhost:9090           ---
  Exporter     http://localhost:9101/metrics   ---

**Access Remotely:** Use `./scripts/expose-tunnel.sh` or `./scripts/expose-ngrok.sh` to share with others. See [REMOTE-ACCESS.md](./REMOTE-ACCESS.md)

------------------------------------------------------------------------

# Deployment & Management Scripts

The project includes convenient scripts to manage the system:

| Script | Purpose |
|--------|---------|
| `./scripts/deploy.sh` | Start all services (Docker + parser) |
| `./scripts/teardown.sh` | Stop all services |
| `./scripts/monitor.sh` | Check status and view logs |
| `./scripts/simulate_attack.sh` | Generate test attacks |
| `./scripts/setup-launchd.sh` | Auto-start on login (macOS only) |
| `./scripts/build-parser.sh` | Rebuild C++ parser |
| `./scripts/expose-tunnel.sh` | Share dashboard via Cloudflare Tunnel |
| `./scripts/expose-ngrok.sh` | Share dashboard via ngrok |

**See [DEPLOYMENT.md](./DEPLOYMENT.md) for complete usage details, troubleshooting, and advanced options.**

**See [REMOTE-ACCESS.md](./REMOTE-ACCESS.md) for remote access setup and comparison.**

------------------------------------------------------------------------

# Project Structure

    .
    ├── cpp-parser/
    │   ├── CMakeLists.txt
    │   ├── Dockerfile
    │   ├── include/
    │   └── src/
    ├── python-exporter/
    │   ├── Dockerfile
    │   ├── requirements.txt
    │   └── exporter.py
    ├── prometheus/
    │   ├── prometheus.yml
    │   └── alert_rules.yml
    ├── grafana/
    │   └── provisioning/
    ├── scripts/
    │   └── simulate_attack.sh
    ├── shared/
    ├── docker-compose.yml
    └── README.md

------------------------------------------------------------------------

# SSH Brute Force Attack Flow

``` mermaid
sequenceDiagram

participant Attacker
participant Server as Target Server

Attacker->>Server: SYN
Server-->>Attacker: SYN-ACK
Attacker->>Server: ACK

Note over Attacker,Server: TCP handshake complete

Attacker->>Server: SSH login root/password1
Server-->>Attacker: Failed password
Note right of Server: Logged to auth.log

Attacker->>Server: SSH login root/password2
Server-->>Attacker: Failed password

Note over Attacker,Server: Hundreds of automated attempts

Attacker->>Server: SSH login root/correct_password
Server-->>Attacker: Accepted password
Note right of Server: Compromise logged
```

------------------------------------------------------------------------

# Example Log Entries

## Linux (/var/log/auth.log)

    Feb 19 14:23:01 server sshd[1234]: Failed password for root from 203.0.113.42 port 54321 ssh2
    Feb 19 14:23:02 server sshd[1234]: Failed password for root from 203.0.113.42 port 54322 ssh2
    Feb 19 14:23:03 server sshd[1234]: Invalid user admin from 198.51.100.7 port 12345
    Feb 19 14:25:00 server sshd[1234]: Accepted password for ubuntu from 10.0.1.1 port 22222 ssh2

## macOS (/var/log/system.log)

    Feb 19 14:23:01 MacBook-Pro sshd[1234]: Failed password for root from 203.0.113.42 port 54321 ssh2
    Feb 19 14:23:02 MacBook-Pro sshd[1234]: Failed password for root from 203.0.113.42 port 54322 ssh2
    Feb 19 14:23:03 MacBook-Pro sshd[1234]: Invalid user admin from 198.51.100.7 port 12345
    Feb 19 14:25:00 MacBook-Pro sshd[1234]: Accepted password for ubuntu from 10.0.1.1 port 22222 ssh2

------------------------------------------------------------------------

# Metrics

  Metric                        Description
  ----------------------------- -------------------------
  ssh_failed_logins_total       Total failed logins
  ssh_successful_logins_total   Successful logins
  ssh_failures_per_minute       Failures per minute
  ssh_failures_moving_avg_5m    5-minute moving average
  ssh_failures_by_ip            Failure count per IP
  ssh_alert_high_failure_rate   Alert state

------------------------------------------------------------------------

# Alerts

  Alert                       Condition
  --------------------------- ---------------------------
  HighSSHFailureRate          failures_per_minute \> 10
  CriticalSSHFailureRate      failures_per_minute \> 50
  SSHExporterDown             exporter unavailable
  ElevatedSSHFailureAverage   moving average spike

------------------------------------------------------------------------

# Attack Simulator & Testing

Generate realistic fake SSH login attempts with:

``` bash
sudo ./scripts/simulate_attack.sh
```

This script automatically detects your OS and uses the correct auth log:
- **Linux**: `/var/log/auth.log`
- **macOS**: `/var/log/system.log`

Alternatively, specify a custom log file:

``` bash
sudo ./scripts/simulate_attack.sh /tmp/test_auth.log
```

**For more testing scenarios and advanced options, see [DEPLOYMENT.md](./DEPLOYMENT.md).**

------------------------------------------------------------------------

# License

MIT License
