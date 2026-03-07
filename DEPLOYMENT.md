# SSH-Monitor Deployment Guide

This guide covers deploying SSH-Monitor on your macOS system so the dashboard stays alive and immediately shows stats when attacks are simulated.

## Quick Start (< 5 minutes)

### 1. Deploy Everything

```bash
./scripts/deploy.sh
```

This single command:
- ✓ Builds the C++ parser
- ✓ Starts Docker services (Prometheus, Grafana, Python exporter)
- ✓ Launches the C++ parser in the background
- ✓ Displays dashboard URLs

### 2. Generate Test Attacks

In another terminal, run:

```bash
sudo ./scripts/simulate_attack.sh
```

### 3. View the Dashboard

Open your browser to:
- **Grafana Dashboard**: http://localhost:3000
- **Login**: `admin` / `admin`
- **Prometheus**: http://localhost:9090

The dashboard will immediately show the simulated attacks in real-time.

### 4. Stop Everything

```bash
./scripts/teardown.sh
```

---

## Remote Access (Share Dashboard with Others)

Want others on different systems to view your dashboard? Several options:

### Option 1: Cloudflare Tunnel (Recommended) 🌟
Free, permanent, no credit card needed - best for 24/7 remote access

```bash
brew install cloudflare/cloudflare/cloudflared    # Install once
cloudflared login                                 # Authorize once

./scripts/deploy.sh                               # Start dashboard
./scripts/expose-tunnel.sh                        # Expose to internet

cloudflared tunnel list                           # Get public URL
# Share: https://your-dashboard.workers.dev
```

### Option 2: ngrok (Quick Demo)
Super fast, great for quick sharing (2-hour free sessions)

```bash
brew install ngrok                                # Install once
ngrok config add-authtoken YOUR_TOKEN_HERE       # Configure once

./scripts/deploy.sh                               # Start dashboard
./scripts/expose-ngrok.sh                         # Expose to internet

# Share temporary URL from output
```

### Option 3: GitHub Pages (Reports)
Perfect for sharing static snapshots/reports weekly

See [REMOTE-ACCESS.md](./REMOTE-ACCESS.md) for setup

---

**Full guide: [REMOTE-ACCESS.md](./REMOTE-ACCESS.md)**

Includes comparison table, setup instructions, security considerations, and troubleshooting.

---

## System Components

After `deploy.sh`, you'll have:

| Component | What It Does | Port | Status Command |
|-----------|-------------|------|-----------------|
| **C++ Parser** | Reads SSH logs, writes metrics | (host) | `./scripts/monitor.sh` |
| **Python Exporter** | Converts metrics to Prometheus format | 9101 | `curl http://localhost:9101/metrics` |
| **Prometheus** | Stores metrics & evaluates alerts | 9090 | `curl http://localhost:9090` |
| **Grafana** | Dashboard visualization | 3000 | http://localhost:3000 |

---

## Monitoring & Troubleshooting

### Check System Status

```bash
./scripts/monitor.sh
```

Shows:
- C++ Parser status and resource usage
- Docker container status
- Metrics file info
- Dashboard accessibility
- Recent logs

### View Real-Time Parser Logs

```bash
./scripts/monitor.sh --tail
```

Streams parser logs as they happen. Press `Ctrl+C` to stop.

### View Metrics

```bash
./scripts/monitor.sh --metrics
```

Shows the current metrics JSON file - useful for debugging what the parser is collecting.

---

## Optional: Auto-Start on Login (macOS)

If you want SSH-Monitor to automatically start when you log in:

### Install Auto-Start Service

```bash
./scripts/setup-launchd.sh install
```

This creates a macOS launchd service that:
- Starts automatically when you log in
- Restarts if services crash
- Logs output to `~/Library/Logs/ssh-monitor.log`

### Manage the Service

```bash
# Check status
./scripts/setup-launchd.sh status

# Manually start/stop
launchctl start local.ssh-monitor
launchctl stop local.ssh-monitor

# View logs
tail -f ~/Library/Logs/ssh-monitor.log

# Uninstall auto-start
./scripts/setup-launchd.sh uninstall
```

---

## Common Tasks

### Simulate SSH Attacks

Generate fake attack traffic to test the dashboard:

```bash
sudo ./scripts/simulate_attack.sh
```

The script auto-detects your OS and uses the correct log file:
- **macOS**: `/var/log/system.log`
- **Linux**: `/var/log/auth.log`

You can also specify a custom log file:

```bash
sudo ./scripts/simulate_attack.sh /tmp/test_auth.log
```

### Restart Services Without Full Redeploy

```bash
# Stop everything
./scripts/teardown.sh

# Start everything again
./scripts/deploy.sh
```

### Change Grafana Password

1. Visit http://localhost:3000
2. Click your avatar (bottom-left)
3. Select "Change password"
4. Default password is `admin`

### View Prometheus Alerts

1. Visit http://localhost:9090/alerts
2. Shows active and inactive alert rules
3. Default threshold: 10 failed logins per minute

### Increase Log Retention

Edit `docker-compose.yml` and modify the Prometheus command:

```yaml
command:
  - "--storage.tsdb.retention.time=30d"  # Change from 7d to 30d
```

Then restart:
```bash
./scripts/teardown.sh
./scripts/deploy.sh
```

---

## Architecture

```
Your macOS System
├── C++ SSH Parser (Host Process)
│   └── Reads /var/log/system.log
│       └── Writes ./shared/ssh_metrics.json
│
└── Docker Services (Containers)
    ├── Python Exporter (port 9101)
    │   └── Reads ./shared/ssh_metrics.json
    │       └── Exposes Prometheus metrics
    │
    ├── Prometheus (port 9090)
    │   └── Scrapes Python exporter every 5s
    │       └── Stores metrics in time-series DB
    │
    └── Grafana (port 3000)
        └── Queries Prometheus
            └── Displays beautiful dashboards
```

---

## Troubleshooting

### Parser not starting

```bash
./scripts/build-parser.sh
```

Then manually test:

```bash
./cpp-parser/ssh_parser --log /var/log/system.log --out ./shared/ssh_metrics.json
```

### Docker services failing

```bash
# Check logs
docker compose logs

# Restart services
./scripts/teardown.sh
./scripts/deploy.sh
```

### No metrics appearing in Grafana

1. Check metrics file exists:
   ```bash
   ./scripts/monitor.sh --metrics
   ```

2. Check Prometheus scraping:
   ```bash
   curl -s 'http://localhost:9090/api/v1/query?query=ssh_failed_logins_total'
   ```

3. Verify exporter is running:
   ```bash
   curl http://localhost:9101/metrics
   ```

### Dashboard showing "No data"

1. Run an attack simulator:
   ```bash
   sudo ./scripts/simulate_attack.sh
   ```

2. Wait 5-10 seconds for metrics to be scraped

3. Refresh Grafana (F5)

---

## Files Reference

### Deployment Scripts

| Script | Purpose |
|--------|---------|
| `scripts/deploy.sh` | Start all services |
| `scripts/teardown.sh` | Stop all services |
| `scripts/monitor.sh` | Check status & view logs |
| `scripts/setup-launchd.sh` | Auto-start configuration (macOS) |
| `scripts/build-parser.sh` | Compile C++ parser |
| `scripts/launch-parser.sh` | Manual parser launch |
| `scripts/simulate_attack.sh` | Generate test attacks |

### Configuration Files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Docker service definitions |
| `prometheus/prometheus.yml` | Prometheus scrape config |
| `prometheus/alert_rules.yml` | Alert thresholds |
| `grafana/provisioning/*` | Grafana dashboards & datasources |
| `python-exporter/exporter.py` | Metrics conversion logic |
| `cpp-parser/src/main.cpp` | Log parsing logic |

### Data Files

| File | Purpose |
|------|---------|
| `shared/ssh_metrics.json` | Current metrics (written by parser) |
| `.parser.pid` | Parser process ID |
| `.parser.log` | Parser output log |
| `prometheus-data/` | Prometheus time-series database |
| `grafana-data/` | Grafana configuration database |

---

## Performance Notes

### Resource Usage

- **C++ Parser**: ~5-10 MB RAM, minimal CPU (only when log changes)
- **Python Exporter**: ~30-50 MB RAM
- **Prometheus**: ~100-200 MB RAM (depends on retention)
- **Grafana**: ~80-150 MB RAM

Total: ~300-700 MB RAM for full stack

### Log Retention

By default, Prometheus stores 7 days of metrics. Change in `docker-compose.yml`:

```yaml
command:
  - "--storage.tsdb.retention.time=7d"  # Adjust here
```

Options: `1d`, `7d`, `30d`, `365d`, etc.

---

## Security Notes

### Grafana Credentials

**Change default password immediately in production:**

```bash
curl -X PUT http://admin:admin@localhost:3000/api/user/password \
  -H "Content-Type: application/json" \
  -d '{"oldPassword":"admin","newPassword":"YourNewPassword","confirmNew":"YourNewPassword"}'
```

### Log File Access

The parser needs read access to system logs:
- `-` Your user typically has this access
- `sudo` required for `simulate_attack.sh` to write test entries

### Docker Security

Services run with default Docker security:
- No network exposure outside localhost
- Bind mounts use `:ro` (read-only) where possible
- Container restart policy: `unless-stopped` (safe)

---

## FAQ

**Q: Can I run this on Linux?**  
A: Yes! All scripts work on Ubuntu/Debian/WSL. Just use `./scripts/deploy.sh` - it auto-detects `/var/log/auth.log` on Linux.

**Q: What if services crash?**  
A: Docker services auto-restart (`restart: unless-stopped`). If using `setup-launchd.sh`, the parser also auto-restarts.

**Q: Can I customize the dashboard?**  
A: Yes! Edit `grafana/provisioning/dashboards/ssh_monitoring.json` or create new ones in Grafana web UI.

**Q: How do I monitor remote systems?**  
A: Deploy this on each remote system, or centralize log collection using tools like rsyslog/syslog-ng before the parser.

**Q: Can I change alert thresholds?**  
A: Yes! Edit `prometheus/alert_rules.yml` and restart with `./scripts/teardown.sh && ./scripts/deploy.sh`.

**Q: Do I need to execute scripts with sudo?**  
A: - `deploy.sh`, `teardown.sh`, `monitor.sh`, `setup-launchd.sh`: **No**  
- `simulate_attack.sh`: **Yes** (needs to write to system logs)  
- `build-parser.sh`: **No** 

---

## Getting Help

### View Logs

```bash
# Parser logs
./scripts/monitor.sh --tail

# Docker service logs
docker compose logs python-exporter
docker compose logs prometheus
docker compose logs grafana
```

### Check Configuration

```bash
# Check what's in metrics file
./scripts/monitor.sh --metrics

# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq .

# Test alert evaluation
curl -s 'http://localhost:9090/api/v1/query?query=ALERTS'
```

### Reset Everything

If something gets stuck, nuke it and start fresh:

```bash
./scripts/teardown.sh
docker system prune -a --volumes  # CAREFUL: removes all Docker data
./scripts/deploy.sh
```
