# Hybrid C++ and Python Real-Time SSH Security Monitoring System

A production-style monitoring pipeline that detects SSH brute-force attacks in
real time using a **C++ log parser**, a **Python Prometheus exporter**, and a
**Grafana** dashboard — all orchestrated with Docker Compose.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE (Linux)                              │
│                                                                          │
│   /var/log/auth.log                                                      │
│        │  (append by sshd)                                               │
│        ▼                                                                 │
│  ┌────────────────────┐    JSON file     ┌────────────────────────────┐  │
│  │  C++ SSH Parser     │ ──────────────▶ │  Python Prometheus         │  │
│  │  (cpp-parser)       │  /shared/       │  Exporter (python-exporter)│  │
│  │                     │  ssh_metrics    │                            │  │
│  │  • ifstream tail    │  .json          │  • prometheus_client       │  │
│  │  • regex matching   │                 │  • 5-min moving avg        │  │
│  │  • unordered_map    │                 │  • alert evaluation        │  │
│  │  • time bucketing   │                 │  • port 9101               │  │
│  └────────────────────┘                  └──────────┬─────────────────┘  │
│                                                     │  :9101/metrics     │
│                                                     ▼                    │
│                                          ┌──────────────────────┐        │
│                                          │  Prometheus           │        │
│                                          │  • scrape every 5s   │        │
│                                          │  • alert rules        │        │
│                                          │  • port 9090          │        │
│                                          └──────────┬───────────┘        │
│                                                     │  PromQL            │
│                                                     ▼                    │
│                                          ┌──────────────────────┐        │
│                                          │  Grafana              │        │
│                                          │  • auto-provisioned  │        │
│                                          │  • dashboards         │        │
│                                          │  • port 3000          │        │
│                                          └──────────────────────┘        │
└──────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **sshd** writes authentication events to `/var/log/auth.log`.
2. The **C++ parser** tails the log file with `ifstream` + `getline`, parses
   each line for SSH events, and writes a JSON summary to a shared volume
   every second.
3. The **Python exporter** polls the JSON file the JSON file and translates it
   into Prometheus metrics exposed on `:9101/metrics`.
4. **Prometheus** scrapes the exporter every 5 seconds and evaluates alert rules.
5. **Grafana** queries Prometheus via PromQL and renders the dashboard.

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Linux host with `/var/log/auth.log` (or use the simulator)

### Launch

```bash
# Clone the project
cd "SSH Security Monitoring System"

# Build and start all services
docker compose up --build -d

# In another terminal, simulate an attack (requires sudo)
sudo ./scripts/simulate_attack.sh
```

### Access

| Service    | URL                        | Credentials    |
|------------|----------------------------|----------------|
| Grafana    | http://localhost:3000       | admin / admin  |
| Prometheus | http://localhost:9090       | —              |
| Exporter   | http://localhost:9101/metrics | —            |

---

## Project Structure

```
.
├── cpp-parser/
│   ├── CMakeLists.txt         # Build system
│   ├── Dockerfile             # Multi-stage build
│   ├── include/
│   │   └── parser.h           # Data structures & class interface
│   └── src/
│       └── main.cpp           # Core parser implementation
├── python-exporter/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── exporter.py            # Prometheus metrics bridge
├── prometheus/
│   ├── prometheus.yml          # Scrape config
│   └── alert_rules.yml        # Alert definitions
├── grafana/
│   └── provisioning/
│       ├── dashboards/
│       │   ├── dashboard.yml       # Provider config
│       │   └── ssh_monitoring.json # Dashboard definition
│       └── datasources/
│           └── datasource.yml      # Prometheus datasource
├── scripts/
│   └── simulate_attack.sh     # Attack traffic generator
├── shared/                    # Runtime: JSON bridge (Docker volume)
├── docker-compose.yml
└── README.md
```

---

## How It Works

### What is an SSH Brute-Force Attack?

An SSH brute-force attack is an automated attempt to gain unauthorized access to
a server by systematically trying many username/password combinations against the
SSH daemon (port 22).

**Typical attack pattern:**

```
Attacker                          Target Server
   │                                    │
   ├── SYN ──────────────────────────▶ │  TCP handshake
   │◀──────────────────── SYN-ACK ────┤
   ├── ACK ──────────────────────────▶ │
   │                                    │
   ├── SSH: try root / password1 ────▶ │  ← Attempt 1
   │◀──────── "Failed password" ──────┤    (logged to auth.log)
   │                                    │
   ├── SSH: try root / password2 ────▶ │  ← Attempt 2
   │◀──────── "Failed password" ──────┤    (logged to auth.log)
   │                                    │
   │         ... hundreds/thousands     │
   │              of attempts ...       │
   │                                    │
   ├── SSH: try root / correct!! ────▶ │  ← Compromise!
   │◀──────── "Accepted password" ────┤    (logged to auth.log)
```

**What appears in `/var/log/auth.log`:**

```
Feb 19 14:23:01 server sshd[1234]: Failed password for root from 203.0.113.42 port 54321 ssh2
Feb 19 14:23:02 server sshd[1234]: Failed password for root from 203.0.113.42 port 54322 ssh2
Feb 19 14:23:03 server sshd[1234]: Invalid user admin from 198.51.100.7 port 12345
Feb 19 14:25:00 server sshd[1234]: Accepted password for ubuntu from 10.0.1.1 port 22222 ssh2
```

This system monitors these log entries in real time and alerts when the failure
rate spikes.

---

### TCP Behavior During an SSH Brute-Force Attack

Each SSH login attempt involves TCP-level activity:

```
┌────────────────────────────────────────────────────────────────┐
│                    TCP Connection Lifecycle                     │
├────────────┬───────────────────────────────────────────────────┤
│ Phase      │ What happens                                      │
├────────────┼───────────────────────────────────────────────────┤
│ SYN        │ Attacker initiates TCP 3-way handshake to port 22│
│ SYN-ACK    │ Server responds, connection established           │
│ SSH Banner │ SSH protocol version exchange                     │
│ Key Exch.  │ Diffie-Hellman key exchange (encrypted channel)   │
│ Auth       │ Client sends username + password                  │
│ Response   │ Server returns success or failure                 │
│ FIN / RST  │ Connection torn down after failure                │
└────────────┴───────────────────────────────────────────────────┘
```

**Indicators at the network level:**

- **High SYN rate** to port 22 from one or few source IPs.
- **Many short-lived TCP connections** (RST after auth failure).
- **Consistent packet sizes** (automated tools use identical payloads).

A brute-force tool like `hydra` can generate hundreds of connections per second,
each creating a separate TCP session. This is why monitoring both the network
layer _and_ the application log (`auth.log`) gives the most complete picture.

---

### `unordered_map` — Usage and Time Complexity

The C++ parser uses `std::unordered_map` to count failures per IP address.
Here's why this is the optimal choice:

```cpp
// Declaration in the parser
std::unordered_map<std::string, int> failures_per_ip;

// Every time a failure is detected
failures_per_ip[ip]++;   // O(1) amortised
```

**How it works:**

`unordered_map` is a hash table. It maps keys (IP addresses) to values (counts)
using a hash function:

```
  Key (IP string)      Hash Function       Bucket Array
  ─────────────────    ─────────────       ────────────────
  "203.0.113.42"   ──▶  hash()  ──▶  ──▶  [bucket 7] → {"203.0.113.42", 15}
  "198.51.100.7"   ──▶  hash()  ──▶  ──▶  [bucket 3] → {"198.51.100.7", 8}
  "10.0.0.55"      ──▶  hash()  ──▶  ──▶  [bucket 12] → {"10.0.0.55", 3}
```

**Time complexity comparison:**

| Operation       | `unordered_map` | `map` (red-black tree) |
|-----------------|:---------------:|:----------------------:|
| Insert          | **O(1)** avg    | O(log n)               |
| Lookup          | **O(1)** avg    | O(log n)               |
| Delete          | **O(1)** avg    | O(log n)               |
| Worst case      | O(n)            | O(log n)               |
| Memory overhead | Higher          | Lower                  |
| Ordering        | None            | Sorted by key          |

**Why `unordered_map` wins here:**

1. We don't need sorted output (we sort only for the top-N display).
2. IP lookups happen on every log line — O(1) matters at high throughput.
3. The hash function for `std::string` is well-distributed for IP addresses.
4. Worst-case O(n) is extremely unlikely with IP-like keys.

**Time bucket aggregation** uses the same structure:

```cpp
// Key = epoch / 60 (minute granularity)
std::unordered_map<long, int> failures_per_minute;

long bucket = std::time(nullptr) / 60;
failures_per_minute[bucket]++;   // O(1)
```

This gives us instant "failures in the last minute" by checking at most 2 buckets
(current minute + previous minute).

---

## Metrics Reference

| Metric                         | Type  | Description                              |
|--------------------------------|-------|------------------------------------------|
| `ssh_failed_logins_total`      | Gauge | Cumulative failed SSH login attempts     |
| `ssh_successful_logins_total`  | Gauge | Cumulative successful SSH logins         |
| `ssh_failures_per_minute`      | Gauge | Failures observed in the last 60 seconds |
| `ssh_failures_moving_avg_5m`   | Gauge | 5-minute simple moving average of FPM    |
| `ssh_failures_by_ip{source_ip}`| Gauge | Failure count per source IP (top 5)      |
| `ssh_alert_high_failure_rate`  | Gauge | 1 = alert active, 0 = normal            |

---

## Alert Rules

| Alert                        | Condition                          | Severity |
|------------------------------|------------------------------------|----------|
| `HighSSHFailureRate`         | `ssh_failures_per_minute > 10`     | warning  |
| `CriticalSSHFailureRate`     | `ssh_failures_per_minute > 50`     | critical |
| `SSHExporterDown`            | Exporter unreachable for 30s       | critical |
| `ElevatedSSHFailureAverage`  | 5-min moving avg > 5 for 5 min     | warning  |

Thresholds are configurable:
- Prometheus rules: edit `prometheus/alert_rules.yml`
- Exporter threshold: set `ALERT_THRESHOLD` env var in `docker-compose.yml`

---

## Simulating an Attack

The included script generates realistic fake auth.log entries:

```bash
# Generate attack traffic (requires sudo for /var/log/auth.log)
sudo ./scripts/simulate_attack.sh

# Or target a custom file (for local testing without sudo)
./scripts/simulate_attack.sh /tmp/test_auth.log
```

**What the simulator does each round (every 2 seconds):**

- Writes 5–19 `Failed password` lines from random attacker IPs
- Writes 0–4 `Invalid user` lines with random usernames
- Writes 0–2 `Accepted password` lines (legitimate traffic)

**To test on a machine without real SSH traffic:**

```bash
# Terminal 1: Start the stack
docker compose up --build

# Terminal 2: Generate fake events
sudo ./scripts/simulate_attack.sh

# Terminal 3: Watch the JSON output
watch -n1 cat shared/ssh_metrics.json
```

---

## Configuration

### Environment Variables (Python Exporter)

| Variable           | Default                     | Description                    |
|--------------------|-----------------------------|--------------------------------|
| `METRICS_FILE`     | `/shared/ssh_metrics.json`  | Path to JSON from C++ parser   |
| `EXPORTER_PORT`    | `9101`                      | HTTP port for Prometheus scrape |
| `POLL_INTERVAL`    | `1.0`                       | Seconds between reads          |
| `ALERT_THRESHOLD`  | `10`                        | Failures/min alert threshold   |
| `MOVING_AVG_WINDOW`| `300`                       | Moving average window (seconds)|

### C++ Parser CLI Arguments

| Argument      | Default                    | Description              |
|---------------|----------------------------|--------------------------|
| `--log`, `-l` | `/var/log/auth.log`        | Log file to monitor      |
| `--out`, `-o` | `/shared/ssh_metrics.json` | JSON output path         |

---

## Building Locally (Without Docker)

### C++ Parser

```bash
cd cpp-parser
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# Run
./ssh_parser --log /var/log/auth.log --out /tmp/ssh_metrics.json
```

### Python Exporter

```bash
cd python-exporter
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

METRICS_FILE=/tmp/ssh_metrics.json python exporter.py
```

---

## Grafana Dashboard Panels

The auto-provisioned dashboard includes:

| Panel                                      | Type       | Description                                |
|--------------------------------------------|------------|--------------------------------------------|
| Total Failed Logins                        | Stat       | Big number with color thresholds           |
| Total Successful Logins                    | Stat       | Green indicator                            |
| Failures/Minute (Current)                  | Stat       | Real-time failure rate                     |
| Alert Status                               | Stat       | OK / ALERT! indicator                      |
| Failed Logins/Min + Moving Average Overlay | Time Series| Line chart with dashed MA overlay          |
| Top Attacking IPs                          | Bar Gauge  | Horizontal bars, top 5 IPs by failure count|
| Success vs Failure Ratio                   | Pie Chart  | Donut chart of login outcomes              |
| Failures Timeline (Cumulative)             | Time Series| Stacked area of total events over time     |

---

## License

MIT License. Built for educational and demonstration purposes.
