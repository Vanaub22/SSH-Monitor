"""
exporter.py – Prometheus Metrics Exporter (Python Service)

Reads the JSON file produced by the C++ SSH log parser and exposes
Prometheus-compatible metrics on port 9101.

Metrics exposed:
  - ssh_failed_logins_total        (Counter)
  - ssh_successful_logins_total    (Counter)
  - ssh_failures_per_minute        (Gauge)
  - ssh_failures_moving_avg_5m     (Gauge)   – 5-minute simple moving average
  - ssh_failures_by_ip             (Gauge)   – top 5 attacking IPs

Architecture:
  C++ parser  ──JSON──▶  /shared/ssh_metrics.json  ──▶  this exporter  ──▶  Prometheus
"""

import json
import os
import time
import logging
from collections import deque

from prometheus_client import start_http_server, Gauge, Counter, Info

# ─── Configuration ────────────────────────────────────────────────────────────

METRICS_FILE   = os.getenv("METRICS_FILE", "/shared/ssh_metrics.json")
EXPORTER_PORT  = int(os.getenv("EXPORTER_PORT", "9101"))
POLL_INTERVAL  = float(os.getenv("POLL_INTERVAL", "1.0"))  # seconds
MOVING_AVG_WIN = int(os.getenv("MOVING_AVG_WINDOW", "300"))  # 5 min in seconds
ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", "10"))    # failures/min

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [exporter] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ─── Prometheus Metrics ──────────────────────────────────────────────────────

failed_logins_total = Gauge(
    "ssh_failed_logins_total",
    "Cumulative number of failed SSH login attempts",
)
successful_logins_total = Gauge(
    "ssh_successful_logins_total",
    "Cumulative number of successful SSH logins",
)
failures_per_minute = Gauge(
    "ssh_failures_per_minute",
    "SSH login failures observed in the last minute",
)
failures_moving_avg = Gauge(
    "ssh_failures_moving_avg_5m",
    "5-minute simple moving average of failures per minute",
)
failures_by_ip = Gauge(
    "ssh_failures_by_ip",
    "Failed login attempts per source IP (top 5)",
    ["source_ip"],
)
alert_active = Gauge(
    "ssh_alert_high_failure_rate",
    "1 if failures_per_minute exceeds threshold, 0 otherwise",
)
service_info = Info(
    "ssh_exporter",
    "Metadata about the SSH metrics exporter",
)

# ─── Moving Average Calculator ───────────────────────────────────────────────

class MovingAverage:
    """
    Simple moving average over a configurable window (default 5 min).

    Uses collections.deque with maxlen so the oldest samples are
    automatically discarded – O(1) append, O(n) average (n ≤ window).
    """

    def __init__(self, window_seconds: int = 300, sample_interval: int = 1):
        max_samples = window_seconds // max(sample_interval, 1)
        self.samples: deque = deque(maxlen=max_samples)

    def add(self, value: float):
        self.samples.append(value)

    def average(self) -> float:
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)


# ─── Core Loop ───────────────────────────────────────────────────────────────

def read_metrics(path: str) -> dict | None:
    """Read and parse the JSON metrics file written by the C++ parser."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        log.warning("Malformed JSON in %s: %s", path, e)
        return None
    except Exception as e:
        log.error("Error reading %s: %s", path, e)
        return None


def update_metrics(data: dict, mavg: MovingAverage):
    """Push parsed JSON values into Prometheus gauges."""
    tf = data.get("total_failures", 0)
    ts = data.get("total_successes", 0)
    fpm = data.get("failures_last_minute", 0)

    failed_logins_total.set(tf)
    successful_logins_total.set(ts)
    failures_per_minute.set(fpm)

    # Moving average
    mavg.add(fpm)
    failures_moving_avg.set(round(mavg.average(), 2))

    # Alert evaluation
    alert_active.set(1 if fpm > ALERT_THRESHOLD else 0)

    # Top 5 IPs by failure count
    ip_map = data.get("failures_per_ip", {})
    top_ips = sorted(ip_map.items(), key=lambda x: x[1], reverse=True)[:5]

    # Clear old labels by setting them to 0 first isn't ideal;
    # instead we re-expose only the current top 5.
    # (In production, use a dedicated label-managed pattern.)
    for ip, count in top_ips:
        failures_by_ip.labels(source_ip=ip).set(count)

    log.info(
        "failures=%d  successes=%d  fpm=%d  mavg=%.2f  alert=%s",
        tf, ts, fpm, mavg.average(),
        "ACTIVE" if fpm > ALERT_THRESHOLD else "ok",
    )


def main():
    log.info("Starting SSH Prometheus exporter on port %d", EXPORTER_PORT)
    log.info("Reading metrics from %s (poll every %.1fs)", METRICS_FILE, POLL_INTERVAL)
    log.info("Alert threshold: %d failures/min", ALERT_THRESHOLD)

    service_info.info({
        "version": "1.0.0",
        "metrics_file": METRICS_FILE,
        "alert_threshold": str(ALERT_THRESHOLD),
    })

    start_http_server(EXPORTER_PORT)
    log.info("Prometheus HTTP server started.")

    mavg = MovingAverage(window_seconds=MOVING_AVG_WIN, sample_interval=int(POLL_INTERVAL))

    while True:
        data = read_metrics(METRICS_FILE)
        if data is not None:
            update_metrics(data, mavg)
        else:
            log.debug("Waiting for metrics file...")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
