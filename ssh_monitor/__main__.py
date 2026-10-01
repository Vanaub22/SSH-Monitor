"""Command-line entry point for SSH Monitor."""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading

from ssh_monitor.server import create_server
from ssh_monitor.sources import create_source
from ssh_monitor.state import MonitorState


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def _port(value: str) -> int:
    parsed = _positive_integer(value)
    if parsed > 65535:
        raise argparse.ArgumentTypeError("value must not exceed 65535")
    return parsed


def _positive_number(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return parsed


def _host(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("value must not be empty")
    return value


def _source_kind(value: str) -> str:
    allowed = ("demo", "file", "system")
    if value not in allowed:
        raise argparse.ArgumentTypeError(f"value must be one of: {', '.join(allowed)}")
    return value


def _environment_boolean(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    if raw_value.lower() == "true":
        return True
    if raw_value.lower() == "false":
        return False
    raise argparse.ArgumentTypeError(f"{name} must be true or false")


def build_parser() -> argparse.ArgumentParser:
    """Build the documented command-line interface."""
    parser = argparse.ArgumentParser(
        prog="ssh-monitor",
        description="Show SSH sign-in activity in a beginner-friendly local dashboard.",
    )
    parser.add_argument(
        "--source",
        type=_source_kind,
        choices=("demo", "file", "system"),
        default=os.getenv("SSH_MONITOR_SOURCE", "demo"),
        help="event source to use (default: demo)",
    )
    parser.add_argument(
        "--log-file",
        default=os.getenv("SSH_MONITOR_LOG_FILE"),
        help="text log to follow when the source is file",
    )
    parser.add_argument(
        "--host",
        type=_host,
        default=os.getenv("SSH_MONITOR_HOST", "127.0.0.1"),
        help="network address for the dashboard (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=_port,
        default=os.getenv("SSH_MONITOR_PORT", "8080"),
        help="dashboard port (default: 8080)",
    )
    parser.add_argument(
        "--alert-threshold",
        type=_positive_integer,
        default=os.getenv("SSH_MONITOR_ALERT_THRESHOLD", "10"),
        help="failed sign-ins in the time window before a warning appears",
    )
    parser.add_argument(
        "--window-seconds",
        type=_positive_integer,
        default=os.getenv("SSH_MONITOR_WINDOW_SECONDS", "60"),
        help="rolling warning window in seconds (default: 60)",
    )
    parser.add_argument(
        "--poll-interval",
        type=_positive_number,
        default=os.getenv("SSH_MONITOR_POLL_INTERVAL", "0.5"),
        help="delay between file checks in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--ignore-existing",
        action=argparse.BooleanOptionalAction,
        default=_environment_boolean("SSH_MONITOR_IGNORE_EXISTING"),
        help="whether to ignore log lines that existed before the monitor started",
    )
    return parser


def main() -> int:
    """Start collection and serve the local dashboard until interrupted."""
    try:
        parser = build_parser()
    except argparse.ArgumentTypeError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        source, source_name = create_source(
            args.source,
            args.log_file,
            not args.ignore_existing,
            args.poll_interval,
        )
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    state = MonitorState(
        source_name=source_name,
        alert_threshold=args.alert_threshold,
        window_seconds=args.window_seconds,
    )
    stop_event = threading.Event()
    collector = threading.Thread(
        target=source.run,
        args=(stop_event, state.record, state.set_source_error),
        name="event-collector",
        daemon=True,
    )
    collector.start()

    try:
        server = create_server(args.host, args.port, state)
    except OSError as exc:
        stop_event.set()
        print(f"Could not start the dashboard on port {args.port}: {exc}", file=sys.stderr)
        return 1

    visible_host = "localhost" if args.host in ("0.0.0.0", "127.0.0.1") else args.host
    print(f"SSH Monitor is running at http://{visible_host}:{args.port}")
    print(f"Data source: {source_name}")
    print("Press Ctrl+C to stop.")

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping SSH Monitor.")
    finally:
        stop_event.set()
        server.server_close()
        collector.join(timeout=4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
