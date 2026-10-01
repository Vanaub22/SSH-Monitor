"""Small HTTP server for the dashboard and its JSON status endpoint."""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ssh_monitor.state import MonitorState


LOGGER = logging.getLogger(__name__)


class DashboardServer(ThreadingHTTPServer):
    """HTTP server carrying references needed by request handlers."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], state: MonitorState, web_root: Path):
        self.state = state
        self.web_root = web_root
        super().__init__(address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    """Serve the dashboard, current status, and a health check."""

    server: DashboardServer

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send_file(self.server.web_root / "index.html", "text/html; charset=utf-8")
            return
        if self.path == "/api/status":
            self._send_json(self.server.state.snapshot())
            return
        if self.path == "/health":
            snapshot = self.server.state.snapshot()
            self._send_json(
                {
                    "status": "healthy",
                    "source_available": snapshot["source_error"] is None,
                }
            )
            return
        self.send_error(404, "Page not found")

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'",
        )

    def _send_file(self, path: Path, content_type: str) -> None:
        try:
            content = path.read_bytes()
        except OSError:
            self.send_error(500, "Dashboard file is unavailable")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, value: dict[str, Any]) -> None:
        content = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format_string: str, *args: object) -> None:
        LOGGER.debug(format_string, *args)


def create_server(host: str, port: int, state: MonitorState) -> DashboardServer:
    """Create a configured dashboard server."""
    web_root = Path(__file__).resolve().parent / "web"
    return DashboardServer((host, port), state, web_root)
