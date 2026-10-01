from __future__ import annotations

import json
import threading
import unittest
import urllib.request

from ssh_monitor.server import create_server
from ssh_monitor.state import MonitorState


class DashboardServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = MonitorState("Test source", alert_threshold=10, window_seconds=60)
        self.server = create_server("127.0.0.1", 0, self.state)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=1)

    def read(self, path: str) -> tuple[int, str, str]:
        with urllib.request.urlopen(self.base_url + path, timeout=2) as response:
            return (
                response.status,
                response.headers.get_content_type(),
                response.read().decode("utf-8"),
            )

    def test_serves_dashboard(self) -> None:
        status, content_type, body = self.read("/")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html")
        self.assertIn("SSH Monitor", body)

    def test_serves_status_json(self) -> None:
        status, content_type, body = self.read("/api/status")
        data = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json")
        self.assertEqual(data["source"], "Test source")

    def test_health_reports_source_problem(self) -> None:
        self.state.set_source_error("Unavailable")
        _, _, body = self.read("/health")
        self.assertFalse(json.loads(body)["source_available"])


if __name__ == "__main__":
    unittest.main()
