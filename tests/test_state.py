from __future__ import annotations

import unittest

from ssh_monitor.models import SignInEvent
from ssh_monitor.state import MonitorState


class MonitorStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 100.0
        self.state = MonitorState("Test", alert_threshold=2, window_seconds=60, clock=self.clock)

    def clock(self) -> float:
        return self.now

    def event(self, outcome: str, address: str = "203.0.113.5") -> SignInEvent:
        return SignInEvent.create(outcome, address, "root")

    def test_warning_appears_at_threshold(self) -> None:
        self.state.record(self.event("failed"))
        self.assertEqual(self.state.snapshot()["status"], "normal")
        self.state.record(self.event("failed"))
        self.assertEqual(self.state.snapshot()["status"], "attention")

    def test_warning_clears_after_window_but_session_total_remains(self) -> None:
        self.state.record(self.event("failed"))
        self.state.record(self.event("failed"))
        self.now += 61
        snapshot = self.state.snapshot()
        self.assertEqual(snapshot["status"], "normal")
        self.assertEqual(snapshot["failed_in_window"], 0)
        self.assertEqual(snapshot["total_failed"], 2)

    def test_counts_success_and_ranks_failed_sources(self) -> None:
        self.state.record(self.event("successful", "192.0.2.8"))
        self.state.record(self.event("failed", "198.51.100.7"))
        self.state.record(self.event("failed", "198.51.100.7"))
        snapshot = self.state.snapshot()
        self.assertEqual(snapshot["total_successful"], 1)
        self.assertEqual(snapshot["top_sources"][0]["source_address"], "198.51.100.7")
        self.assertEqual(snapshot["top_sources"][0]["failed_attempts"], 2)


if __name__ == "__main__":
    unittest.main()
