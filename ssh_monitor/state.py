"""Thread-safe in-memory state used by the collector and dashboard."""

from __future__ import annotations

import time
from collections import Counter, deque
from collections.abc import Callable
from threading import Lock

from ssh_monitor.models import SignInEvent


class MonitorState:
    """Store session counters and calculate the current warning state."""

    def __init__(
        self,
        source_name: str,
        alert_threshold: int,
        window_seconds: int,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.source_name = source_name
        self.alert_threshold = alert_threshold
        self.window_seconds = window_seconds
        self._clock = clock
        self._started_at = clock()
        self._lock = Lock()
        self._total_failed = 0
        self._total_successful = 0
        self._failures_by_address: Counter[str] = Counter()
        self._recent_events: deque[SignInEvent] = deque(maxlen=40)
        self._recent_failures: deque[float] = deque()
        self._source_error: str | None = None

    def record(self, event: SignInEvent) -> None:
        """Record one parsed sign-in event."""
        now = self._clock()
        with self._lock:
            self._recent_events.appendleft(event)
            if event.outcome == "failed":
                self._total_failed += 1
                self._failures_by_address[event.source_address] += 1
                self._recent_failures.append(now)
            else:
                self._total_successful += 1
            self._prune(now)

    def set_source_error(self, message: str | None) -> None:
        """Publish a collection error so the dashboard can explain missing data."""
        with self._lock:
            self._source_error = message

    def _prune(self, now: float) -> None:
        oldest_allowed = now - self.window_seconds
        while self._recent_failures and self._recent_failures[0] < oldest_allowed:
            self._recent_failures.popleft()

    def snapshot(self) -> dict[str, object]:
        """Return a consistent, JSON-compatible snapshot of the current state."""
        now = self._clock()
        with self._lock:
            self._prune(now)
            recent_failure_count = len(self._recent_failures)
            warning_active = recent_failure_count >= self.alert_threshold
            top_sources = [
                {"source_address": address, "failed_attempts": count}
                for address, count in self._failures_by_address.most_common(5)
            ]
            return {
                "status": "attention" if warning_active else "normal",
                "status_message": (
                    "Repeated failed sign-ins need attention."
                    if warning_active
                    else "No unusual sign-in activity is currently visible."
                ),
                "failed_in_window": recent_failure_count,
                "window_seconds": self.window_seconds,
                "alert_threshold": self.alert_threshold,
                "total_failed": self._total_failed,
                "total_successful": self._total_successful,
                "top_sources": top_sources,
                "recent_events": [event.as_dict() for event in self._recent_events],
                "source": self.source_name,
                "source_error": self._source_error,
                "uptime_seconds": int(now - self._started_at),
            }
