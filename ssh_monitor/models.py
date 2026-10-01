"""Data models shared by the parser, state store, and web server."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class SignInEvent:
    """A successful or failed SSH sign-in attempt."""

    outcome: str
    source_address: str
    username: str
    observed_at: datetime

    @classmethod
    def create(cls, outcome: str, source_address: str, username: str) -> "SignInEvent":
        """Create an event using the current time in UTC."""
        return cls(
            outcome=outcome,
            source_address=source_address,
            username=username,
            observed_at=datetime.now(timezone.utc),
        )

    def as_dict(self) -> dict[str, str]:
        """Return a JSON-compatible representation for the dashboard."""
        return {
            "outcome": self.outcome,
            "source_address": self.source_address,
            "username": self.username,
            "observed_at": self.observed_at.isoformat(),
        }
