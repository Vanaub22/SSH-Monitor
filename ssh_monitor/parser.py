"""Parse common OpenSSH authentication messages into structured events."""

from __future__ import annotations

import ipaddress
import re

from ssh_monitor.models import SignInEvent


FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>[^\s]+) "
    r"from (?P<address>[^\s]+)",
    re.IGNORECASE,
)
INVALID_USER = re.compile(
    r"Invalid user (?P<user>[^\s]+) from (?P<address>[^\s]+)",
    re.IGNORECASE,
)
PAM_FAILURE = re.compile(
    r"authentication failure;.*?rhost=(?P<address>[^\s;]+).*?user=(?P<user>[^\s;]*)",
    re.IGNORECASE,
)
ACCEPTED_SIGN_IN = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) "
    r"for (?P<user>[^\s]+) from (?P<address>[^\s]+)",
    re.IGNORECASE,
)


def _normalise_address(value: str) -> str | None:
    """Return a valid IP address without brackets, or None when invalid."""
    candidate = value.strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _event_from_match(match: re.Match[str], outcome: str) -> SignInEvent | None:
    address = _normalise_address(match.group("address"))
    if address is None:
        return None
    username = match.group("user") or "unknown"
    return SignInEvent.create(outcome, address, username)


def parse_line(line: str) -> SignInEvent | None:
    """Parse one log line and return None when it is not a supported SSH event."""
    for pattern in (FAILED_PASSWORD, INVALID_USER, PAM_FAILURE):
        match = pattern.search(line)
        if match:
            return _event_from_match(match, "failed")

    match = ACCEPTED_SIGN_IN.search(line)
    if match:
        return _event_from_match(match, "successful")
    return None
