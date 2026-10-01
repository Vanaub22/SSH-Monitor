from __future__ import annotations

import unittest

from ssh_monitor.parser import parse_line


class ParseLineTests(unittest.TestCase):
    def test_parses_failed_password(self) -> None:
        event = parse_line(
            "Jan 10 host sshd[42]: Failed password for root from 203.0.113.9 port 22 ssh2"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "failed")
        self.assertEqual(event.username, "root")
        self.assertEqual(event.source_address, "203.0.113.9")

    def test_parses_invalid_user(self) -> None:
        event = parse_line(
            "Jan 10 host sshd[42]: Invalid user guest from 198.51.100.4 port 2200"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "failed")
        self.assertEqual(event.username, "guest")

    def test_parses_successful_public_key_with_ipv6(self) -> None:
        event = parse_line(
            "sshd[42]: Accepted publickey for deploy from 2001:db8::10 port 9922 ssh2"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "successful")
        self.assertEqual(event.source_address, "2001:db8::10")

    def test_parses_pam_failure(self) -> None:
        event = parse_line(
            "sshd[42]: pam_unix(sshd:auth): authentication failure; "
            "rhost=192.0.2.90 user=operator"
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.outcome, "failed")
        self.assertEqual(event.username, "operator")

    def test_ignores_unrelated_lines(self) -> None:
        self.assertIsNone(parse_line("A normal application message"))

    def test_rejects_invalid_source_address(self) -> None:
        self.assertIsNone(parse_line("Failed password for root from unknown port 22"))


if __name__ == "__main__":
    unittest.main()
