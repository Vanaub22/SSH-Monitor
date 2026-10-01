from __future__ import annotations

import argparse
import contextlib
import io
import os
import unittest
from unittest.mock import patch

from ssh_monitor.__main__ import build_parser


class ConfigurationTests(unittest.TestCase):
    def test_defaults_are_validated_and_converted(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            arguments = build_parser().parse_args([])
        self.assertEqual(arguments.source, "demo")
        self.assertEqual(arguments.port, 8080)
        self.assertEqual(arguments.poll_interval, 0.5)
        self.assertFalse(arguments.ignore_existing)

    def test_command_line_can_disable_environment_boolean(self) -> None:
        with patch.dict(os.environ, {"SSH_MONITOR_IGNORE_EXISTING": "true"}, clear=True):
            arguments = build_parser().parse_args(["--no-ignore-existing"])
        self.assertFalse(arguments.ignore_existing)

    def test_invalid_environment_boolean_is_rejected(self) -> None:
        with patch.dict(os.environ, {"SSH_MONITOR_IGNORE_EXISTING": "sometimes"}, clear=True):
            with self.assertRaises(argparse.ArgumentTypeError):
                build_parser()

    def test_invalid_environment_port_is_rejected(self) -> None:
        with patch.dict(os.environ, {"SSH_MONITOR_PORT": "70000"}, clear=True):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    build_parser().parse_args([])


if __name__ == "__main__":
    unittest.main()
