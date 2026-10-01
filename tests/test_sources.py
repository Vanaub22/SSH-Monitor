from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ssh_monitor.sources import CommandSource, DemoSource, FileSource, create_source


class FileSourceTests(unittest.TestCase):
    def test_reads_existing_and_appended_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.log"
            path.write_text(
                "sshd: Failed password for root from 203.0.113.2 port 22 ssh2\n",
                encoding="utf-8",
            )
            events = []
            errors = []
            stopped = threading.Event()
            source = FileSource(path, read_existing=True, poll_interval=0.01)
            worker = threading.Thread(
                target=source.run,
                args=(stopped, events.append, errors.append),
                daemon=True,
            )
            worker.start()

            deadline = time.time() + 2
            while len(events) < 1 and time.time() < deadline:
                time.sleep(0.01)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(
                    "sshd: Accepted password for operator from 192.0.2.4 port 22 ssh2\n"
                )
                stream.flush()
            while len(events) < 2 and time.time() < deadline:
                time.sleep(0.01)

            stopped.set()
            worker.join(timeout=1)
            self.assertEqual([event.outcome for event in events], ["failed", "successful"])
            self.assertIn(None, errors)


class SourceSelectionTests(unittest.TestCase):
    def test_demo_source_needs_no_configuration(self) -> None:
        source, label = create_source("demo", None, True, 0.5)
        self.assertIsInstance(source, DemoSource)
        self.assertEqual(label, "Demonstration data")

    def test_file_source_requires_a_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "--log-file"):
            create_source("file", None, True, 0.5)

    def test_windows_system_source_uses_powershell(self) -> None:
        with patch("ssh_monitor.sources.platform.system", return_value="Windows"):
            source, label = create_source("system", None, True, 0.5)
        self.assertIsInstance(source, CommandSource)
        self.assertEqual(source.command[0], "powershell.exe")
        self.assertEqual(label, "Windows OpenSSH event log")

    def test_unknown_system_is_rejected(self) -> None:
        with patch("ssh_monitor.sources.platform.system", return_value="UnsupportedOS"):
            with self.assertRaisesRegex(ValueError, "not supported"):
                create_source("system", None, True, 0.5)


if __name__ == "__main__":
    unittest.main()
