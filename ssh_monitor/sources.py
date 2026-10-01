"""Event sources for demonstration, text files, and local operating systems."""

from __future__ import annotations

import os
import platform
import queue
import random
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Optional, Protocol

from ssh_monitor.models import SignInEvent
from ssh_monitor.parser import parse_line


EventCallback = Callable[[SignInEvent], None]
ErrorCallback = Callable[[Optional[str]], None]


class EventSource(Protocol):
    """Interface shared by every source implementation."""

    def run(
        self,
        stop_event: threading.Event,
        on_event: EventCallback,
        on_error: ErrorCallback,
    ) -> None:
        """Collect events until the stop event is set."""


class DemoSource:
    """Generate a small, clearly identified stream of fictional events."""

    addresses = ("203.0.113.18", "198.51.100.42", "192.0.2.77")
    usernames = ("admin", "root", "support", "test")

    def run(
        self,
        stop_event: threading.Event,
        on_event: EventCallback,
        on_error: ErrorCallback,
    ) -> None:
        on_error(None)
        generator = random.Random(24)
        event_number = 0
        while not stop_event.wait(1.25):
            event_number += 1
            successful = event_number % 9 == 0
            event = SignInEvent.create(
                "successful" if successful else "failed",
                "10.0.0.25" if successful else generator.choice(self.addresses),
                "operator" if successful else generator.choice(self.usernames),
            )
            on_event(event)


class FileSource:
    """Follow a text log while handling delayed creation and log rotation."""

    def __init__(self, path: Path, read_existing: bool, poll_interval: float) -> None:
        self.path = path
        self.read_existing = read_existing
        self.poll_interval = poll_interval

    def run(
        self,
        stop_event: threading.Event,
        on_event: EventCallback,
        on_error: ErrorCallback,
    ) -> None:
        stream = None
        identity: tuple[int, int] | None = None
        first_open = True

        while not stop_event.is_set():
            if stream is None:
                try:
                    stream = self.path.open("r", encoding="utf-8", errors="replace")
                    stat = os.fstat(stream.fileno())
                    identity = (stat.st_dev, stat.st_ino)
                    if first_open and not self.read_existing:
                        stream.seek(0, os.SEEK_END)
                    first_open = False
                    on_error(None)
                except (OSError, PermissionError) as exc:
                    on_error(f"Cannot read {self.path}: {exc}")
                    stop_event.wait(self.poll_interval)
                    continue

            line = stream.readline()
            if line:
                event = parse_line(line)
                if event is not None:
                    on_event(event)
                continue

            try:
                stat = self.path.stat()
                current_identity = (stat.st_dev, stat.st_ino)
                if current_identity != identity or stat.st_size < stream.tell():
                    stream.close()
                    stream = None
            except OSError:
                stream.close()
                stream = None
            stop_event.wait(self.poll_interval)

        if stream is not None:
            stream.close()


class CommandSource:
    """Parse lines emitted by a platform-provided log command."""

    def __init__(self, command: list[str]) -> None:
        self.command = command

    def run(
        self,
        stop_event: threading.Event,
        on_event: EventCallback,
        on_error: ErrorCallback,
    ) -> None:
        try:
            process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            on_error(f"Could not start the operating system log reader: {exc}")
            return

        lines: queue.Queue[Optional[str]] = queue.Queue()

        def read_output() -> None:
            if process.stdout is not None:
                for output_line in process.stdout:
                    lines.put(output_line)
            lines.put(None)

        threading.Thread(target=read_output, daemon=True).start()
        on_error(None)

        try:
            while not stop_event.is_set():
                try:
                    line = lines.get(timeout=0.5)
                except queue.Empty:
                    if process.poll() is not None:
                        details = ""
                        if process.stderr is not None:
                            details = process.stderr.read().strip()
                        on_error(details or "The operating system log reader stopped.")
                        return
                    continue
                if line is None:
                    on_error("The operating system log reader stopped.")
                    return
                event = parse_line(line)
                if event is not None:
                    on_event(event)
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def _linux_source(log_file: str | None, read_existing: bool, poll_interval: float) -> FileSource:
    if log_file:
        return FileSource(Path(log_file), read_existing, poll_interval)
    candidates = (Path("/var/log/auth.log"), Path("/var/log/secure"))
    path = next((candidate for candidate in candidates if candidate.exists()), candidates[0])
    return FileSource(path, read_existing, poll_interval)


def _macos_source() -> CommandSource:
    return CommandSource(
        [
            "/usr/bin/log",
            "stream",
            "--style",
            "syslog",
            "--predicate",
            'process == "sshd"',
        ]
    )


def _windows_source() -> CommandSource:
    script = (
        "Get-WinEvent -ListLog 'OpenSSH/Operational' -ErrorAction Stop | Out-Null; "
        "$items=Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 100 "
        "-ErrorAction SilentlyContinue | Sort-Object RecordId; $last=0; "
        "foreach ($item in $items) { Write-Output $item.Message; $last=$item.RecordId }; "
        "while ($true) { $filter=\"*[System[EventRecordID > $last]]\"; "
        "$items=Get-WinEvent -LogName 'OpenSSH/Operational' -FilterXPath $filter "
        "-ErrorAction SilentlyContinue | Sort-Object RecordId; "
        "foreach ($item in $items) { Write-Output $item.Message; $last=$item.RecordId }; "
        "Start-Sleep -Milliseconds 750 }"
    )
    return CommandSource(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", script]
    )


def create_source(
    source_kind: str,
    log_file: str | None,
    read_existing: bool,
    poll_interval: float,
) -> tuple[EventSource, str]:
    """Build the requested source and return it with a dashboard label."""
    if source_kind == "demo":
        return DemoSource(), "Demonstration data"
    if source_kind == "file":
        if not log_file:
            raise ValueError("--log-file is required when --source is file")
        return (
            FileSource(Path(log_file), read_existing, poll_interval),
            f"Log file: {log_file}",
        )

    system_name = platform.system()
    if system_name == "Linux":
        source = _linux_source(log_file, read_existing, poll_interval)
        return source, f"Linux authentication log: {source.path}"
    if system_name == "Darwin":
        return _macos_source(), "macOS unified system log"
    if system_name == "Windows":
        return _windows_source(), "Windows OpenSSH event log"
    raise ValueError(f"System log collection is not supported on {system_name}")
