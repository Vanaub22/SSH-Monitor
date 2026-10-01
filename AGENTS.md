# Contributor and Agent Guide

## Purpose

SSH Monitor must make SSH sign-in activity understandable to people who have no prior SSH or security experience. It must remain straightforward to start on current macOS, Windows, and Linux systems.

Every change must preserve these priorities, in order:

1. Explain behavior in plain language.
2. Keep startup and configuration small and predictable.
3. Preserve cross-platform behavior.
4. Prefer safe, observable behavior over hidden automation.
5. Keep the implementation maintainable without unnecessary services or dependencies.

## Required reading

Before editing, read this file and the sections of `README.md` related to the proposed change. Inspect the relevant implementation and tests before making assumptions about behavior.

## Architecture

The application is a dependency-free Python 3.9 or newer package.

- `ssh_monitor/__main__.py` owns configuration, startup, and shutdown.
- `ssh_monitor/sources.py` obtains log lines or demonstration events. Platform-specific code belongs here.
- `ssh_monitor/parser.py` converts supported OpenSSH messages into `SignInEvent` values.
- `ssh_monitor/state.py` owns counters, the rolling warning window, and snapshots.
- `ssh_monitor/server.py` exposes the dashboard and JSON endpoints.
- `ssh_monitor/web/index.html` contains the self-contained browser interface.
- `tests/` mirrors behavior at these boundaries.

Maintain this flow:

```text
source -> parser -> state -> HTTP API -> dashboard
```

Do not let the dashboard parse raw log messages. Do not put operating-system detection in the parser. Do not make sources depend on HTTP behavior.

## Language and presentation

All user-facing text, documentation, code comments, docstrings, commit-ready configuration comments, and error messages must be formal and clear.

- Do not use emojis, pictograms, novelty banners, decorative comment dividers, or comments made from repeated punctuation.
- Do not use decorative comments such as long hyphen, equals-sign, or box-drawing separators.
- Use comments to explain a decision or non-obvious constraint. Do not narrate the next line of code.
- Use complete sentences in documentation and user-facing messages.
- Define SSH or security terminology before relying on it.
- Prefer “failed sign-in” over “attack” unless the evidence establishes malicious behavior.
- Avoid exaggerated claims such as “production-ready,” “military-grade,” or “fully secure.”
- Never label an address as an attacker solely because it produced a failed sign-in.

The dashboard must remain readable on narrow and wide screens. It must not rely on color alone to communicate status. Dynamic values must be inserted with safe DOM APIs such as `textContent`, not with untrusted HTML strings.

## Portability requirements

Code must support current macOS, Windows, and Linux installations with Python 3.9 or newer.

- Use `pathlib` for filesystem paths.
- Do not assume a POSIX shell, GNU command, drive layout, path separator, or line ending in Python code.
- Keep Docker startup compatible with Docker Compose version 2 on all three platforms.
- Document macOS, Windows, and Linux behavior when a platform-specific source changes.
- Isolate unavoidable operating-system commands behind a source implementation.
- Keep demonstration mode available when system logs cannot be accessed.
- Do not introduce a required compiler, database, JavaScript package manager, or external monitoring stack without an explicit architectural decision documented in the README.

The native dashboard must listen on loopback by default. A change that exposes it more broadly requires clear security documentation and an explicit configuration choice.

## Configuration

Every new setting must have:

1. A safe default when a default is reasonable.
2. A descriptive command-line option when it applies to native use.
3. A consistently named `SSH_MONITOR_` environment variable when it applies to Docker.
4. Validation with an actionable error.
5. A row in the README configuration table.
6. A corresponding `.env.example` entry when Docker users need it.

Do not silently select a materially different data source after a configured source fails. Report the source error on the dashboard.

## Dependencies

Prefer the Python standard library. A new runtime dependency must provide clear value that cannot be achieved simply with the standard library. If a dependency is added, pin or constrain it appropriately, document why it exists, and verify it on all supported platforms.

Browser assets must remain local. Do not require third-party fonts, scripts, analytics, or content delivery networks.

## Security and privacy

Treat usernames, addresses, and raw logs as security-sensitive information.

- Do not send collected data to external services by default.
- Do not log complete raw authentication records unless a documented diagnostic option enables it.
- Do not add automatic blocking, account modification, firewall changes, or privilege escalation as a side effect of monitoring.
- Keep API responses limited to the information needed by the dashboard.
- Retain the browser security headers unless they are replaced by stricter equivalents.
- Use documentation address ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` in examples and demonstration data.
- Never include real credentials, private keys, tokens, or personal addresses in the repository.

## Parser changes

OpenSSH messages vary by version and operating system. Parser changes must be narrow enough to avoid classifying unrelated logs.

- Validate source addresses with the `ipaddress` module.
- Support both IPv4 and IPv6 when the message format allows it.
- Return `None` for unrelated or malformed input.
- Add one positive test for each supported message form.
- Add a negative test when a broader expression could create false positives.
- Use synthetic examples with documentation-only addresses.

Do not infer intent from a parsed event. The parser records observable outcomes only.

## State and concurrency

The source thread writes state while HTTP request threads read it. All shared mutable state must remain protected by the state lock.

- Keep the rolling window based on an injectable clock so expiration can be tested without sleeping.
- Return JSON-compatible copies from `snapshot`; do not expose mutable internal collections.
- Keep recent-event storage bounded.
- Define threshold boundaries explicitly and test them.
- Avoid holding locks during file, subprocess, or network operations.

## Tests and verification

Use standard-library `unittest` unless the project deliberately adopts a test dependency.

Run these checks after every behavior change:

```console
python3 -m unittest discover -s tests -v
python3 -m compileall -q ssh_monitor tests
```

Also run the checks with `py` on Windows when Windows-specific code changes. For dashboard or HTTP changes, start the application, request `/health` and `/api/status`, and inspect the dashboard at a narrow and wide viewport. For Docker changes, run `docker compose config` and build the affected service.

Tests must be deterministic. Use temporary directories for filesystem tests, injected clocks for time behavior, and reserved documentation addresses for network examples. Do not read the developer's real authentication logs in automated tests.

## Documentation requirements

The README is part of the product. Update it in the same change whenever startup, configuration, supported messages, endpoints, limitations, or platform behavior changes.

Instructions must state:

- The directory in which a command is run when it may be ambiguous.
- Platform differences for command names such as `python3` and `py`.
- What a successful command makes available.
- How to stop or reverse a started process.
- Any permission or privacy consequence.

Examples must be copyable and must not require unexplained placeholders.

## Repository hygiene

- Preserve unrelated user changes.
- Do not commit generated bytecode, virtual environments, local `.env` files, collected logs, or build output.
- Keep executable source text in the repository rather than generated binaries.
- Remove obsolete implementation and documentation when an architecture is replaced.
- Use small functions, descriptive names, type hints, and focused modules.
- Avoid compatibility layers for architecture that no longer exists.

## Completion checklist

Before considering a change complete, confirm all applicable items:

- A person unfamiliar with SSH can understand the new behavior.
- The default demonstration still starts without log permissions.
- Native macOS, Windows, and Linux implications were considered.
- Docker Compose remains a one-command default startup.
- User-facing language and comments are formal and contain no emojis or decorative separators.
- New configuration is validated and documented.
- Parser, state, and source boundary tests cover the change.
- The full test suite and compilation checks pass.
- Health and status endpoints still return valid JSON.
- No secret, real authentication record, or generated artifact was added.
