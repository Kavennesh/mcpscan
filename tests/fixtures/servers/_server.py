"""Shared plumbing for the MCP fixture servers.

These files are *targets*, not scanner code. They run inside the runner container
as the untrusted process, so they import nothing from ``mcpscan`` and use only the
standard library -- the same rule the escape fixtures follow.

Unlike those, nothing here spawns a process, so this directory needs no exemption
in ``tests/test_containment.py``. If a fixture ever does need to fork, that is a
deliberate decision requiring a visible exemption, not something to slip in.

The helpers are deliberately thin and unvalidating. A fixture whose job is to
violate the spec must be able to write whatever bytes it likes, so
:func:`write_raw` exists alongside :func:`write_message` and neither of them
checks anything.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any

PROTOCOL_VERSION = "2025-11-25"


def read_message() -> dict[str, Any] | None:
    """Next line from stdin as a parsed object. ``None`` at EOF.

    An unparseable line comes back as ``{}`` rather than raising: the client
    under test is entitled to send us garbage too, and a fixture that dies on it
    would turn a client bug into a confusing container crash.
    """
    line = sys.stdin.readline()
    if not line:
        return None
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def write_raw(text: str) -> None:
    """Write bytes verbatim. No framing, no validation -- that is the point."""
    sys.stdout.write(text)
    sys.stdout.flush()


def write_message(payload: dict[str, Any]) -> None:
    write_raw(json.dumps(payload) + "\n")


def respond(request_id: Any, result: dict[str, Any]) -> None:
    write_message({"jsonrpc": "2.0", "id": request_id, "result": result})


def fail(request_id: Any, code: int, message: str) -> None:
    write_message(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    )


def notify(method: str, params: dict[str, Any] | None = None) -> None:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        payload["params"] = params
    write_message(payload)


def initialize_result(
    *,
    version: str = PROTOCOL_VERSION,
    capabilities: dict[str, Any] | None = None,
    instructions: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": True}} if capabilities is None else capabilities,
        "serverInfo": {"name": "fixture", "title": "mcpscan fixture", "version": "0.0.1"},
    }
    if instructions is not None:
        result["instructions"] = instructions
    return result


def serve(handle: Callable[[dict[str, Any]], None]) -> None:
    """Read messages until stdin closes, handing each to ``handle``.

    EOF ends the loop, which is how the spec says a client shuts a stdio server
    down: close the input stream first, then escalate.
    """
    while True:
        message = read_message()
        if message is None:
            return
        handle(message)
