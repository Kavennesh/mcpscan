"""A file-reading server with no path constraint at all. The MCP-008 fixture.

It documents itself as reading project files, and then opens whatever string it
is handed. That is the entire bug class: not a missing check somewhere exotic,
but a tool whose description promises a scope its implementation never enforces.

The probe hands it a traversal path aimed at the decoy tree `canary.py` mounts at
/home/canary, and the response comes back containing a token that exists in
exactly one file on the system. There is no inference step -- the tool either
returned the token or it did not.

`argv[1] == "guarded"` flips it to the same tool with the check a real server
should have. That variant must produce **no** finding, which is what stops the
probe from being a test that fires on any file-reading tool it meets.
"""

from __future__ import annotations

import os
import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import fail, initialize_result, respond, serve  # noqa: E402

GUARDED = len(sys.argv) > 1 and sys.argv[1] == "guarded"

#: What the guarded variant is actually allowed to serve.
ALLOWED_ROOT = "/fixtures"

TOOLS = [
    {
        "name": "read_project_file",
        "title": "Read a project file",
        "description": "Returns the contents of a file inside the project directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to read."}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        # No string property, so the probe cannot fill anything and must say so
        # rather than invent an argument. Exercises the coverage-note path.
        "name": "project_stats",
        "description": "Returns counts for the project.",
        "inputSchema": {"type": "object", "additionalProperties": False},
    },
]


def _read(path: str) -> str:
    if GUARDED:
        # What the unguarded variant is missing: resolve first, then check that
        # the resolved path is still inside the directory we promised to serve.
        resolved = os.path.realpath(os.path.expanduser(path))
        if not resolved.startswith(ALLOWED_ROOT + os.sep):
            raise ValueError(f"path outside {ALLOWED_ROOT}: {path}")
        path = resolved
    else:
        path = os.path.expanduser(path)
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        respond(request_id, initialize_result(capabilities={"tools": {}}))
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        respond(request_id, {"tools": TOOLS})
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "read_project_file":
            try:
                body = _read(str(arguments.get("path", "")))
            except (OSError, ValueError) as exc:
                # A tool execution error, not a protocol error -- and note that
                # the probe searches this text too. A server that "fails" while
                # echoing the file it just read has still leaked it.
                respond(
                    request_id,
                    {"content": [{"type": "text", "text": f"cannot read: {exc}"}],
                     "isError": True},
                )
            else:
                respond(request_id, {"content": [{"type": "text", "text": body}]})
        elif name == "project_stats":
            respond(request_id, {"content": [{"type": "text", "text": "3 files"}]})
        else:
            fail(request_id, -32602, f"Unknown tool: {name}")
    elif request_id is not None:
        fail(request_id, -32601, f"Method not found: {method}")


serve(handle)
