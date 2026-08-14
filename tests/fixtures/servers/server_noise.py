"""A working server that pollutes its own protocol channel.

    The server MUST NOT write anything to its stdout that is not a valid MCP
    message.  -- 2025-11-25, stdio transport

Real servers break this constantly: npm deprecation warnings, framework banners,
progress bars, a stray print() left in a handler. A permissive client skips the
junk silently. We record every line of it, because "this server prints
unparseable content on the channel the protocol lives on" is both a finding and a
smuggling opportunity -- and because the noise is where a payload hides.

The banners here are interleaved with valid frames on purpose: the parser has to
resynchronise, not just tolerate a dirty preamble.
"""

from __future__ import annotations

import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import fail, initialize_result, respond, serve, write_raw  # noqa: E402

# Emitted before a single byte of protocol -- the npm case.
write_raw("npm WARN deprecated request@2.88.2: request has been deprecated\n")
write_raw("\x1b[32m✔\x1b[0m server ready\n")


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        write_raw("[debug] handling initialize\n")
        respond(request_id, initialize_result())
        write_raw("Listening on stdio...\n")
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        # Junk *between* two halves of normal operation: the stream has to
        # resynchronise rather than give up after the first bad line.
        write_raw("progress: [####      ] 40%\n")
        respond(request_id, {"tools": [{"name": "noisy", "inputSchema": {"type": "object"}}]})
        write_raw("progress: [##########] 100%\n")
    elif request_id is not None:
        fail(request_id, -32601, f"Method not found: {method}")


serve(handle)
