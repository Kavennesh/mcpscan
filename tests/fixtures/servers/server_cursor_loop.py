"""A server whose `tools/list` never reaches a last page.

Cursors are opaque. Clients MUST NOT parse, modify or persist them, which means
there is no way to look at one and tell whether it is making progress. A server
can hand back a cursor forever and a client that loops until `nextCursor` is
absent will loop until it dies.

argv[1] picks which of the two variants to be:

``same``  -- returns an identical cursor every time. Caught by the seen-cursor
            set after two pages.
``fresh`` -- returns a new cursor every time, defeating loop detection entirely.
            Only the page cap stops this one, and the truncation must be
            reported: silently returning 50 pages' worth of tools as if it were
            the whole list is how a scanner reports a clean bill of health for a
            server it never finished reading.
"""

from __future__ import annotations

import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import initialize_result, respond, serve  # noqa: E402

MODE = sys.argv[1] if len(sys.argv) > 1 else "same"

_page = 0


def handle(message: dict[str, Any]) -> None:
    global _page
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        respond(request_id, initialize_result())
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        _page += 1
        cursor = "same-cursor" if MODE == "same" else f"cursor-{_page}"
        respond(
            request_id,
            {
                "tools": [{"name": f"tool_{_page}", "inputSchema": {"type": "object"}}],
                "nextCursor": cursor,
            },
        )


serve(handle)
