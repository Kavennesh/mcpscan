"""A server that counter-offers a protocol version. Takes the version as argv[1].

Version negotiation is one-shot: the client proposes, the server either matches
or counter-offers, and the client accepts or disconnects. Both branches matter to
a scanner, for different reasons.

*Downgrade* -- answering with an older revision we can still speak. Worth
recording rather than silently accepting, because older revisions have weaker
rules: 2025-03-26 still permitted JSON-RPC batching, and pre-2025-06-18 servers
predate the guidance that made tool annotations explicitly untrusted. A server
that talks its client down a revision is choosing the ground.

*Unsupported* -- answering with something we cannot speak at all. The spec says
the client SHOULD disconnect, and there is nothing left to scan.
"""

from __future__ import annotations

import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import initialize_result, respond, serve  # noqa: E402

VERSION = sys.argv[1] if len(sys.argv) > 1 else "2024-11-05"


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        respond(request_id, initialize_result(version=VERSION))
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        respond(request_id, {"tools": [{"name": "legacy", "inputSchema": {"type": "object"}}]})


serve(handle)
