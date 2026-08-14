"""A well-behaved MCP server. The negative control for the transport suite.

Every other fixture in this directory violates something. This one violates
nothing, which is what makes it load-bearing: if the clean server produces a
single anomaly, the parser is crying wolf, and a scanner that cries wolf gets
its findings ignored.

It also exercises the paths that only appear on a *correct* server -- two-page
cursor pagination, an `isError: true` tool result, resource templates -- so the
happy path is proven rather than assumed.

Step 4 reuses it as the negative control for the static rules: all three must
find nothing here. The metadata lives in ``clean_metadata.py`` so a pure test can
read it without running this module, which blocks on stdin the moment it is
imported.
"""

from __future__ import annotations

import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import fail, initialize_result, respond, serve  # noqa: E402
from clean_metadata import (  # noqa: E402
    INSTRUCTIONS,
    PROMPTS,
    RESOURCE_TEMPLATES,
    RESOURCES,
    TOOLS_PAGE_ONE,
    TOOLS_PAGE_TWO,
)


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    if method == "initialize":
        respond(
            request_id,
            initialize_result(
                capabilities={
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": False, "listChanged": False},
                    "prompts": {"listChanged": False},
                },
                instructions=INSTRUCTIONS,
            ),
        )
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        # Two pages, so the cursor loop in the client is actually walked rather
        # than short-circuited by a single complete page.
        if params.get("cursor") == "page-2":
            respond(request_id, {"tools": TOOLS_PAGE_TWO})
        else:
            respond(request_id, {"tools": TOOLS_PAGE_ONE, "nextCursor": "page-2"})
    elif method == "tools/call":
        name = params.get("name")
        if name == "read_file":
            respond(request_id, {"content": [{"type": "text", "text": "file contents"}]})
        elif name == "write_file":
            # A tool execution error: a successful exchange whose payload
            # describes a failure. Distinct from the protocol error below.
            respond(
                request_id,
                {"content": [{"type": "text", "text": "path is required"}], "isError": True},
            )
        else:
            fail(request_id, -32602, f"Unknown tool: {name}")
    elif method == "resources/list":
        respond(request_id, {"resources": RESOURCES})
    elif method == "resources/templates/list":
        respond(request_id, {"resourceTemplates": RESOURCE_TEMPLATES})
    elif method == "resources/read":
        respond(
            request_id,
            {
                "contents": [
                    {
                        "uri": params.get("uri", ""),
                        "mimeType": "text/markdown",
                        "text": "# Project",
                    }
                ]
            },
        )
    elif method == "prompts/list":
        respond(request_id, {"prompts": PROMPTS})
    elif method == "prompts/get":
        respond(
            request_id,
            {
                "description": "Code review prompt",
                "messages": [
                    {"role": "user", "content": {"type": "text", "text": "Please review"}}
                ],
            },
        )
    elif request_id is not None:
        fail(request_id, -32601, f"Method not found: {method}")


serve(handle)
