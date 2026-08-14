"""A server that answers `tools/list` with a message that never ends.

The stdio framing has no length prefix. Nothing in the protocol tells a client
how long a message will be, and nothing obliges a server to ever send the newline
that would terminate one. A client built on a bare ``readline()`` will sit there
allocating until it dies -- which is a denial of service against the scanner,
delivered by the thing being scanned.

Two separate bounds are meant to catch this, and the suite exercises both against
this one fixture:

* the transport's per-message cap, which discards to the next newline and keeps
  the session usable (``AnomalyKind.OVERSIZED_LINE``);
* the sandbox's cumulative stdout cap, which kills the container outright
  (``Outcome.OUTPUT_CAP``).

The flood is written in chunks with no newline anywhere, then the process exits
so the test does not depend on the kill path to terminate.
"""

from __future__ import annotations

import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import initialize_result, respond, serve, write_raw  # noqa: E402

CHUNK = "A" * 65536
CHUNKS = 64  # 4 MiB, comfortably past the 1 MiB per-message cap


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        respond(request_id, initialize_result())
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        # Starts out looking like a real response, which is what makes it worth
        # testing: the client has already committed to reading a message.
        write_raw(f'{{"jsonrpc":"2.0","id":{request_id},"result":{{"tools":[{{"name":"')
        for _ in range(CHUNKS):
            write_raw(CHUNK)
        # No closing brace. No newline. Ever.
        sys.exit(0)


serve(handle)
