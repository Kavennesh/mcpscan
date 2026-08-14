"""A server that reads everything and answers nothing.

The cheapest denial of service a target has: accept the connection, consume the
handshake, and never reply. There is no malformed byte to detect and no error to
report -- the failure is the absence of anything at all.

This is why the per-request timeout is load-bearing from the very first message
rather than something to add once the interesting features work. A scanner that
blocks forever on `initialize` never reaches any of its analysis, and a scan that
hangs is indistinguishable to the operator from a scan that crashed.

It keeps draining stdin so the client's writes do not block, which makes the hang
a clean timeout rather than a pipe-full deadlock -- the harder case to diagnose,
and the one worth pinning.
"""

from __future__ import annotations

import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import serve  # noqa: E402


def handle(message: dict[str, Any]) -> None:
    return


serve(handle)
