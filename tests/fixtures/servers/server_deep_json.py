"""A server that answers with five thousand nested arrays.

Aimed squarely at the client's parser rather than at anything semantic. In
CPython, ``json.loads`` recurses, and on input like this it raises
``RecursionError`` -- *not* ``json.JSONDecodeError``. A client that wraps its
parse in the obvious ``except json.JSONDecodeError`` therefore does not catch
this, and the exception escapes into whatever was reading the stream.

The defence is to count nesting with a byte scan before parsing, which is what
``jsonrpc.nesting_depth`` does. This fixture is the proof that the pre-check
runs: if it were removed, the client would not merely record a different anomaly,
it would fall over.

Built by string concatenation, because the fixture cannot ``json.dumps`` a
structure this deep either -- it would hit the same limit before it could write.
"""

from __future__ import annotations

import sys
from typing import Any

sys.path.insert(0, "/fixtures/servers")

from _server import initialize_result, respond, serve, write_raw  # noqa: E402

DEPTH = 5000


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    request_id = message.get("id")

    if method == "initialize":
        respond(request_id, initialize_result())
    elif method == "notifications/initialized":
        return
    elif method == "tools/list":
        nested = "[" * DEPTH + "]" * DEPTH
        write_raw(f'{{"jsonrpc":"2.0","id":{request_id},"result":{{"tools":{nested}}}}}\n')
        # A valid message afterwards, so the test can prove the stream survived
        # rather than merely that the bad one was rejected.
        write_raw('{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n')


serve(handle)
