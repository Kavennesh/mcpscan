"""Fixture 4 of 7 -- 5 GiB of stdout. Pins the read cap and ``--log-driver none``.

Two separate things are under test, and only one of them is ours:

* mcpscan's own reader has to stop at ``Limits.stdout_bytes`` and kill the
  container, rather than buffering whatever a target feels like sending. An MCP
  server talks JSON-RPC over this pipe; a hostile one can talk forever.

* the *daemon* must not be persisting the flood either. Docker's default
  ``json-file`` log driver writes every byte of container stdout to
  ``/var/lib/docker/containers/<id>/*-json.log`` on the host. Without
  ``--log-driver none`` this fixture fills the host disk even when our reader
  correctly stops at 8 MiB, because the two are entirely independent paths.

The header line is written and flushed before the flood starts so the test can
tell "the fixture ran and then flooded" from "the fixture never started" -- the
verdict at the end is unreachable by design, since a working sandbox kills this
process long before it finishes.
"""

from __future__ import annotations

import sys

from _guard import emit, require_sandbox

FIXTURE = "stdout_flood"

require_sandbox(FIXTURE)

CHUNK = b"A" * (1024 * 1024)
TARGET_BYTES = 5 * 1024 * 1024 * 1024

emit(FIXTURE, [], phase="start", target_bytes=TARGET_BYTES, chunk_bytes=len(CHUNK))

out = sys.stdout.buffer
written = 0
while written < TARGET_BYTES:
    out.write(CHUNK)
    written += len(CHUNK)
out.flush()

# Only reachable if nothing capped us.
emit(FIXTURE, [], phase="finished", written=written, capped=False)

raise SystemExit(0)
