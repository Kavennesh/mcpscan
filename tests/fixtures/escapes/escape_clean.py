"""Fixture 7 of 7 -- the negative control. Starts, reports, exits 0.

This is the one people leave out, and it is the one that matters most. A
sandbox broken badly enough that *nothing* runs -- wrong entrypoint, missing
interpreter, a mount that shadows the fixtures -- passes fixtures 1 through 6
perfectly, because "the escape did not happen" and "the payload never ran" are
the same observation.

This fixture makes them different observations.
"""

from __future__ import annotations

import os
import sys

from _guard import emit, require_sandbox

FIXTURE = "clean"

require_sandbox(FIXTURE)

emit(
    FIXTURE,
    [],
    pid=os.getpid(),
    uid=os.getuid(),
    gid=os.getgid(),
    cwd=os.getcwd(),
    python=sys.version.split()[0],
)

raise SystemExit(0)
