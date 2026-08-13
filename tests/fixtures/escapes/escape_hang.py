"""Fixture 5 of 7 -- a process that will not leave. Pins the wall-clock kill.

The important detail is that this ignores SIGTERM. Without that, the fixture
tests nothing: ``docker stop`` sends SIGTERM, a well-behaved process dies, and
a sandbox with no escalation path at all passes. Ignoring it forces the
timeout to be enforced by SIGKILL -- which cannot be caught, blocked or ignored,
and is therefore the only signal a hostile target cannot outlast.

Docker's own ``--stop-timeout`` is not sufficient here either: it governs the
grace period of an explicit ``docker stop``, not a wall-clock budget. The
watchdog has to belong to mcpscan.

The verdict is written and flushed before hanging, so the test can distinguish
"reached the hang and was killed" from "died on startup", which would produce
the same timeout-shaped result for entirely the wrong reason.
"""

from __future__ import annotations

import signal
import time

from _guard import emit, require_sandbox

FIXTURE = "hang"

require_sandbox(FIXTURE)

IGNORED = ["SIGTERM", "SIGINT", "SIGHUP", "SIGQUIT"]

for name in IGNORED:
    signal.signal(getattr(signal, name), signal.SIG_IGN)

emit(FIXTURE, [], phase="hanging", ignoring=IGNORED)

while True:
    time.sleep(3600)
