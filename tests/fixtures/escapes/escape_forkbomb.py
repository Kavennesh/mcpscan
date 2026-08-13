"""Fixture 2 of 7 -- process exhaustion. Pins ``--pids-limit``.

This is a *bounded* fork bomb: it forks until the kernel refuses, records the
count, kills its children and reports. It does not bomb exponentially.

That is a deliberate choice and it makes the test stronger, not weaker. An
unbounded bomb can only assert "the host survived", which is unfalsifiable in
the useful direction -- a sandbox with a pids limit of 100000 passes it on a big
enough machine. A bounded one measures the ceiling and the test compares that
number against ``Limits.pids``, so a limit that was silently dropped or
loosened fails loudly. It also cannot wedge the developer's machine if
something upstream is misconfigured.

Note that on cgroup v2 the pids controller counts threads, not just processes,
so the ceiling observed here is the whole container's budget minus whatever the
init process and the interpreter already hold.
"""

from __future__ import annotations

import os
import sys

from _guard import emit, require_sandbox

FIXTURE = "forkbomb"

require_sandbox(FIXTURE)

# Far above any sane --pids-limit. Reaching this means no ceiling was enforced,
# which the test treats as a failure rather than as a very patient success.
HARD_STOP = 4096

children: list[int] = []
ceiling = 0
refusal: str | None = None

# Flush before forking: buffered bytes are duplicated into every child, and a
# child that later flushed them would corrupt the verdict line.
sys.stdout.flush()
sys.stderr.flush()

try:
    while ceiling < HARD_STOP:
        pid = os.fork()
        if pid == 0:
            # Child: hold the slot, then leave without touching the parent's
            # buffers, atexit handlers or the verdict stream.
            try:
                os.pause()
            finally:
                os._exit(0)
        children.append(pid)
        ceiling += 1
except OSError as exc:
    refusal = f"{type(exc).__name__}: {exc}"

for pid in children:
    try:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    except OSError:
        pass

emit(
    FIXTURE,
    [],
    ceiling=ceiling,
    refusal=refusal,
    unbounded=ceiling >= HARD_STOP,
    hard_stop=HARD_STOP,
)

raise SystemExit(0)
