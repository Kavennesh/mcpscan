"""Fixture 3 of 7 -- filesystem writes. Pins ``--read-only``, the ``ro`` bind
mount, and the ``noexec`` tmpfs.

Five write targets, each a different containment mechanism:

* ``/`` and ``/etc/passwd`` -- the read-only root filesystem
* ``/usr/bin/...`` -- the "drop a binary somewhere on PATH" move specifically
* ``/proc/sysrq-trigger`` -- writable-by-root kernel control that a container
  must never reach; Docker masks it, and this catches ``systempaths=unconfined``
* the ``/fixtures`` mount -- proves ``ro`` on the bind mount, not just the rootfs

Then two checks on ``/tmp``, which is deliberately writable:

* a positive control -- if ``/tmp`` were *not* writable, "every write failed"
  would be trivially true and this fixture would prove nothing
* a ``noexec`` check that execs a native binary

That last distinction is the one that decides whether this test is real. Under
``noexec``, ``python3 /tmp/payload.py`` still runs: the interpreter reads the
script as data and the kernel never maps it executable. Only a genuine
``execve`` of a native binary is refused, so that is what this does.
"""

from __future__ import annotations

import os
import shutil

from _guard import attempt, emit, require_sandbox

FIXTURE = "fswrite"

require_sandbox(FIXTURE)

READ_ONLY_TARGETS = [
    "/mcpscan-payload",
    "/etc/passwd",
    "/usr/bin/mcpscan-payload",
    "/proc/sysrq-trigger",
    "/fixtures/mcpscan-payload",
]


def _write(path: str) -> str:
    with open(path, "wb") as handle:
        handle.write(b"mcpscan-escape\n")
    return f"wrote {path}"


def _tmp_writable() -> bool:
    try:
        with open("/tmp/mcpscan-control", "wb") as handle:
            handle.write(b"ok\n")
        return True
    except OSError:
        return False


def _tmp_noexec() -> dict[str, object]:
    """Copy a real ELF binary into /tmp, mark it executable, and try to run it.

    Run in a forked child: a successful ``execv`` in this process would replace
    the fixture and no verdict would ever be written.
    """
    target = "/tmp/mcpscan-true"
    try:
        shutil.copy("/bin/true", target)
        os.chmod(target, 0o755)
    except OSError as exc:
        return {"blocked": True, "stage": "copy-or-chmod", "detail": str(exc)}

    pid = os.fork()
    if pid == 0:
        try:
            os.execv(target, [target])
        except OSError as exc:
            os._exit(exc.errno or 1)
        os._exit(0)

    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    # The child only reaches exit 0 by *becoming* /bin/true, i.e. execve won.
    return {"blocked": code != 0, "child_exit": code, "stage": "execv"}


attempts = [attempt(f"write {path}", lambda p=path: _write(p)) for path in READ_ONLY_TARGETS]

emit(
    FIXTURE,
    attempts,
    tmp_writable=_tmp_writable(),
    tmp_noexec=_tmp_noexec(),
)

raise SystemExit(0)
