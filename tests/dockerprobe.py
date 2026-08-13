"""Ask the Docker daemon what exists, without spawning anything.

``CLAUDE.md`` confines process spawning to ``src/mcpscan/sandbox.py``, and
``tests/test_containment.py`` enforces that across ``tests/`` too, so this
cannot shell out to the ``docker`` CLI. It speaks the daemon's HTTP API over
its unix socket using only the standard library, which also leaves the
"no new runtime dependencies" rule intact.

It checks for the *images*, not merely for a reachable daemon. That distinction
is what keeps CI green: a GitHub runner has a Docker daemon but never runs
``make images``, so a daemon-only probe would let the escape suite run there and
fail for a reason that has nothing to do with the sandbox.
"""

from __future__ import annotations

import http.client
import os
import socket
from functools import lru_cache

RUNNER_IMAGE = "mcpscan/runner:0.1.0"
FETCHER_IMAGE = "mcpscan/fetcher:0.1.0"

DEFAULT_SOCKET = "/var/run/docker.sock"
TIMEOUT_S = 3.0


class _UnixSocketConnection(http.client.HTTPConnection):
    """An HTTPConnection that dials a unix socket instead of a TCP host."""

    def __init__(self, socket_path: str) -> None:
        super().__init__("localhost", timeout=TIMEOUT_S)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_S)
        sock.connect(self._socket_path)
        self.sock = sock


def _socket_path() -> str | None:
    """The local socket to talk to, or None if the daemon is not local."""
    host = os.environ.get("DOCKER_HOST")
    if not host:
        return DEFAULT_SOCKET
    if host.startswith("unix://"):
        return host.removeprefix("unix://")
    # tcp:// or ssh:// -- a remote daemon this probe does not speak. Report
    # unavailable so the suite skips instead of guessing.
    return None


def _status(path: str) -> int:
    sock_path = _socket_path()
    if sock_path is None or not os.path.exists(sock_path):
        return 0
    conn = _UnixSocketConnection(sock_path)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        response.read()  # drain, or the socket is left half-consumed
        return response.status
    finally:
        conn.close()


def daemon_reachable() -> bool:
    try:
        return _status("/_ping") == 200
    except OSError:
        return False


def image_present(image: str) -> bool:
    try:
        return _status(f"/images/{image}/json") == 200
    except OSError:
        return False


def container_exists(container_id: str) -> bool:
    """Whether a container is still known to the daemon.

    Used to assert that the wall-clock kill path cleans up after itself rather
    than leaking a stopped container per timed-out scan.
    """
    try:
        return _status(f"/containers/{container_id}/json") == 200
    except OSError:
        return False


@lru_cache(maxsize=1)
def images_ready() -> bool:
    return daemon_reachable() and all(
        image_present(image) for image in (RUNNER_IMAGE, FETCHER_IMAGE)
    )


def skip_reason() -> str:
    if not daemon_reachable():
        return "no reachable local Docker daemon"
    missing = [i for i in (RUNNER_IMAGE, FETCHER_IMAGE) if not image_present(i)]
    if missing:
        return f"sandbox images not built ({', '.join(missing)}); run `make images`"
    return ""
