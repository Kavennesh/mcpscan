"""Fixture 1 of 7 -- network egress. Pins ``--network none``.

Four attempts, chosen to cover the distinct ways a target could reach out:

* raw TCP to a hardcoded address -- the simplest exfil
* UDP, which fails at a different layer than TCP does
* DNS resolution, which is an exfil channel in its own right (data in the
  label) even when no TCP connection is ever allowed to complete
* the cloud metadata endpoint, 169.254.169.254 -- link-local, needs no DNS and
  no egress past the host's NIC, and is the realistic path to stealing
  credentials when a scanner runs on a CI runner or a cloud VM

The loopback probe at the end is a control: it proves the socket layer works at
all, so "everything was refused" cannot be satisfied by a Python that is simply
too broken to open a socket.
"""

from __future__ import annotations

import socket

from _guard import attempt, emit, require_sandbox

FIXTURE = "network"

require_sandbox(FIXTURE)

# Nothing here should ever block long enough to matter; with no route the
# kernel refuses immediately. The timeout only bounds a misconfigured sandbox.
TIMEOUT = 3.0


def _tcp(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        return f"connected {sock.getpeername()}"


def _udp(host: str, port: int) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(b"mcpscan-probe", (host, port))
        return "datagram accepted by the stack"


def _dns(name: str) -> str:
    return str(socket.getaddrinfo(name, 80, proto=socket.IPPROTO_TCP)[0][4])


def _metadata() -> str:
    with socket.create_connection(("169.254.169.254", 80), timeout=TIMEOUT) as sock:
        sock.sendall(b"GET /latest/meta-data/ HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n")
        return sock.recv(256).decode("utf-8", "replace")


def _loopback_control() -> str:
    """Connect to a certainly-closed local port.

    ECONNREFUSED here means the stack is alive and it is the *route* that is
    missing for everything else. ENETUNREACH here would mean this fixture
    cannot distinguish containment from a broken interpreter.
    """
    try:
        with socket.create_connection(("127.0.0.1", 1), timeout=TIMEOUT):
            return "unexpectedly open"
    except ConnectionRefusedError:
        return "refused (stack is alive)"
    except OSError as exc:
        return f"unexpected: {exc}"


attempts = [
    attempt("tcp 1.1.1.1:443", lambda: _tcp("1.1.1.1", 443)),
    attempt("udp 8.8.8.8:53", lambda: _udp("8.8.8.8", 53)),
    attempt("dns example.com", lambda: _dns("example.com")),
    attempt("http 169.254.169.254 (cloud metadata)", _metadata),
]

emit(FIXTURE, attempts, loopback_control=_loopback_control())

raise SystemExit(0)
