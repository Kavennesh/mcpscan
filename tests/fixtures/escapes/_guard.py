"""Shared helpers for the escape fixtures.

The files in this directory are hostile payloads, not scanner code. They run
*inside* the runner container as the untrusted process under test, so they
import nothing from ``mcpscan`` and use only the standard library.

Two invariants live here, and both exist because of a specific failure mode:

``require_sandbox()``
    A fixture that runs outside a container is dangerous -- ``escape_forkbomb``
    would fork-bomb a developer's machine. Every fixture refuses to do anything
    unless it can see the marker file baked into the sandbox images.

``emit()``
    A fixture records what it *attempted*, not just what happened. A test that
    only checked "the bad thing did not occur" would pass identically for a
    contained fixture and for one that crashed on line 1 -- and a security suite
    that goes green because its payload is broken is worse than no suite at all.
"""

from __future__ import annotations

import errno
import json
import os
import sys
from collections.abc import Callable
from typing import Any

# Written into both sandbox images by sandbox/Dockerfile.{runner,fetcher}.
SANDBOX_MARKER = "/etc/mcpscan-sandbox"

EXIT_OK = 0
EXIT_NOT_SANDBOXED = 86


def require_sandbox(fixture: str) -> None:
    """Abort unless we are inside an mcpscan sandbox image."""
    if not os.path.isfile(SANDBOX_MARKER):
        json.dump(
            {
                "fixture": fixture,
                "refused": f"{SANDBOX_MARKER} absent -- not inside the mcpscan sandbox",
            },
            sys.stdout,
        )
        sys.stdout.write("\n")
        raise SystemExit(EXIT_NOT_SANDBOXED)


def attempt(what: str, action: Callable[[], Any]) -> dict[str, Any]:
    """Run one escape attempt and record whether the kernel refused it.

    Only ``OSError`` counts as containment -- that is the kernel saying no.
    Anything else is a bug in the fixture itself and is reported as such, so a
    ``TypeError`` in this file can never masquerade as a working sandbox.
    """
    try:
        result = action()
    except OSError as exc:
        name = errno.errorcode.get(exc.errno or 0, str(exc.errno))
        return {"what": what, "blocked": True, "errno": name, "detail": str(exc)}
    except Exception as exc:  # a fixture bug -- deliberately NOT reported as "blocked"
        return {"what": what, "blocked": False, "bug": f"{type(exc).__name__}: {exc}"}
    return {"what": what, "blocked": False, "result": repr(result)[:200]}


def emit(fixture: str, attempts: list[dict[str, Any]], **extra: Any) -> None:
    """Write the single-line JSON verdict that the test reads back."""
    payload: dict[str, Any] = {
        "fixture": fixture,
        "attempted": len(attempts),
        "blocked": sum(1 for a in attempts if a["blocked"]),
        "bugs": sum(1 for a in attempts if "bug" in a),
        "attempts": attempts,
        **extra,
    }
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()
