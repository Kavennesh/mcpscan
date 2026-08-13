from __future__ import annotations

import os
from pathlib import Path

CONSENT_PATH = Path(
    os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
) / "mcpscan" / "consent"

BANNER = """\
mcpscan executes untrusted code in order to analyse it.

Only scan MCP servers that you own, or that you have explicit written
authorisation to test. Scanning third-party servers without permission
may be unlawful in your jurisdiction.
"""


def ensure_consent(assume_yes: bool = False) -> None:
    if CONSENT_PATH.is_file():
        return
    if assume_yes:
        _record()
        return
    print(BANNER)
    answer = input("Type 'I am authorised' to continue: ").strip().lower()
    if answer != "i am authorised":
        raise SystemExit(2)
    _record()


def _record() -> None:
    CONSENT_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONSENT_PATH.write_text("acknowledged\n")
