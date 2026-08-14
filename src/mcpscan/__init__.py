"""mcpscan -- a security scanner for Model Context Protocol servers.

The version is read from installed package metadata rather than written here.
It was previously a literal in three places -- ``pyproject.toml``, this file, and
``report.TOOL_VERSION`` -- which is two more than can stay in agreement. A wheel
built at 0.2.0 would have gone on reporting 0.1.0 in every JSON report.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mcpscan")
except PackageNotFoundError:  # pragma: no cover - a source tree with no install
    # Honest rather than a plausible-looking lie: a report that claims a release
    # number it was not built from is worse than one that admits it does not know.
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
