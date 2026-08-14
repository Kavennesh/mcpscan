"""Materialising the `.py.txt` source fixtures into a real Python tree.

The fixtures under ``tests/fixtures/sources/`` are stored with a ``.py.txt``
extension, and that is load-bearing rather than cosmetic. ``vulnerable_server``
has to contain ``subprocess.run(...)`` and ``os.system(...)`` to be worth testing
at all, and ``tests/test_containment.py`` globs ``**/*.py`` across ``src/`` and
``tests/`` to enforce CLAUDE.md constraint 2. Kept as data, they are invisible to
that scan, so the constraint holds with **no new exemption** -- the alternative
was widening the exemption list, which is exactly the erosion the containment
suite exists to prevent.

Writing them into ``tmp_path`` at run time means the analyser is still exercised
against a genuine ``.py`` tree walked by the real globbing code, rather than
against a special case that only tests hit.

They are never imported and never executed. ``mcp.server.fastmcp`` is not a
dependency of this project and importing one of these files would fail -- which
is a feature, not something to work around.
"""

from __future__ import annotations

from pathlib import Path

SOURCES = Path(__file__).parent / "fixtures" / "sources"


def fixture_text(name: str) -> str:
    """Read one fixture's source without materialising it."""
    return (SOURCES / f"{name}.py.txt").read_text(encoding="utf-8")


def materialise(tmp_path: Path, *names: str) -> Path:
    """Write the named fixtures into ``tmp_path`` as ``.py`` and return the root."""
    root = tmp_path / "target"
    root.mkdir(parents=True, exist_ok=True)
    for name in names:
        (root / f"{name}.py").write_text(fixture_text(name), encoding="utf-8")
    return root


def available() -> list[str]:
    """Every fixture name available to materialise."""
    return sorted(path.name.removesuffix(".py.txt") for path in SOURCES.glob("*.py.txt"))
