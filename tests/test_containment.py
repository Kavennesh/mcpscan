"""Constraint 2 of CLAUDE.md, enforced.

    "``subprocess``, ``os.exec*``, ``os.system`` and
     ``asyncio.create_subprocess_*`` appear in ``src/mcpscan/sandbox.py`` and
     nowhere else. A CI test enforces this."

That test did not exist. This is it.

Unlike the rest of the sandbox suite this one passes today and is expected to
keep passing forever -- it is not gated on Docker, because nothing about
"did anyone add a way to spawn a process outside the sandbox" needs a daemon.

The scan covers ``tests/`` as well as ``src/``, which is load-bearing rather
than thorough-for-its-own-sake: it is what stops the escape suite from quietly
shelling out to the ``docker`` CLI instead of going through ``SandboxHandle``,
and therefore what keeps ``test_sandbox.py`` an honest test of the real code
path.

The scan is an AST walk rather than a grep. Partly for accuracy -- ``os.execv``
in a comment or a docstring is not a spawn -- and partly so this file can name
every forbidden symbol in its own source without matching itself.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNED_DIRS = [REPO_ROOT / "src", REPO_ROOT / "tests"]

#: The only module permitted to spawn a process.
SANDBOX_MODULE = REPO_ROOT / "src" / "mcpscan" / "sandbox.py"

#: The escape fixtures are hostile payloads that must genuinely fork, exec and
#: spawn -- that is what they are testing. They run inside the container as the
#: untrusted process, never as scanner code. Exempted here, visibly, rather
#: than through a config file nobody reads.
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "escapes"

FORBIDDEN_MODULES = frozenset({"subprocess", "multiprocessing", "pty"})

#: Attributes of `os` that create a process.
FORBIDDEN_OS_ATTRS = frozenset({"system", "popen", "fork", "forkpty", "plock"})
FORBIDDEN_OS_PREFIXES = ("exec", "spawn", "posix_spawn")

#: Attributes of `asyncio` that create a process.
FORBIDDEN_ASYNCIO_PREFIXES = ("create_subprocess",)


def _is_forbidden_os_attr(name: str) -> bool:
    return name in FORBIDDEN_OS_ATTRS or name.startswith(FORBIDDEN_OS_PREFIXES)


class SpawnVisitor(ast.NodeVisitor):
    """Collect every syntactic construct that could start a process."""

    def __init__(self) -> None:
        self.hits: list[tuple[int, str]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in FORBIDDEN_MODULES:
                self.hits.append((node.lineno, f"import {alias.name}"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        root = module.split(".")[0]
        if root in FORBIDDEN_MODULES:
            self.hits.append((node.lineno, f"from {module} import ..."))
        elif root == "os":
            for alias in node.names:
                if _is_forbidden_os_attr(alias.name):
                    self.hits.append((node.lineno, f"from os import {alias.name}"))
        elif root == "asyncio":
            for alias in node.names:
                if alias.name.startswith(FORBIDDEN_ASYNCIO_PREFIXES):
                    self.hits.append((node.lineno, f"from asyncio import {alias.name}"))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        base = node.value
        if isinstance(base, ast.Name):
            if base.id == "os" and _is_forbidden_os_attr(node.attr):
                self.hits.append((node.lineno, f"os.{node.attr}"))
            elif base.id == "asyncio" and node.attr.startswith(FORBIDDEN_ASYNCIO_PREFIXES):
                self.hits.append((node.lineno, f"asyncio.{node.attr}"))
        self.generic_visit(node)


def scan(source: str) -> list[tuple[int, str]]:
    visitor = SpawnVisitor()
    visitor.visit(ast.parse(source))
    return visitor.hits


def python_files() -> list[Path]:
    return sorted(
        path
        for directory in SCANNED_DIRS
        for path in directory.rglob("*.py")
        if "__pycache__" not in path.parts
    )


def is_exempt(path: Path) -> bool:
    return path == SANDBOX_MODULE or FIXTURE_DIR in path.parents


def test_process_spawning_is_confined_to_sandbox_module() -> None:
    violations: list[str] = []
    for path in python_files():
        if is_exempt(path):
            continue
        for lineno, what in scan(path.read_text(encoding="utf-8")):
            violations.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {what}")

    assert not violations, (
        "process spawning outside src/mcpscan/sandbox.py (CLAUDE.md constraint 2).\n"
        "If a module needs to run something, route it through SandboxHandle:\n  "
        + "\n  ".join(violations)
    )


def test_the_scan_actually_detects_things() -> None:
    """A detector that detects nothing passes the test above trivially.

    Same principle as the escape fixtures reporting what they attempted: a
    guard has to be shown working, not merely shown green.
    """
    hostile = "\n".join(
        [
            "import os",
            "import asyncio",
            "import subprocess",
            "from multiprocessing import Process",
            "from os import execv",
            "os.system('id')",
            "os.popen('id')",
            "os.fork()",
            "os.execve('/bin/sh', [], {})",
            "os.posix_spawn('/bin/sh', [], {})",
            "os.spawnl(os.P_NOWAIT, '/bin/sh')",
            "asyncio.create_subprocess_exec('/bin/sh')",
            "asyncio.create_subprocess_shell('id')",
        ]
    )
    found = {what for _, what in scan(hostile)}

    assert "import subprocess" in found
    assert "from multiprocessing import ..." in found
    assert "from os import execv" in found
    assert {"os.system", "os.popen", "os.fork", "os.execve", "os.posix_spawn"} <= found
    assert "asyncio.create_subprocess_exec" in found
    assert "asyncio.create_subprocess_shell" in found


def test_benign_lookalikes_are_not_flagged() -> None:
    """Precision matters too: a guard that cries wolf gets an exemption added."""
    benign = "\n".join(
        [
            "import os",
            "import os.path",
            "os.path.exists('/tmp')",
            "os.environ.get('HOME')",
            "os.getpid()",
            "cursor.execute('select 1')",
            "runner.exec_command('id')",
            "'os.system' in text",
        ]
    )
    assert scan(benign) == []


def test_the_sandbox_module_is_the_only_exemption_in_src() -> None:
    exempt_src = [p for p in python_files() if is_exempt(p) and p.is_relative_to(REPO_ROOT / "src")]
    assert exempt_src in ([], [SANDBOX_MODULE])
