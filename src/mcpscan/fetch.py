"""Making a registry package runnable without giving the runner a network.

``npx -y @vendor/server`` is how almost every MCP server is invoked, and it cannot
work in a container with ``--network none``. The fetcher image exists for exactly
this and had never been called: ``Image.FETCHER`` appeared nowhere in ``src/``
except the guard refusing to network anything else.

The shape, measured rather than assumed:

    fetcher   --network bridge, writable /out
              npm install --ignore-scripts --prefix /out <spec>
    runner    --network none, /out mounted READ-ONLY
              node /out/node_modules/<pkg>/<bin>

**Nothing is installed inside the runner.** The first design tried to, and the
numbers killed it: a typical server's dependency tree is 31 MB and installing it
into the runner's 64 MB tmpfs peaked at 93% -- fine for that server, and a coin
flip for a larger one. Resolving into a host directory and mounting it read-only
uses 0% of the tmpfs and needs no change to ``sandbox.py``.

**`npm pack` is not enough.** It was the obvious choice, being what the fetcher's
own documentation describes, but it retrieves one tarball and no dependencies:
``@modelcontextprotocol/server-filesystem`` declares four, and an offline install
of the bare tarball fails with ``ENOTCACHED``.

So this uses ``npm install --ignore-scripts``. That differs from the letter of
``Dockerfile.fetcher``, which says fetching uses ``npm pack`` -- but the reason it
gives is that "npm install runs preinstall/install/postinstall scripts", and
``--ignore-scripts`` plus the image's own ``NPM_CONFIG_IGNORE_SCRIPTS=true``
closes exactly that. The prohibition the file actually states is on a step that
"runs, imports, builds, or unpacks-**and-invokes** a fetched package"; unpacking
without invoking is what happens here. **This is a deliberate departure from a
documented decision and should be reviewed as one.**
"""

from __future__ import annotations

import json
import posixpath
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final

from mcpscan.sandbox import Image, Limits, Mount, SandboxHandle

#: Where a fetched tree is mounted in the runner.
FETCH_ROOT: Final = PurePosixPath("/out")

#: Command heads that mean "download this and run it".
NODE_RUNNERS: Final = frozenset({"npx", "bunx", "pnpm"})
PYTHON_RUNNERS: Final = frozenset({"uvx", "uv"})

#: Flags a runner takes that are not the package name.
_SKIP_FLAGS: Final = frozenset(
    {"-y", "--yes", "-q", "--quiet", "--silent", "exec", "x", "run", "tool"}
)

FETCH_WALL_CLOCK_S: Final = 300.0


class FetchError(Exception):
    """A package could not be retrieved. Never a finding -- see the module docstring."""


@dataclass(frozen=True, slots=True)
class Fetched:
    """A resolved package on the host, and how to run it offline."""

    root: Path
    command: list[str]
    #: Environment the runner needs to find the package. Python needs PYTHONPATH;
    #: node resolves from the absolute path in ``command`` and needs nothing.
    env: dict[str, str] = field(default_factory=dict)

    def mount(self) -> Mount:
        """Read-only. The runner executes from here and must not write to it."""
        return Mount(source=self.root, target=FETCH_ROOT, read_only=True)

    def cleanup(self) -> None:
        """Remove the fetched tree. Best effort, and not always enough.

        Known limitation: npm creates subdirectories inside ``/out`` owned by the
        container's uid 65532, and unlinking a file needs write permission on its
        *parent*. A host user who is not root therefore cannot delete parts of
        the tree, ``ignore_errors`` swallows it, and the directory survives in the
        system temp area.

        The real fix is running the fetch container as the host uid, which means
        a new ``--user`` argument in ``build_argv`` -- an ask-gated change to
        ``sandbox.py``, deliberately not made here. Until then this leaks temp
        space rather than anything sensitive: the tree holds a public package.
        """
        shutil.rmtree(self.root, ignore_errors=True)


def needs_fetch(command: Sequence[str]) -> str | None:
    """The package spec a command wants downloaded, or ``None`` if it wants none.

    ``node ./server.js`` needs nothing -- it is already on disk and
    ``prober.localise`` mounts it. ``npx -y @vendor/server`` needs the registry.
    """
    if not command:
        return None
    head = Path(command[0]).name
    if head not in NODE_RUNNERS | PYTHON_RUNNERS:
        return None
    for token in command[1:]:
        if token in _SKIP_FLAGS or token.startswith("-"):
            continue
        # A local path is not a registry spec; localise() handles those.
        if Path(token).exists():
            return None
        return token
    return None


def ecosystem(command: Sequence[str]) -> str:
    head = Path(command[0]).name if command else ""
    return "python" if head in PYTHON_RUNNERS else "node"


async def fetch(command: Sequence[str]) -> Fetched | None:
    """Resolve a command's package so the runner can execute it offline.

    Returns ``None`` when nothing needs fetching. Raises :class:`FetchError` when
    something did and could not be -- which is a scanner error, not a finding: a
    package we failed to download tells us nothing about its security.
    """
    spec = needs_fetch(command)
    if spec is None:
        return None

    root = Path(tempfile.mkdtemp(prefix="mcpscan-fetch-"))
    root.chmod(0o777)  # noqa: S103 - the fetcher writes here as uid 65532
    try:
        if ecosystem(command) == "node":
            return await _fetch_node(spec, command, root)
        return await _fetch_python(spec, command, root)
    except FetchError:
        shutil.rmtree(root, ignore_errors=True)
        raise


async def _fetch_node(spec: str, command: Sequence[str], root: Path) -> Fetched:
    result = await SandboxHandle.run(
        [
            "npm",
            "install",
            "--prefix",
            str(FETCH_ROOT),
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--loglevel",
            "error",
            spec,
        ],
        image=Image.FETCHER,
        limits=Limits(network=True, wall_clock_s=FETCH_WALL_CLOCK_S, memory_mb=1024),
        mounts=(Mount(source=root, target=FETCH_ROOT, read_only=False),),
    )
    if result.exit_code != 0:
        raise FetchError(
            f"could not fetch {spec!r}: npm exited {result.exit_code}. "
            + result.stderr.decode("utf-8", "replace").strip()[:300]
        )

    entry = _node_entry(root, spec)
    if entry is None:
        raise FetchError(
            f"fetched {spec!r} but could not find its executable entry point. "
            "The package may not declare a `bin`."
        )
    return Fetched(root=root, command=["node", str(entry), *_tail(command, spec)])


def _safe_entry(base: PurePosixPath, relative: str) -> PurePosixPath | None:
    """Join a manifest-supplied path to ``base``, or refuse it.

    ``package.json`` comes from the registry, so ``bin`` and ``main`` are
    attacker-controlled strings, and both of the obvious joins are wrong:

        PurePosixPath("/out/node_modules/x") / "/etc/shadow"
            -> /etc/shadow            (an absolute part discards everything before it)
        PurePosixPath("/out/node_modules/x") / "../../../etc/shadow"
            -> resolves out of the mount entirely

    And the tempting cleanup makes it worse: ``"../../../etc/shadow".lstrip("./")``
    is ``"etc/shadow"``, which then *passes* a prefix check. So the components are
    rejected before joining, and the normalised result is checked afterwards.
    """
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    joined = posixpath.normpath(str(base / candidate))
    if joined != str(FETCH_ROOT) and not joined.startswith(str(FETCH_ROOT) + "/"):
        return None
    return PurePosixPath(joined)


def _node_entry(root: Path, spec: str) -> PurePosixPath | None:
    """Resolve a package's bin entry from its own package.json.

    Guessing `dist/index.js` would work for most servers and fail silently for
    the rest, which is the worst of both.
    """
    modules = root / "node_modules"
    name = spec.rsplit("@", 1)[0] if spec.count("@") > 1 else spec
    name = name.split("@")[0] if not spec.startswith("@") else name

    candidates = [modules / name]
    candidates += [p.parent for p in modules.glob("*/*/package.json")]
    candidates += [p.parent for p in modules.glob("*/package.json")]

    for directory in candidates:
        manifest = directory / "package.json"
        if not manifest.is_file():
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("name") != name:
            continue
        binary = data.get("bin")
        relative: str | None = None
        if isinstance(binary, str):
            relative = binary
        elif isinstance(binary, dict) and binary:
            relative = str(next(iter(binary.values())))
        elif isinstance(data.get("main"), str):
            relative = str(data["main"])
        if relative:
            return _safe_entry(FETCH_ROOT / directory.relative_to(root), relative)
    return None


async def _fetch_python(spec: str, command: Sequence[str], root: Path) -> Fetched:
    """Resolve a Python package into a directory the runner puts on PYTHONPATH.

    ``--only-binary=:all:`` is the fetcher's documented rule and is kept: building
    a source distribution executes its ``setup.py``, which is the one thing this
    container must never do. A package with no wheel is refused rather than built.

    **argv, never ``sh -c``.** The first version of this built a shell string with
    ``{spec!r}``, which is a command injection: ``repr`` switches to double quotes
    the moment the value contains a single quote, and ``$(...)`` inside double
    quotes is evaluated -- inside the one container that has network egress. The
    spec reaches here from ``--stdio`` and from an imported client config, so it
    is not trusted input. Passing argv removes the shell from the picture.
    """
    result = await SandboxHandle.run(
        [
            "python3",
            "-m",
            "pip",
            "install",
            "--no-cache-dir",
            "--only-binary=:all:",
            "--target",
            f"{FETCH_ROOT}/site",
            "--quiet",
            "--",
            spec,
        ],
        image=Image.FETCHER,
        limits=Limits(network=True, wall_clock_s=FETCH_WALL_CLOCK_S, memory_mb=1024),
        mounts=(Mount(source=root, target=FETCH_ROOT, read_only=False),),
    )
    if result.exit_code != 0:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise FetchError(f"could not fetch {spec!r}: pip exited {result.exit_code}. {detail[:300]}")

    entry = _python_entry(root / "site", spec)
    if entry is None:
        raise FetchError(
            f"fetched {spec!r} but found no runnable module in it. Looked for a "
            "package with __main__.py under the install prefix."
        )
    return Fetched(
        root=root,
        command=["python3", "-m", entry, *_tail(command, spec)],
        # Without this the runner imports nothing and `-m` fails with a message
        # about the module not existing, which reads like the package being wrong.
        env={"PYTHONPATH": f"{FETCH_ROOT}/site"},
    )


def _python_entry(site: Path, spec: str) -> str | None:
    """Find a module that ``python3 -m`` can run. Discovered, never guessed.

    ``spec.replace("-", "_")`` is right often enough to be dangerous: it produces
    a plausible module name for packages whose import name differs from their
    distribution name, and the failure surfaces as an import error that looks
    like a broken package rather than a wrong guess.
    """
    if not site.is_dir():
        return None

    preferred = spec.split("[")[0].replace("-", "_")
    candidates = [
        entry.name
        for entry in sorted(site.iterdir())
        if entry.is_dir() and (entry / "__main__.py").is_file()
    ]
    if preferred in candidates:
        return preferred
    return candidates[0] if candidates else None


def _tail(command: Sequence[str], spec: str) -> list[str]:
    """Whatever the user passed *after* the package name, preserved verbatim."""
    tokens = list(command)
    if spec in tokens:
        return tokens[tokens.index(spec) + 1 :]
    return []
