"""Making a registry package runnable without giving the runner a network.

Two layers, for the usual reason: the parsing decides *what* to fetch and runs in
CI, while actually fetching needs a daemon and the network and is gated.

The gated half is also the only test in the suite that depends on a third party
being up. It is marked so it skips rather than fails when the registry is not
reachable -- a red build caused by npm having a bad afternoon teaches people to
ignore red builds.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

#: A directory *inside the container* that the server under test is told to
#: serve. Not a host temp path -- the container's /tmp is its own 64 MB tmpfs.
SERVED = "/tmp"  # noqa: S108

from mcpscan.fetch import (  # noqa: E402
    FETCH_ROOT,
    Fetched,
    _node_entry,
    _tail,
    ecosystem,
    needs_fetch,
)


# --------------------------------------------------------------------------
# what needs fetching -- pure
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (["npx", "-y", "@modelcontextprotocol/server-filesystem", SERVED],
         "@modelcontextprotocol/server-filesystem"),
        (["npx", "@vendor/server"], "@vendor/server"),
        (["npx", "--yes", "server-thing"], "server-thing"),
        (["bunx", "-y", "@vendor/server"], "@vendor/server"),
        (["uvx", "mcp-server-git"], "mcp-server-git"),
        (["pnpm", "exec", "@vendor/server"], "@vendor/server"),
    ],
)
def test_a_registry_spec_is_recognised(command: list[str], expected: str) -> None:
    assert needs_fetch(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        ["node", "./server.js"],
        ["python3", "server.py"],
        ["/usr/local/bin/my-mcp-server"],
        [],
    ],
)
def test_a_local_command_needs_no_fetch(command: list[str]) -> None:
    """`prober.localise` mounts these; downloading anything would be wrong."""
    assert needs_fetch(command) is None


def test_a_local_path_after_a_runner_is_not_a_registry_spec(tmp_path: Path) -> None:
    """`npx ./local-thing` means the directory, not a package of that name."""
    local = tmp_path / "local-thing"
    local.mkdir()
    assert needs_fetch(["npx", str(local)]) is None


def test_the_ecosystem_follows_the_runner() -> None:
    assert ecosystem(["npx", "@vendor/x"]) == "node"
    assert ecosystem(["bunx", "@vendor/x"]) == "node"
    assert ecosystem(["uvx", "thing"]) == "python"
    assert ecosystem(["uv", "tool", "run", "thing"]) == "python"


def test_arguments_after_the_package_are_preserved() -> None:
    """`npx -y @vendor/server /tmp --readonly` -- the tail is the server's config."""
    command = ["npx", "-y", "@vendor/server", SERVED, "--readonly"]
    assert _tail(command, "@vendor/server") == [SERVED, "--readonly"]


def test_no_arguments_is_an_empty_tail() -> None:
    assert _tail(["npx", "-y", "@vendor/server"], "@vendor/server") == []


# --------------------------------------------------------------------------
# resolving the entry point -- pure, against a fake tree
# --------------------------------------------------------------------------
def make_package(root: Path, name: str, manifest: dict) -> None:
    directory = root / "node_modules" / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_a_string_bin_is_resolved(tmp_path: Path) -> None:
    make_package(tmp_path, "thing", {"name": "thing", "bin": "dist/main.js"})
    assert _node_entry(tmp_path, "thing") == FETCH_ROOT / "node_modules/thing/dist/main.js"


def test_a_mapped_bin_is_resolved(tmp_path: Path) -> None:
    """What the real filesystem server has: {"mcp-server-filesystem": "dist/index.js"}."""
    make_package(
        tmp_path,
        "@vendor/server",
        {"name": "@vendor/server", "bin": {"the-server": "dist/index.js"}},
    )
    entry = _node_entry(tmp_path, "@vendor/server")
    assert entry == FETCH_ROOT / "node_modules/@vendor/server/dist/index.js"


def test_main_is_the_fallback_when_there_is_no_bin(tmp_path: Path) -> None:
    make_package(tmp_path, "thing", {"name": "thing", "main": "index.js"})
    assert _node_entry(tmp_path, "thing") == FETCH_ROOT / "node_modules/thing/index.js"


def test_a_package_with_no_entry_point_resolves_to_nothing(tmp_path: Path) -> None:
    """Guessing dist/index.js would work for most and fail silently for the rest."""
    make_package(tmp_path, "thing", {"name": "thing"})
    assert _node_entry(tmp_path, "thing") is None


def test_the_right_package_is_picked_out_of_a_full_tree(tmp_path: Path) -> None:
    """133 packages get installed; only one of them is the server."""
    for name in ("glob", "minimatch", "diff"):
        make_package(tmp_path, name, {"name": name, "bin": f"{name}.js"})
    make_package(tmp_path, "@vendor/server", {"name": "@vendor/server", "bin": "run.js"})

    assert _node_entry(tmp_path, "@vendor/server") == (
        FETCH_ROOT / "node_modules/@vendor/server/run.js"
    )


def test_a_malformed_manifest_is_skipped_not_fatal(tmp_path: Path) -> None:
    directory = tmp_path / "node_modules" / "broken"
    directory.mkdir(parents=True)
    (directory / "package.json").write_text("{not json")
    make_package(tmp_path, "thing", {"name": "thing", "bin": "ok.js"})

    assert _node_entry(tmp_path, "thing") == FETCH_ROOT / "node_modules/thing/ok.js"


def test_the_fetched_mount_is_read_only(tmp_path: Path) -> None:
    """The runner executes from here. A writable mount would let a target edit
    the code it is being scanned as."""
    mount = Fetched(root=tmp_path, command=["node", "x"]).mount()
    assert mount.read_only
    assert mount.target == FETCH_ROOT
    assert ",ro," in mount.to_spec()


# --------------------------------------------------------------------------
# the real thing -- needs a daemon and the network
# --------------------------------------------------------------------------
from tests.dockerprobe import images_ready, skip_reason  # noqa: E402


@pytest.mark.sandbox
@pytest.mark.skipif(not images_ready(), reason=skip_reason())
async def test_a_real_registry_package_is_fetched_and_runs_offline() -> None:
    """The end-to-end claim: `npx -y <package>` is scannable.

    This is the one test that depends on npmjs.org being up, so it skips rather
    than fails when the registry is unreachable. A red build caused by someone
    else's outage teaches people to ignore red builds.
    """
    from mcpscan.fetch import FetchError, fetch
    from mcpscan.sandbox import Image, Limits, SandboxHandle

    reachable = await SandboxHandle.run(
        ["npm", "ping", "--registry", "https://registry.npmjs.org/"],
        image=Image.FETCHER,
        limits=Limits(network=True, wall_clock_s=30.0),
    )
    if reachable.exit_code != 0:
        pytest.skip("npm registry not reachable from this machine")

    command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", SERVED]
    try:
        fetched = await fetch(command)
    except FetchError as exc:
        pytest.skip(f"registry fetch failed: {exc}")

    assert fetched is not None
    try:
        # Resolved into a host directory, not the runner's 64 MB tmpfs. The tree
        # for this server is 31 MB and installing it into the tmpfs peaked at
        # 93%, which is why nothing is installed inside the runner at all.
        assert (fetched.root / "node_modules").is_dir()
        assert fetched.command[0] == "node"
        assert str(FETCH_ROOT) in fetched.command[1]

        # And it runs with no network, which is the whole point.
        result = await SandboxHandle.run(
            ["node", fetched.command[1], SERVED],
            image=Image.RUNNER,
            limits=Limits(network=False, wall_clock_s=20.0),
            mounts=(fetched.mount(),),
        )
        assert result.outcome.value in {"exited", "timeout"}
        combined = (result.stdout + result.stderr).decode("utf-8", "replace")
        assert "Cannot find module" not in combined, combined[:400]
    finally:
        fetched.cleanup()


# --------------------------------------------------------------------------
# defects found by adversarial review of the first cut -- pinned so they stay fixed
# --------------------------------------------------------------------------
def test_no_fetch_command_goes_through_a_shell() -> None:
    """The first `_fetch_python` built `sh -c "... {spec!r}"`, which is injection.

    `repr` switches to double quotes the moment the value contains a single
    quote, and `$(...)` inside double quotes is evaluated -- in the one container
    that has network egress. Verified before fixing:

        spec = "foo'$(id -u)"  ->  repr is "foo'$(id -u)"  ->  sh sees "foo'0"

    The spec reaches here from `--stdio` and from an imported client config, so
    it is not trusted input. argv removes the shell from the picture; this test
    stops it coming back.
    """
    import inspect

    from mcpscan import fetch as module

    source = inspect.getsource(module)
    assert '"sh"' not in source, "a fetch command is being built for a shell"
    assert "'-c'" not in source and '"-c"' not in source


@pytest.mark.parametrize(
    "hostile",
    [
        "/etc/shadow",
        "../../../etc/shadow",
        "../../../../../../etc/passwd",
        "./../../escape.js",
        "/",
    ],
)
def test_a_manifest_cannot_point_the_entry_outside_the_mount(
    tmp_path: Path, hostile: str
) -> None:
    """`bin` and `main` come from the registry, so they are attacker-controlled.

    `PurePosixPath("/out/x") / "/etc/shadow"` is `/etc/shadow` -- an absolute
    component discards everything before it. And the tempting cleanup is worse:
    `"../../../etc/shadow".lstrip("./")` is `"etc/shadow"`, which then *passes*
    a prefix check.
    """
    make_package(tmp_path, "thing", {"name": "thing", "bin": hostile})
    assert _node_entry(tmp_path, "thing") is None


def test_an_ordinary_nested_entry_is_still_accepted(tmp_path: Path) -> None:
    """The guard must not be so tight that real packages stop resolving."""
    make_package(tmp_path, "thing", {"name": "thing", "bin": "./dist/cli/index.js"})
    entry = _node_entry(tmp_path, "thing")
    assert entry is not None
    assert str(entry).startswith(str(FETCH_ROOT) + "/")
    assert "index.js" in str(entry)


def test_a_python_package_carries_the_pythonpath_it_needs(tmp_path: Path) -> None:
    """`python3 -m x` finds nothing without PYTHONPATH, and the failure reads
    like a broken package rather than a missing environment."""
    from mcpscan.fetch import _python_entry

    site = tmp_path / "site"
    (site / "mcp_server_git").mkdir(parents=True)
    (site / "mcp_server_git" / "__main__.py").write_text("")

    assert _python_entry(site, "mcp-server-git") == "mcp_server_git"


def test_a_python_entry_is_discovered_not_guessed(tmp_path: Path) -> None:
    """`spec.replace("-","_")` is right often enough to be dangerous: it produces
    a plausible name for packages whose import name differs from their
    distribution name, and the failure looks like the package being wrong."""
    from mcpscan.fetch import _python_entry

    site = tmp_path / "site"
    (site / "actual_module").mkdir(parents=True)
    (site / "actual_module" / "__main__.py").write_text("")

    # The guessed name (`some_distribution`) does not exist; the real one does.
    assert _python_entry(site, "some-distribution") == "actual_module"


def test_a_python_package_with_no_runnable_module_resolves_to_nothing(
    tmp_path: Path,
) -> None:
    site = tmp_path / "site"
    (site / "just_a_library").mkdir(parents=True)
    from mcpscan.fetch import _python_entry

    assert _python_entry(site, "just-a-library") is None
