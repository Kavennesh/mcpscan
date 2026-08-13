"""The `docker run` flag contract.

Pure argv inspection -- no daemon, no images, no containers. That is the point:
this is the one guard in the sandbox suite that can run on CI, where the escape
tests in ``test_sandbox.py`` are necessarily skipped. It lives in its own file
for exactly that reason; folded into ``test_sandbox.py`` it would inherit that
module's "skip unless images are built" marker and quietly never run anywhere.

It is gated on ``mcpscan.sandbox`` existing instead, so it is dormant today and
becomes permanently enforcing the moment the module lands. What it defends
against is not the initial implementation -- it is the refactor eighteen months
from now that loosens one flag to make some awkward target work, which is
precisely how sandboxes stop being sandboxes.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

sandbox = pytest.importorskip(
    "mcpscan.sandbox",
    reason="src/mcpscan/sandbox.py not implemented yet (CLAUDE.md build order, step 2)",
)

CID = Path("/run/mcpscan/cid")
TARGET_CMD = ["python3", "/fixtures/escape_clean.py"]


def build(**overrides: Any) -> list[str]:
    kwargs: dict[str, Any] = {
        "image": sandbox.Image.RUNNER,
        "limits": sandbox.Limits(),
        "env": None,
        "mounts": (
            sandbox.Mount(
                source=Path("/srv/target"),
                target=PurePosixPath("/target"),
                read_only=True,
            ),
        ),
        "cidfile": CID,
    }
    kwargs.update(overrides)
    return sandbox.SandboxHandle.build_argv(list(TARGET_CMD), **kwargs)


def split(argv: list[str], image: str) -> tuple[list[str], list[str]]:
    """Return (flag section, target command), using the image as the boundary."""
    assert argv[:2] == ["docker", "run"], argv[:2]
    index = argv.index(image)
    return argv[2:index], argv[index + 1 :]


def options(flags: list[str]) -> dict[str, list[str]]:
    """Parse the flag section, accepting both `--flag value` and `--flag=value`."""
    parsed: dict[str, list[str]] = defaultdict(list)
    i = 0
    while i < len(flags):
        token = flags[i]
        assert token.startswith("-"), f"unexpected bare token in flag section: {token!r}"
        if "=" in token:
            name, _, value = token.partition("=")
            parsed[name].append(value)
            i += 1
        elif i + 1 < len(flags) and not flags[i + 1].startswith("-"):
            parsed[token].append(flags[i + 1])
            i += 2
        else:
            parsed[token].append("")
            i += 1
    return dict(parsed)


def runner_options(**overrides: Any) -> dict[str, list[str]]:
    argv = build(**overrides)
    flags, _ = split(argv, str(sandbox.Image.RUNNER))
    return options(flags)


def test_runner_argv_carries_every_required_flag() -> None:
    opts = runner_options()

    assert opts["--network"] == ["none"]
    assert opts["--read-only"] == [""]
    assert opts["--cap-drop"] == ["ALL"]
    assert opts["--user"] == ["65532:65532"]
    assert opts["--init"] == [""]
    assert opts["--pids-limit"] == ["128"]
    assert opts["--cpus"] == ["1.0"]
    assert opts["--cidfile"] == [str(CID)]
    assert opts["--hostname"] == ["sandbox"]

    # Without this the daemon writes every byte of a target's stdout to
    # /var/lib/docker on the host, independently of our own read cap.
    assert opts["--log-driver"] == ["none"]

    assert "no-new-privileges" in " ".join(opts["--security-opt"])

    ulimits = set(opts["--ulimit"])
    assert any(u.startswith("nofile=") for u in ulimits), ulimits
    assert "core=0" in ulimits, ulimits

    tmpfs = " ".join(opts["--tmpfs"])
    assert tmpfs.startswith("/tmp:"), tmpfs  # noqa: S108 -- asserting on a container path
    for option in ("noexec", "nosuid", "nodev", "size=", "mode=1777"):
        assert option in tmpfs, f"{option} missing from tmpfs spec: {tmpfs}"

    mount = " ".join(opts["--mount"])
    assert "type=bind" in mount and "ro" in mount.split(","), mount
    # Docker rejects bind-recursive without an explicit bind-propagation, and
    # without it a submount of a read-only bind stays writable.
    assert "bind-propagation=rprivate" in mount, mount
    assert "bind-recursive=readonly" in mount, mount


def test_swap_is_disabled_not_merely_capped() -> None:
    """--memory alone silently permits 2x that in swap; equal values disable it."""
    opts = runner_options()
    assert opts["--memory"] == opts["--memory-swap"], (
        f"memory={opts['--memory']} swap={opts['--memory-swap']} -- unequal values "
        "hand the target swap on top of its memory cap"
    )


def test_runner_argv_contains_no_escape_hatch() -> None:
    """Every flag here is a plausible one-line 'fix' that would open the box."""
    argv = build()
    joined = " ".join(argv)

    for flag in (
        "--privileged",
        "--userns=host",
        "--oom-kill-disable",
        "--device",
        "--group-add",
        "--cap-add",
        "--pid=host",
        "--ipc=host",
        "--uts=host",
        "--network host",
        "seccomp=unconfined",
        "apparmor=unconfined",
        "systempaths=unconfined",
        "docker.sock",
    ):
        assert flag not in joined, f"escape hatch in runner argv: {flag}"

    opts = options(split(argv, str(sandbox.Image.RUNNER))[0])
    assert "--pid" not in opts
    assert "--ipc" not in opts or opts["--ipc"] != ["host"]

    for mount in opts.get("--mount", []) + opts.get("-v", []) + opts.get("--volume", []):
        source = mount.split(",")[0].split("=")[-1] if "=" in mount else mount.split(":")[0]
        assert source not in ("/", "/proc", "/sys", "/dev", "/etc", "/var/run"), mount


def test_rm_is_absent_so_an_oom_can_be_attributed() -> None:
    """--rm destroys the container before State.OOMKilled can be read.

    An OOM kill and a wall-clock kill both surface as exit 137. Outcome.OOM_KILLED
    only exists if the container survives long enough to be inspected.
    """
    opts = runner_options()
    assert "--rm" not in opts, (
        "--rm removes the container before it can be inspected, making "
        "Outcome.OOM_KILLED indistinguishable from Outcome.TIMEOUT"
    )


def test_target_command_is_passed_through_untouched() -> None:
    """Shell metacharacters stay literal, as targets.py already guarantees."""
    hostile = ["npx", "-y", "foo", ";", "rm", "-rf", "/", "&&", "curl", "$(whoami)"]
    argv = sandbox.SandboxHandle.build_argv(
        list(hostile),
        image=sandbox.Image.RUNNER,
        limits=sandbox.Limits(),
        env=None,
        mounts=(),
        cidfile=CID,
    )
    _, command = split(argv, str(sandbox.Image.RUNNER))
    assert command == hostile, "target argv was reordered, quoted, or joined into a shell string"


def test_env_is_never_inherited_from_the_host() -> None:
    """`-e VAR` with no '=' pulls VAR out of the host environment.

    That is a direct path for a real credential to reach a target, which
    CLAUDE.md constraint 3 forbids. Only explicit KEY=VALUE pairs are allowed.
    """
    opts = runner_options(env={"GITHUB_TOKEN": "mcpscan-canary-0000"})
    passed = opts.get("-e", []) + opts.get("--env", [])
    assert passed, "env was dropped entirely"
    for entry in passed:
        assert "=" in entry, f"bare -e {entry} inherits {entry} from the host environment"
    assert "--env-file" not in opts


def test_network_is_enabled_only_when_limits_ask_for_it() -> None:
    """The fetcher is the sole reason a network flag other than 'none' exists."""
    assert runner_options()["--network"] == ["none"]

    fetching = sandbox.Limits(network=True)
    argv = build(image=sandbox.Image.FETCHER, limits=fetching)
    flags, _ = split(argv, str(sandbox.Image.FETCHER))
    assert options(flags)["--network"] != ["none"]
    assert "--network host" not in " ".join(argv)


def test_network_is_refused_for_the_runner_image() -> None:
    """The negative half of fetch/execute separation.

    The test above proves the fetcher *can* be networked. This proves nothing
    else can. Without it, `Limits(network=True)` reaches build_argv for any
    image and silently produces `--network bridge` around untrusted code --
    which is the exact configuration the whole sandbox exists to prevent, and
    it would be a one-word change to fall into.

    build_argv is the single chokepoint: run() constructs its argv here, so
    refusing at this level closes the path rather than one caller of it.
    """
    with pytest.raises(sandbox.SandboxError, match="fetcher"):
        build(image=sandbox.Image.RUNNER, limits=sandbox.Limits(network=True))
