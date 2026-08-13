"""The sandbox escape suite -- seven hostile fixtures run through the sandbox.

**These tests fail right now, and that is the point.** ``src/mcpscan/sandbox.py``
does not exist yet; it is the remaining half of step 2 in ``CLAUDE.md``. This
file was written first so that it *is* the specification: the API referenced
below and the flags asserted in ``test_sandbox_flags.py`` are the contract the
implementation has to satisfy, rather than a description written afterwards to
match whatever got built.

Two structural choices, both deliberate:

*Gating.* The module skips unless both sandbox images are present. CI has a
Docker daemon but no ``make images`` step, and ``CLAUDE.md`` requires
``make check`` to pass before any commit -- so the suite must be red on a
developer's machine, where it drives the work, and skipped where it would only
be noise. ``tests/dockerprobe.py`` checks for the images specifically, not just
a live daemon.

*Deferred import.* ``mcpscan.sandbox`` is imported inside ``_sandbox()``, not at
module scope. At module scope the ImportError would be a pytest *collection*
error, which aborts the entire run and hides every other test in the repo. From
inside a test body it is seven ordinary, readable failures.

Each fixture reports a JSON verdict describing what it *attempted*, and the
assertions below check that count. A test that only checked "the bad thing did
not happen" would pass identically for a contained fixture and for one that
crashed before trying anything -- a security suite that goes green because its
payload is broken is worse than having no suite.

The contract these tests pin
----------------------------

::

    class Image(StrEnum):
        RUNNER  = "mcpscan/runner:0.1.0"
        FETCHER = "mcpscan/fetcher:0.1.0"

    class Outcome(StrEnum):
        EXITED | TIMEOUT | OOM_KILLED | OUTPUT_CAP | LAUNCH_FAILED

    @dataclass(frozen=True, slots=True)
    class Limits:
        wall_clock_s: float = 30.0
        memory_mb:    int   = 512
        pids:         int   = 128
        cpus:         float = 1.0
        stdout_bytes: int   = 8 * 1024 * 1024
        network:      bool  = False      # True only for the fetcher

    @dataclass(frozen=True, slots=True)
    class Mount:
        source: Path
        target: PurePosixPath
        read_only: bool = True

    @dataclass(frozen=True, slots=True)
    class SandboxResult:
        outcome:          Outcome
        exit_code:        int | None
        stdout:           bytes
        stderr:           bytes
        stdout_truncated: bool
        duration_s:       float
        container_id:     str
        def verdict(self) -> dict[str, Any]: ...

    class SandboxHandle:
        @staticmethod
        def available() -> bool: ...
        @staticmethod
        def build_argv(command, *, image, limits, env, mounts, cidfile) -> list[str]: ...
        @classmethod
        async def run(cls, command, *, image, limits, env=None, mounts=()) -> SandboxResult: ...

``verdict()`` parses **the first line** of stdout as JSON, not the whole stream.
``escape_stdout_flood`` writes a header line and then gigabytes of filler, and
the header is what proves it got as far as flooding.

``run()`` is a coroutine because ``pyproject.toml`` sets ``asyncio_mode = "auto"``
and ``CLAUDE.md`` lists ``asyncio.create_subprocess_*`` among the permitted
spawn calls. The long-lived streaming handle that step 3 needs for JSON-RPC is
deliberately *not* pinned here -- these tests use ``run()`` only, so they leave
that design open.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests.dockerprobe import container_exists, images_ready, skip_reason

FIXTURES = Path(__file__).parent / "fixtures" / "escapes"

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(not images_ready(), reason=skip_reason()),
]


def _sandbox() -> Any:
    """Import the module under test.

    Inside a function on purpose -- see the module docstring.
    """
    from mcpscan import sandbox

    return sandbox


async def run_fixture(name: str, **limits: Any) -> Any:
    """Run one escape fixture in the runner image and return its SandboxResult."""
    sb = _sandbox()
    return await sb.SandboxHandle.run(
        ["python3", f"/fixtures/{name}"],
        image=sb.Image.RUNNER,
        limits=sb.Limits(**limits),
        mounts=(
            sb.Mount(source=FIXTURES, target=PurePosixPath("/fixtures"), read_only=True),
        ),
    )


def assert_fixture_ran(verdict: dict[str, Any], expected_attempts: int) -> None:
    """Guard against a broken payload being mistaken for a working sandbox."""
    assert verdict["attempted"] == expected_attempts, (
        f"fixture made {verdict['attempted']} attempts, expected {expected_attempts} -- "
        "the payload is broken, so this run proves nothing about containment"
    )
    assert verdict["bugs"] == 0, f"fixture raised a non-OSError: {verdict['attempts']}"


# --------------------------------------------------------------------------
# 1. network egress
# --------------------------------------------------------------------------
async def test_network_egress_is_blocked() -> None:
    """`--network none`: no TCP, no UDP, no DNS, no cloud metadata endpoint."""
    result = await run_fixture("escape_network.py")
    verdict = result.verdict()

    assert_fixture_ran(verdict, expected_attempts=4)
    assert verdict["blocked"] == 4, f"egress reached the network: {verdict['attempts']}"
    assert result.outcome is _sandbox().Outcome.EXITED
    assert result.exit_code == 0
    # The control proves the socket layer worked, so "all four refused" means
    # the route was missing rather than the interpreter being broken.
    assert "refused" in verdict["loopback_control"], verdict["loopback_control"]


# --------------------------------------------------------------------------
# 2. fork bomb
# --------------------------------------------------------------------------
async def test_fork_bomb_hits_the_pid_ceiling() -> None:
    """`--pids-limit`: process creation stops at the configured ceiling."""
    result = await run_fixture("escape_forkbomb.py", pids=64, wall_clock_s=30.0)
    verdict = result.verdict()

    assert not verdict["unbounded"], (
        f"forked {verdict['ceiling']} processes without the kernel refusing -- "
        "no pid ceiling was enforced"
    )
    assert 0 < verdict["ceiling"] <= 64, verdict
    assert verdict["refusal"] is not None
    assert result.outcome is _sandbox().Outcome.EXITED


# --------------------------------------------------------------------------
# 3. filesystem writes
# --------------------------------------------------------------------------
async def test_read_only_paths_reject_writes() -> None:
    """`--read-only`, the `ro` bind mount, and the `noexec` tmpfs."""
    result = await run_fixture("escape_fswrite.py")
    verdict = result.verdict()

    assert_fixture_ran(verdict, expected_attempts=5)
    assert verdict["blocked"] == 5, f"a write succeeded: {verdict['attempts']}"

    # Positive control: if /tmp were read-only too, "every write failed" would
    # be trivially true and this test would prove nothing.
    assert verdict["tmp_writable"] is True, "scratch tmpfs is not writable at all"

    # Only a native execve is refused under noexec; `python3 /tmp/x.py` is not.
    noexec = verdict["tmp_noexec"]
    assert noexec["blocked"] is True, f"executed a binary from the noexec tmpfs: {noexec}"


# --------------------------------------------------------------------------
# 4. stdout flood
# --------------------------------------------------------------------------
async def test_stdout_flood_is_capped() -> None:
    """A target writing 5 GiB must not be buffered, persisted, or waited on."""
    cap = 1024 * 1024
    result = await run_fixture("escape_stdout_flood.py", stdout_bytes=cap, wall_clock_s=30.0)

    assert result.stdout_truncated, "read the whole flood instead of capping it"
    assert len(result.stdout) <= cap, f"cap was {cap}, read {len(result.stdout)} bytes"
    assert result.outcome is _sandbox().Outcome.OUTPUT_CAP
    # The header proves the fixture reached the flood rather than dying early.
    assert result.verdict()["phase"] == "start"
    assert result.duration_s < 30.0, "capping did not stop the container promptly"


# --------------------------------------------------------------------------
# 5. hung process
# --------------------------------------------------------------------------
async def test_hung_process_is_killed_past_timeout() -> None:
    """The fixture ignores SIGTERM, so only a SIGKILL escalation ends it."""
    budget = 3.0
    result = await run_fixture("escape_hang.py", wall_clock_s=budget)

    assert result.outcome is _sandbox().Outcome.TIMEOUT
    assert result.verdict()["phase"] == "hanging", "never reached the hang"
    assert result.duration_s >= budget, "killed before the budget was spent"
    assert result.duration_s < budget + 20.0, (
        f"took {result.duration_s:.1f}s to kill a SIGTERM-ignoring process; "
        "the timeout path is not escalating to SIGKILL"
    )
    assert not container_exists(result.container_id), "timed-out container was leaked"


# --------------------------------------------------------------------------
# 6. /proc/1/root escape
# --------------------------------------------------------------------------
async def test_proc_1_root_does_not_reach_the_host() -> None:
    """The PID namespace is private, and the capability/user flags took effect."""
    result = await run_fixture("escape_procroot.py")
    verdict = result.verdict()

    assert verdict["pid_namespace"]["contained"] is True, (
        f"/proc/1/root is on a different device than / -- the PID namespace is "
        f"shared with the host: {verdict['pid_namespace']}"
    )
    assert verdict["host_shadow_readable"] is False, "read /etc/shadow through /proc/1/root"
    assert verdict["is_root"] is False, "running as uid 0"
    assert verdict["caps_all_zero"] is True, f"capabilities retained: {verdict['capabilities']}"
    assert verdict["no_new_privs"] == "1", "no-new-privileges was not applied"
    assert verdict["seccomp_mode"] == "2", "seccomp is not in filter mode"
    assert verdict["kcore"]["masked"] is True, f"/proc/kcore is readable: {verdict['kcore']}"
    assert verdict["cgroup_writable"] is False, "cgroup fs is writable"
    assert verdict["docker_sockets"] == [], f"container runtime socket exposed: {verdict}"


# --------------------------------------------------------------------------
# 7. clean exit -- the negative control
# --------------------------------------------------------------------------
async def test_clean_exit_is_reported_as_success() -> None:
    """Without this, a sandbox that runs nothing at all passes tests 1-6."""
    result = await run_fixture("escape_clean.py")
    verdict = result.verdict()

    assert result.outcome is _sandbox().Outcome.EXITED
    assert result.exit_code == 0
    assert result.stdout_truncated is False
    assert verdict["fixture"] == "clean"
    assert verdict["uid"] != 0
    assert result.duration_s < 30.0
