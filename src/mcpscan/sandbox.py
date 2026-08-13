"""Docker isolation -- the only module in mcpscan permitted to spawn a process.

Everything a target does happens inside a container built by
:func:`SandboxHandle.build_argv`. There is no parameter, environment variable or
branch here that runs a target on the host, and adding one would defeat the
point of the tool rather than merely weaken it. If another module needs to run
something, it goes through :class:`SandboxHandle`;
``tests/test_containment.py`` enforces that across the whole repository.

Four properties are worth stating explicitly, because each one is load-bearing
and none of them is obvious from reading the flag list:

**Only the fetcher may have network.** ``Limits.network`` is refused for any
other image. The fetcher is safe with egress solely because it never executes
what it downloads; the same flag on the runner is a networked untrusted target,
which is the one configuration this tool exists to prevent.

**Output is drained, never merely capped.** Once ``Limits.stdout_bytes`` is
reached the excess is read and discarded rather than left in the pipe. Stopping
the read would block the ``docker`` client on a full pipe, and the container we
are in the middle of killing would never be reaped.

**The container outlives the CLI on purpose.** ``--rm`` is deliberately absent:
an OOM kill and a wall-clock kill both surface as exit 137, so ``State.OOMKilled``
has to be read before the container is destroyed. Removal happens in a
``finally``, and :func:`reap_stale_containers` cleans up after the crash that
skips it.

**Killing is immediate.** The wall-clock budget *was* the grace period, so the
timeout path goes straight to ``docker kill``. A hostile target that ignores
SIGTERM is exactly the case this has to handle.

A note on ``Outcome.OOM_KILLED``: it is reported when Docker says
``State.OOMKilled`` is true, which on cgroup v2 hosts is not always set even for
a genuine out-of-memory kill. A memory-exhausted target can therefore surface as
``EXITED`` with exit code 137. That under-reporting is deliberate -- inferring
OOM from a bare 137 would mislabel every other SIGKILL as a memory problem.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import tempfile
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Final

DOCKER: Final = "docker"

#: Applied to every container mcpscan creates, so a leak is identifiable as
#: ours and reapable. One value per process.
SESSION_LABEL: Final = "mcpscan.session"
SESSION_ID: Final = uuid.uuid4().hex

#: A container of ours older than this cannot belong to a live scan -- the
#: default wall-clock budget is measured in seconds.
REAP_AFTER: Final = timedelta(hours=1)

# Baked into both images as the image default; passed again so the flag
# contract can assert it rather than trusting the Dockerfile.
SANDBOX_UID: Final = 65532
SANDBOX_GID: Final = 65532

TMPFS_MB: Final = 64
NOFILE: Final = 256
HOSTNAME: Final = "sandbox"

STDERR_BYTES: Final = 256 * 1024

_CHUNK: Final = 64 * 1024
_CID_POLL_S: Final = 0.02
_CID_WAIT_S: Final = 10.0
_DOCKER_CALL_S: Final = 30.0
_KILL_GRACE_S: Final = 20.0

_INSPECT_FORMAT: Final = '{{.Id}} {{.Created}} {{index .Config.Labels "mcpscan.session"}}'


class SandboxError(RuntimeError):
    """The sandbox itself misbehaved, or was asked for a configuration it refuses.

    Never raised because a *target* misbehaved -- a target that floods, hangs or
    crashes is a normal :class:`SandboxResult`, not an exception.
    """


class Image(StrEnum):
    RUNNER = "mcpscan/runner:0.1.0"
    FETCHER = "mcpscan/fetcher:0.1.0"


class Outcome(StrEnum):
    EXITED = "exited"
    TIMEOUT = "timeout"
    OOM_KILLED = "oom_killed"
    OUTPUT_CAP = "output_cap"
    LAUNCH_FAILED = "launch_failed"


@dataclass(frozen=True, slots=True)
class Limits:
    """Resource budget for one container."""

    wall_clock_s: float = 30.0
    memory_mb: int = 512
    pids: int = 128
    cpus: float = 1.0
    stdout_bytes: int = 8 * 1024 * 1024
    #: True only for the fetcher. The runner never gets egress.
    network: bool = False


@dataclass(frozen=True, slots=True)
class Mount:
    source: Path
    target: PurePosixPath
    read_only: bool = True

    def to_spec(self) -> str:
        """Render the ``--mount`` argument.

        ``bind-recursive=readonly`` is what stops a submount of a read-only bind
        from staying writable, and Docker rejects it unless ``bind-propagation``
        is given explicitly alongside.
        """
        parts = [
            "type=bind",
            f"src={self.source}",
            f"dst={self.target}",
            "bind-propagation=rprivate",
        ]
        if self.read_only:
            parts += ["ro", "bind-recursive=readonly"]
        return ",".join(parts)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    outcome: Outcome
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    duration_s: float
    container_id: str

    def verdict(self) -> dict[str, Any]:
        """Parse the *first line* of stdout as JSON.

        First line, not the whole stream: a target may legitimately keep talking
        afterwards, and the escape fixture that floods stdout writes a header
        line and then gigabytes of filler.
        """
        line, _, _ = self.stdout.partition(b"\n")
        if not line.strip():
            raise SandboxError("target wrote no verdict line to stdout")
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"first stdout line is not JSON: {line[:200]!r}") from exc
        if not isinstance(parsed, dict):
            raise SandboxError(f"verdict is {type(parsed).__name__}, expected an object")
        return {str(key): value for key, value in parsed.items()}


@dataclass(frozen=True, slots=True)
class _ContainerState:
    exit_code: int | None
    oom_killed: bool


# --------------------------------------------------------------------------
# docker plumbing
# --------------------------------------------------------------------------
async def _docker(*args: str, timeout: float = _DOCKER_CALL_S) -> tuple[int, str, str]:
    """Run a short-lived docker command and capture it. Never used for targets."""
    try:
        proc = await asyncio.create_subprocess_exec(
            DOCKER,
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        raise SandboxError(f"could not execute `docker {args[0] if args else ''}`: {exc}") from exc

    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise SandboxError(f"`docker {args[0] if args else ''}` timed out") from exc

    code = -1 if proc.returncode is None else proc.returncode
    return code, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


async def _drain(
    stream: asyncio.StreamReader,
    cap: int,
    truncated_event: asyncio.Event | None,
) -> tuple[bytes, bool]:
    """Read to EOF, keeping at most ``cap`` bytes and discarding the rest.

    The discarding is the important half. Simply stopping at the cap would leave
    the target blocked writing into a full pipe, which in turn blocks the
    ``docker`` client we need to exit before the container can be reaped.
    """
    buffer = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(_CHUNK)
        if not chunk:
            return bytes(buffer), truncated
        room = cap - len(buffer)
        if room > 0:
            buffer.extend(chunk[:room])
        if not truncated and len(chunk) > room:
            truncated = True
            if truncated_event is not None:
                truncated_event.set()


async def _read_cid(cidfile: Path, *, timeout: float = _CID_WAIT_S) -> str:
    """Wait for the docker client to record the container id.

    Written when the container is created, which is well before anything we
    would want to kill has had time to misbehave.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            text = cidfile.read_text(encoding="utf-8").strip()
        except OSError:
            text = ""
        if text:
            return text
        if time.monotonic() >= deadline:
            return ""
        await asyncio.sleep(_CID_POLL_S)


async def _inspect_state(container_id: str) -> _ContainerState | None:
    code, out, _ = await _docker("inspect", "--format", "{{json .State}}", container_id)
    if code != 0:
        return None
    try:
        parsed = json.loads(out)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    exit_code = parsed.get("ExitCode")
    return _ContainerState(
        exit_code=exit_code if isinstance(exit_code, int) else None,
        oom_killed=parsed.get("OOMKilled") is True,
    )


def _parse_created(value: str) -> datetime | None:
    """Parse Docker's ``.Created``, which is RFC3339 UTC at nanosecond precision.

    ``datetime.fromisoformat`` rejects nine fractional digits on Python 3.11, and
    the fraction is meaningless at hour granularity, so the fixed
    ``YYYY-MM-DDTHH:MM:SS`` prefix is taken instead of reaching for a regex.
    """
    try:
        return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# leak reaping
# --------------------------------------------------------------------------
_reap_lock = asyncio.Lock()
_reaped = False


async def reap_stale_containers(older_than: timedelta = REAP_AFTER) -> list[str]:
    """Remove mcpscan containers left behind by an earlier run.

    Dropping ``--rm`` is what makes OOM attribution possible, and it is also what
    makes a leak possible: a crash, a SIGKILL or a power cut between ``docker
    run`` and the removal in ``finally`` strands a container. This is the other
    half of that trade.

    Containers from the *current* session are skipped regardless of age, so a
    deliberately long-running scan cannot reap itself. Note that ``docker ps``
    has no ``until`` filter -- only ``container prune`` does, and that will not
    touch a running container -- so the age comparison is done here.

    Returns the ids removed. Errors are the caller's to ignore; housekeeping
    must not take a scan down with it.
    """
    code, out, _ = await _docker(
        "ps", "--all", "--quiet", "--filter", f"label={SESSION_LABEL}"
    )
    if code != 0:
        return []
    ids = out.split()
    if not ids:
        return []

    # A non-zero code here just means one of the ids disappeared between the two
    # calls; the lines that did print are still good.
    _, out, _ = await _docker("inspect", "--format", _INSPECT_FORMAT, *ids)

    cutoff = datetime.now(UTC) - older_than
    stale: list[str] = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        container_id, created = fields[0], fields[1]
        session = fields[2] if len(fields) > 2 else ""
        if session == SESSION_ID:
            continue
        timestamp = _parse_created(created)
        if timestamp is None or timestamp > cutoff:
            continue
        stale.append(container_id)

    if stale:
        await _docker("rm", "--force", *stale)
    return stale


async def _reap_once() -> None:
    """Reap at most once per process, on first use rather than at import.

    At import it would make ``import mcpscan.sandbox`` talk to the Docker daemon,
    which would break ``tests/test_sandbox_flags.py`` -- that suite inspects
    ``build_argv`` output on machines with no daemon at all.

    Guarded by the lock alone rather than a double-checked flag: the lock is
    uncontended after the first call, and a container launch costs orders of
    magnitude more than acquiring it.
    """
    global _reaped
    async with _reap_lock:
        if _reaped:
            return
        _reaped = True
        try:
            await reap_stale_containers()
        except (OSError, SandboxError):
            # Housekeeping never fails a scan. If Docker is genuinely broken,
            # the run() that follows will say so with a real error.
            return


# --------------------------------------------------------------------------
# the sandbox
# --------------------------------------------------------------------------
class SandboxHandle:
    """Runs a command inside a hardened container. There is no other mode."""

    @staticmethod
    def available() -> bool:
        """Whether a Docker daemon is reachable. Synchronous: the CLI calls it early."""
        try:
            completed = subprocess.run(
                [DOCKER, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                timeout=_DOCKER_CALL_S,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0

    @staticmethod
    def build_argv(
        command: Sequence[str],
        *,
        image: Image,
        limits: Limits,
        env: Mapping[str, str] | None,
        mounts: Sequence[Mount],
        cidfile: Path,
    ) -> list[str]:
        """Build the ``docker run`` argv.

        Pure: no clock, no filesystem, no daemon, no globals beyond the constants
        above. That is what lets the flag contract in
        ``tests/test_sandbox_flags.py`` assert on the result with Docker absent,
        and it is why the caller supplies ``cidfile`` rather than this creating
        one.

        Every flag is justified in the plan's flag table; the ones whose absence
        is silent rather than loud:

        ``--memory-swap`` equal to ``--memory``
            Omitted, Docker grants swap equal to twice memory and the cap
            quietly becomes 1.5 GB of thrash.
        ``--log-driver none``
            Omitted, the daemon writes every byte of the target's stdout to
            ``/var/lib/docker`` on the host, whatever our own read cap says.
        ``--pids-limit``
            Counts threads, not just processes, on cgroup v2.

        Raises :class:`SandboxError` if ``limits.network`` is set for anything
        but the fetcher. Refusing here rather than at the call site makes this
        the single chokepoint: :meth:`run` builds its argv through this method,
        so there is no path to a networked runner.
        """
        if limits.network and image is not Image.FETCHER:
            raise SandboxError(
                f"network=True is only valid for {Image.FETCHER}, not {image}. "
                "The fetcher may have egress because it never executes what it "
                "downloads; the same flag on a runner is a networked untrusted "
                "target."
            )

        argv = [
            DOCKER,
            "run",
            "--cidfile",
            str(cidfile),
            "--label",
            f"{SESSION_LABEL}={SESSION_ID}",
            "--network",
            "bridge" if limits.network else "none",
            "--read-only",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={TMPFS_MB}m,mode=1777",  # noqa: S108
            "--memory",
            f"{limits.memory_mb}m",
            "--memory-swap",
            f"{limits.memory_mb}m",
            "--cpus",
            f"{limits.cpus}",
            "--pids-limit",
            str(limits.pids),
            "--ulimit",
            f"nofile={NOFILE}:{NOFILE}",
            "--ulimit",
            "core=0",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            f"{SANDBOX_UID}:{SANDBOX_GID}",
            "--init",
            "--log-driver",
            "none",
            "--hostname",
            HOSTNAME,
        ]

        # KEY=VALUE only. A bare `-e KEY` would inherit KEY from the host
        # environment, which is how a real credential reaches a target.
        for key, value in (env or {}).items():
            argv += ["--env", f"{key}={value}"]

        for mount in mounts:
            argv += ["--mount", mount.to_spec()]

        argv.append(str(image))
        argv.extend(command)
        return argv

    @classmethod
    async def run(
        cls,
        command: Sequence[str],
        *,
        image: Image,
        limits: Limits,
        env: Mapping[str, str] | None = None,
        mounts: Sequence[Mount] = (),
    ) -> SandboxResult:
        """Run ``command`` in a container and return what happened to it.

        A target that floods, hangs, OOMs or crashes produces a
        :class:`SandboxResult` describing that. :class:`SandboxError` is reserved
        for the sandbox failing at its own job.
        """
        await _reap_once()

        workdir = Path(tempfile.mkdtemp(prefix="mcpscan-"))
        cidfile = workdir / "cid"  # must not exist; docker refuses otherwise
        argv = cls.build_argv(
            list(command),
            image=image,
            limits=limits,
            env=env,
            mounts=mounts,
            cidfile=cidfile,
        )

        container_id = ""
        started = time.monotonic()
        try:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except OSError as exc:
                raise SandboxError(f"could not launch `docker run`: {exc}") from exc

            stdout_stream, stderr_stream = proc.stdout, proc.stderr
            if stdout_stream is None or stderr_stream is None:
                proc.kill()
                await proc.wait()
                raise SandboxError("docker subprocess was created without pipes")

            over_cap = asyncio.Event()
            stdout_task = asyncio.create_task(_drain(stdout_stream, limits.stdout_bytes, over_cap))
            stderr_task = asyncio.create_task(_drain(stderr_stream, STDERR_BYTES, None))
            exited = asyncio.create_task(proc.wait())
            capped = asyncio.create_task(over_cap.wait())

            try:
                finished, _ = await asyncio.wait(
                    {exited, capped},
                    timeout=limits.wall_clock_s,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                capped.cancel()

            timed_out = not finished
            if timed_out or over_cap.is_set():
                # The budget was the grace period. Straight to SIGKILL -- a
                # target that ignores SIGTERM is precisely this case.
                container_id = await _read_cid(cidfile)
                if container_id:
                    await _docker("kill", container_id)
                try:
                    await asyncio.wait_for(asyncio.shield(exited), timeout=_KILL_GRACE_S)
                except TimeoutError:
                    proc.kill()
                    await exited

            await exited
            stdout, stdout_truncated = await stdout_task
            stderr, _ = await stderr_task
            duration_s = time.monotonic() - started

            if not container_id:
                container_id = await _read_cid(cidfile, timeout=0.0)

            state = await _inspect_state(container_id) if container_id else None

            if not container_id:
                outcome = Outcome.LAUNCH_FAILED
            elif timed_out:
                outcome = Outcome.TIMEOUT
            elif stdout_truncated:
                outcome = Outcome.OUTPUT_CAP
            elif state is not None and state.oom_killed:
                outcome = Outcome.OOM_KILLED
            else:
                outcome = Outcome.EXITED

            exit_code = state.exit_code if state is not None else proc.returncode

            return SandboxResult(
                outcome=outcome,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_truncated,
                duration_s=duration_s,
                container_id=container_id,
            )
        finally:
            # An exception or a cancellation between `docker run` creating the
            # container and the id being read would otherwise strand it until
            # the next reap. One non-blocking re-read closes that window; the
            # cidfile is written at creation, so if a container exists its id
            # is already on disk.
            if not container_id:
                container_id = await _read_cid(cidfile, timeout=0.0)
            if container_id:
                await _docker("rm", "--force", container_id)
            shutil.rmtree(workdir, ignore_errors=True)
