"""`.mcpscan.lock` -- what the server looked like when you approved it.

A scan is a moment. This is the file that makes it a commitment: hashes of every
tool's model-steering fields, committed to the repository, and `mcpscan verify`
in CI comparing a live server against them on every build. That is the difference
between an audit and a control, and it is the supply-chain half of the rug-pull
problem -- a dependency whose tool descriptions change between two builds is
exactly what MCP-007 looks for inside one scan, seen across time instead.

Three things shape the format:

**It is read by humans in pull requests.** Sorted keys, one tool per line, and
the hash truncated to something a reviewer can compare at a glance. A changed
description has to show up as a one-line diff, not a reflowed blob.

**It hashes what steers a model, and nothing else.** ``tool_fingerprint`` already
picks those fields for MCP-007, and reusing it means the lock and the rug-pull
probe can never disagree about what counts as a change. A server that reorders
its JSON keys or renumbers a ``_meta`` block is not drift.

**Absence is never success.** A missing lock, an unreachable server or a target
that is in the lock but was not scanned are all errors, not passes. "I could not
check" must never be reported as "unchanged".
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from mcpscan.client import ServerSurvey, tool_fingerprint

#: Bumped when a consumer would break. Additive fields do not bump it.
LOCK_VERSION: Final = 1

DEFAULT_LOCK_PATH: Final = Path(".mcpscan.lock")

#: How much of the digest is written. Full sha256 in the file would be unreadable
#: in a diff and no more secure -- this is a change detector, not a signature.
DIGEST_CHARS: Final = 16


class LockError(Exception):
    """The lock could not be read or does not describe what was asked of it."""


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


def _fingerprints(tools: Sequence[dict[str, Any]]) -> Iterator[tuple[str, str]]:
    yield from tool_fingerprint(list(tools)).items()


def tool_digests(tools: Sequence[dict[str, Any]]) -> dict[str, str]:
    """Hash every tool's steering fields. Shared with MCP-007 by construction."""
    return {name: digest(blob) for name, blob in _fingerprints(tools)}


@dataclass(frozen=True, slots=True)
class ServerLock:
    """One server's approved shape."""

    command: list[str] = field(default_factory=list)
    protocol_version: str = ""
    server_info: dict[str, str] = field(default_factory=dict)
    instructions: str | None = None
    tools: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_survey(
        cls,
        survey: ServerSurvey,
        command: Sequence[str] | None = None,
        *,
        redact: Callable[[str], str] | None = None,
    ) -> ServerLock:
        """Hash a survey. ``redact`` is applied to text before hashing.

        Without it, a server that echoes a canary into a tool description hashes
        a fresh random token on every scan, and `verify` is permanently red for a
        reason invisible in the diff -- the description looks identical because
        the part that changed is the part we planted.
        """
        profile = survey.profile
        scrub = redact or (lambda text: text)
        return cls(
            command=list(command or []),
            protocol_version=profile.protocol_version,
            server_info={
                "name": profile.name,
                "version": profile.version,
            },
            instructions=digest(scrub(profile.instructions)) if profile.instructions else None,
            tools={name: digest(scrub(blob)) for name, blob in _fingerprints(survey.tools)},
        )

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "command": self.command,
            "protocol_version": self.protocol_version,
            "server_info": dict(sorted(self.server_info.items())),
            "tools": dict(sorted(self.tools.items())),
        }
        if self.instructions is not None:
            payload["instructions"] = self.instructions
        return payload

    @classmethod
    def from_json(cls, data: object, where: str) -> ServerLock:
        if not isinstance(data, dict):
            raise LockError(f"{where}: expected an object")
        tools = data.get("tools")
        if not isinstance(tools, dict):
            raise LockError(f"{where}: 'tools' must be an object of name -> digest")
        info = data.get("server_info")
        return cls(
            command=[str(part) for part in data.get("command", []) or []],
            protocol_version=str(data.get("protocol_version", "")),
            server_info={str(k): str(v) for k, v in (info or {}).items()}
            if isinstance(info, dict)
            else {},
            instructions=data.get("instructions"),
            tools={str(k): str(v) for k, v in tools.items()},
        )


@dataclass(frozen=True, slots=True)
class Lock:
    """The whole file. One entry per server, keyed by target label."""

    servers: dict[str, ServerLock] = field(default_factory=dict)

    def render(self) -> str:
        payload = {
            "lock_version": LOCK_VERSION,
            "servers": {name: self.servers[name].to_json() for name in sorted(self.servers)},
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"

    def write(self, path: Path = DEFAULT_LOCK_PATH) -> None:
        path.write_text(self.render(), encoding="utf-8")

    @classmethod
    def read(cls, path: Path = DEFAULT_LOCK_PATH) -> Lock:
        """Load a lock. A missing file is an error, never an empty lock.

        Treating absence as "nothing to check" would make `verify` pass on a
        repository that never had a lock, which is the one thing it must not do.
        """
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise LockError(
                f"no lock at {path}. Create one with "
                f"`mcpscan scan --stdio '<command>' --write-lock`."
            ) from exc
        except OSError as exc:
            raise LockError(f"could not read {path}: {exc}") from exc

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LockError(f"{path} is not valid JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise LockError(f"{path}: expected an object at the top level")

        version = data.get("lock_version")
        if version != LOCK_VERSION:
            raise LockError(
                f"{path}: lock_version is {version!r}, this mcpscan writes "
                f"{LOCK_VERSION}. Regenerate it with --write-lock."
            )

        servers = data.get("servers")
        if not isinstance(servers, dict):
            raise LockError(f"{path}: 'servers' must be an object")

        return cls(
            servers={
                str(name): ServerLock.from_json(entry, f"{path}: servers.{name}")
                for name, entry in servers.items()
            }
        )


# --------------------------------------------------------------------------
# drift
# --------------------------------------------------------------------------
class DriftReason(StrEnum):
    TOOL_CHANGED = "tool_changed"
    TOOL_ADDED = "tool_added"
    TOOL_REMOVED = "tool_removed"
    INSTRUCTIONS_CHANGED = "instructions_changed"
    PROTOCOL_CHANGED = "protocol_changed"
    SERVER_INFO_CHANGED = "server_info_changed"


@dataclass(frozen=True, slots=True)
class Drift:
    """One difference between the lock and what the server serves now."""

    server: str
    reason: DriftReason
    what: str
    was: str | None = None
    now: str | None = None

    def describe(self) -> str:
        arrow = ""
        if self.was is not None or self.now is not None:
            arrow = f"  {self.was or '(absent)'} -> {self.now or '(absent)'}"
        return f"{self.server}: {self.reason.value} {self.what}{arrow}"


def compare(name: str, locked: ServerLock, current: ServerLock) -> list[Drift]:
    """Every way ``current`` differs from what was approved. Pure.

    A tool appearing counts. That is the point: the supply-chain case is a
    dependency that grows a capability between builds, and a check that only
    looked at tools it already knew about would miss exactly that.
    """
    drifts: list[Drift] = []

    if locked.protocol_version and locked.protocol_version != current.protocol_version:
        drifts.append(
            Drift(
                name,
                DriftReason.PROTOCOL_CHANGED,
                "protocol version",
                locked.protocol_version,
                current.protocol_version,
            )
        )

    for key in sorted(set(locked.server_info) | set(current.server_info)):
        was, now = locked.server_info.get(key), current.server_info.get(key)
        if locked.server_info and was != now:
            drifts.append(
                Drift(name, DriftReason.SERVER_INFO_CHANGED, f"serverInfo.{key}", was, now)
            )

    if locked.instructions != current.instructions:
        drifts.append(
            Drift(
                name,
                DriftReason.INSTRUCTIONS_CHANGED,
                "instructions",
                locked.instructions,
                current.instructions,
            )
        )

    for tool in sorted(set(locked.tools) | set(current.tools)):
        was, now = locked.tools.get(tool), current.tools.get(tool)
        if was == now:
            continue
        if was is None:
            drifts.append(Drift(name, DriftReason.TOOL_ADDED, tool, None, now))
        elif now is None:
            drifts.append(Drift(name, DriftReason.TOOL_REMOVED, tool, was, None))
        else:
            drifts.append(Drift(name, DriftReason.TOOL_CHANGED, tool, was, now))

    return drifts


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """What `mcpscan verify` found. ``errors`` is exit 2, ``drifts`` is exit 1."""

    checked: list[str] = field(default_factory=list)
    drifts: list[Drift] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.drifts and not self.errors

    def render(self) -> str:
        lines: list[str] = []
        for drift in self.drifts:
            lines.append(f"  {drift.describe()}")
        for error in self.errors:
            lines.append(f"  error: {error}")
        if not lines:
            lines.append(f"  {len(self.checked)} server(s) unchanged")
        return "\n".join(lines) + "\n"

    def to_json(self) -> dict[str, Any]:
        return {
            "lock_version": LOCK_VERSION,
            "checked": sorted(self.checked),
            "drift": [
                {
                    "server": d.server,
                    "reason": d.reason.value,
                    "what": d.what,
                    "was": d.was,
                    "now": d.now,
                }
                for d in self.drifts
            ],
            "errors": list(self.errors),
        }
