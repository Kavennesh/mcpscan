"""Planted secrets that prove a target read something it should not have.

Detection here is an exact substring match for a token generated moments earlier,
which makes a false positive impossible by construction rather than by tuning: a
response containing this string can only have come from reading the file or the
variable we planted it in. That is a rarer property than it sounds, and it is why
the two probes built on this module can report at HIGH confidence without a
corpus of benign examples behind them.

Two kinds of bait:

**Decoy files** are written to a host temp directory and bind-mounted read-only at
``/home/canary``. The runner image has no such directory -- ``useradd`` there uses
``--no-create-home --home-dir /tmp``, so ``/home`` does not exist -- and baking one
into the image would mean a fixed token shipped in a public artefact plus a change
to an ask-gated Dockerfile. Mounting a fresh tree per scan avoids both.

**Environment canaries** turn ``Target.env_keys`` into values. CLAUDE.md's third
constraint has said since step 1 that "values are replaced with generated canaries
at launch"; ``Target`` has always carried names only and ``SandboxHandle`` has
always accepted an ``env`` mapping, but nothing ever generated the values in
between. This is that missing half.

On randomness: a hostile server that actually reads the file learns the token
either way, so a fresh token buys nothing against *that* server. What it buys is
everything else -- a fixed token could be published, recognised and redacted by a
server that never reads the file at all, and a token that appears in a report can
never be confused with one from an earlier scan.
"""

from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final

from mcpscan.sandbox import Mount

#: Where the decoy tree is mounted inside the container.
CANARY_HOME: Final = PurePosixPath("/home/canary")

#: Recognisable enough to be searched for, unique enough that nothing else
#: produces it. The prefix is deliberate: a token that turns up in a bug report
#: should be identifiable as ours rather than mistaken for a real credential.
TOKEN_PREFIX: Final = "mcpscan-canary"  # noqa: S105 - a marker, and never a real secret

#: Decoy files, relative to CANARY_HOME. These are the paths a tool-poisoning
#: description actually names -- see the MCP-002 exfiltration patterns and the
#: payload in tests/fixtures/servers/server_rugpull.py, which asks for
#: ~/.ssh/id_rsa by name.
DECOY_FILES: Final = (
    PurePosixPath(".ssh/id_rsa"),
    PurePosixPath(".aws/credentials"),
    PurePosixPath(".env"),
    PurePosixPath(".config/gh/hosts.yml"),
)

#: Well-known credential variables. Injected *in addition* to whatever the target
#: declared, because a server that reads `AWS_SECRET_ACCESS_KEY` without ever
#: declaring it is the interesting case -- a declared variable it reads is the
#: variable doing its job.
COMMON_ENV_KEYS: Final = (
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SLACK_TOKEN",
)


class Origin(StrEnum):
    """Where a leaked token was planted. Named in the finding."""

    FILE = "file"
    ENV = "env"


@dataclass(frozen=True, slots=True)
class CanaryHit:
    """One planted secret found somewhere it should not be."""

    origin: Origin
    #: The container path for a file, the variable name for an env canary.
    name: str
    token: str
    #: Whether the target declared this variable. False means it read something
    #: it never asked for, which is worse.
    declared: bool = True

    def describe(self) -> str:
        if self.origin is Origin.FILE:
            return f"the contents of {self.name}"
        undeclared = "" if self.declared else ", which it never declared"
        return f"the value of ${self.name}{undeclared}"


def _token() -> str:
    """A fresh token. 32 hex characters is far past any accidental collision."""
    return f"{TOKEN_PREFIX}-{secrets.token_hex(16)}"


@dataclass(frozen=True, slots=True)
class CanarySet:
    """Every secret planted for one scan, and the means to spot one coming back."""

    root: Path
    env: dict[str, str] = field(default_factory=dict)
    files: dict[PurePosixPath, str] = field(default_factory=dict)
    #: Variables the target declared, as opposed to the ones we volunteered.
    declared: frozenset[str] = frozenset()

    @classmethod
    def create(
        cls,
        env_keys: Iterable[str] = (),
        *,
        include_common: bool = True,
        root: Path | None = None,
    ) -> CanarySet:
        """Plant a fresh set. ``root`` is created if not supplied."""
        base = root if root is not None else Path(tempfile.mkdtemp(prefix="mcpscan-canary-"))

        declared = {key for key in env_keys if key}
        names = set(declared)
        if include_common:
            names |= set(COMMON_ENV_KEYS)

        env = {name: _token() for name in sorted(names)}

        files: dict[PurePosixPath, str] = {}
        for relative in DECOY_FILES:
            token = _token()
            files[CANARY_HOME / relative] = token
            destination = base / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(_decoy_body(relative, token), encoding="utf-8")
            # World-readable on purpose, and load-bearing. The container runs as
            # uid 65532 with no relationship to the host user, and the mount is
            # read-only, so "permissive" here means "readable by the process we
            # are trying to catch reading it". noqa: the alternative is a decoy
            # nothing can open, which fails as a silent false negative.
            destination.chmod(0o644)  # noqa: S103
        _chmod_tree(base)

        return cls(root=base, env=env, files=files, declared=frozenset(declared))

    def mount(self) -> Mount:
        """The read-only bind mount that puts the decoys at ``/home/canary``."""
        return Mount(source=self.root, target=CANARY_HOME, read_only=True)

    def tokens(self) -> dict[str, CanaryHit]:
        """Every token, mapped to what finding it would produce."""
        planted: dict[str, CanaryHit] = {}
        for path, token in self.files.items():
            planted[token] = CanaryHit(origin=Origin.FILE, name=str(path), token=token)
        for name, token in self.env.items():
            planted[token] = CanaryHit(
                origin=Origin.ENV,
                name=name,
                token=token,
                declared=name in self.declared,
            )
        return planted

    def detect(self, *texts: str | None) -> list[CanaryHit]:
        """Every planted secret present in ``texts``, in a stable order.

        Substring, not regex: the token is a literal we generated, and a pattern
        would only introduce a way to be wrong.
        """
        planted = self.tokens()
        found: list[CanaryHit] = []
        seen: set[str] = set()
        for text in texts:
            if not text:
                continue
            for token, hit in planted.items():
                if token in text and token not in seen:
                    seen.add(token)
                    found.append(hit)
        found.sort(key=lambda hit: (hit.origin.value, hit.name))
        return found

    def redact(self, text: str) -> str:
        """Replace tokens with a placeholder before a finding quotes the text.

        A report that prints the token teaches the next reader to search for a
        string that will never appear again, and clutters a diff with noise that
        changes every run.
        """
        for token, hit in self.tokens().items():
            text = text.replace(token, f"<{hit.origin.value} canary {hit.name}>")
        return text

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def _decoy_body(relative: PurePosixPath, token: str) -> str:
    """Content shaped like the real thing, so a naive reader takes the bait."""
    name = relative.name
    if name == "id_rsa":
        return (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{token}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
    if name == "credentials":
        return (
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            f"aws_secret_access_key = {token}\n"
        )
    if name == "hosts.yml":
        return f"github.com:\n    oauth_token: {token}\n    user: mcpscan\n"
    return f"API_KEY={token}\n"


def _chmod_tree(root: Path) -> None:
    """Make every directory traversable by the container's unprivileged uid.

    ``mkdtemp`` creates 0o700, which uid 65532 cannot enter. Skipping this does
    not raise anywhere -- the mount simply appears empty to the target, the
    scope-escape probe never fires, and the scan reports a clean bill of health
    for a check that never ran. Permissive by necessity, on a directory holding
    nothing but fake secrets we generated seconds ago.
    """
    os.chmod(root, 0o755)  # noqa: S103
    for path in root.rglob("*"):
        if path.is_dir():
            os.chmod(path, 0o755)  # noqa: S103


def env_for(canaries: CanarySet, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """The env mapping to hand :meth:`SandboxHandle.session`.

    Only ever KEY=VALUE pairs we generated. A real credential cannot reach here:
    ``Target`` carries variable *names* and has a test proving values are dropped
    at config-import time.
    """
    merged = dict(canaries.env)
    if extra:
        merged.update(extra)
    return merged
