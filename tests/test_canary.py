"""Planted secrets, and the property that makes the probes built on them credible.

MCP-008 and MCP-009 report at HIGH confidence without a corpus of benign examples
behind them, which every other rule in this project needs. They get away with it
because of one property asserted here: the token is a 32-hex string generated
seconds earlier and written to exactly one place, so a response containing it can
only have come from reading that place. There is no threshold to tune and no
phrasing to argue about.

That makes the false-positive tests below unusually cheap and unusually important:
cheap because any text that is not the token must be silent, important because if
that ever stops holding, two probes lose their justification at once.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from mcpscan.canary import (
    CANARY_HOME,
    COMMON_ENV_KEYS,
    DECOY_FILES,
    TOKEN_PREFIX,
    CanarySet,
    Origin,
    env_for,
)


@pytest.fixture
def canaries(tmp_path: Path) -> CanarySet:
    return CanarySet.create(["MY_SERVICE_TOKEN"], root=tmp_path / "canary")


# --------------------------------------------------------------------------
# planting
# --------------------------------------------------------------------------
def test_every_decoy_file_is_written(canaries: CanarySet) -> None:
    for relative in DECOY_FILES:
        assert (canaries.root / relative).is_file()
        assert CANARY_HOME / relative in canaries.files


def test_each_decoy_gets_a_distinct_token(canaries: CanarySet) -> None:
    """A shared token would tell you something leaked but not what."""
    tokens = list(canaries.files.values()) + list(canaries.env.values())
    assert len(tokens) == len(set(tokens))


def test_tokens_are_fresh_between_scans(tmp_path: Path) -> None:
    """A fixed token could be published, recognised and redacted by a server
    that never reads the file at all."""
    first = CanarySet.create(root=tmp_path / "a")
    second = CanarySet.create(root=tmp_path / "b")
    assert set(first.files.values()).isdisjoint(second.files.values())
    assert set(first.env.values()).isdisjoint(second.env.values())


def test_tokens_carry_an_identifying_prefix(canaries: CanarySet) -> None:
    """A token in a bug report should read as ours, not as a real credential."""
    for token in canaries.files.values():
        assert token.startswith(TOKEN_PREFIX)


def test_decoy_bodies_look_like_the_real_thing(canaries: CanarySet) -> None:
    """Bait a naive reader takes. A file containing only a token is not bait."""
    key = (canaries.root / ".ssh/id_rsa").read_text()
    assert key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    creds = (canaries.root / ".aws/credentials").read_text()
    assert "[default]" in creds and "aws_secret_access_key" in creds


# --------------------------------------------------------------------------
# the mount has to actually be readable by the container
# --------------------------------------------------------------------------
def test_the_tree_is_readable_by_an_unrelated_uid(canaries: CanarySet) -> None:
    """The container runs as uid 65532 with no relationship to the host user.

    `mkdtemp` creates 0o700. Skipping the chmod raises nowhere -- the mount just
    looks empty to the target, the scope-escape probe never fires, and the scan
    reports clean for a check that never ran. This is that silent failure, caught.
    """
    assert stat.S_IMODE(os.stat(canaries.root).st_mode) & 0o005, "root not traversable"
    for relative in DECOY_FILES:
        path = canaries.root / relative
        assert stat.S_IMODE(os.stat(path).st_mode) & 0o004, f"{relative} not world-readable"
        for parent in path.relative_to(canaries.root).parents:
            if str(parent) == ".":
                continue
            mode = stat.S_IMODE(os.stat(canaries.root / parent).st_mode)
            assert mode & 0o005, f"{parent} not traversable"


def test_the_mount_is_read_only_and_lands_at_the_canary_home(canaries: CanarySet) -> None:
    mount = canaries.mount()
    assert mount.target == CANARY_HOME
    assert mount.read_only
    spec = mount.to_spec()
    assert ",ro," in spec
    assert "bind-recursive=readonly" in spec


# --------------------------------------------------------------------------
# environment canaries
# --------------------------------------------------------------------------
def test_declared_variables_get_canary_values(canaries: CanarySet) -> None:
    """CLAUDE.md constraint 3, finally implemented rather than merely claimed."""
    assert "MY_SERVICE_TOKEN" in canaries.env
    assert canaries.env["MY_SERVICE_TOKEN"].startswith(TOKEN_PREFIX)
    assert "MY_SERVICE_TOKEN" in canaries.declared


def test_common_credential_names_are_volunteered_too(canaries: CanarySet) -> None:
    """A server reading AWS_SECRET_ACCESS_KEY it never declared is the finding.

    One it declared and reads is that variable doing its job.
    """
    for name in COMMON_ENV_KEYS:
        assert name in canaries.env
        assert name not in canaries.declared


def test_volunteering_can_be_turned_off(tmp_path: Path) -> None:
    lean = CanarySet.create(["ONLY_THIS"], include_common=False, root=tmp_path / "lean")
    assert set(lean.env) == {"ONLY_THIS"}


def test_env_for_returns_only_generated_values(canaries: CanarySet) -> None:
    """A real credential cannot reach the sandbox through this path."""
    env = env_for(canaries)
    assert set(env) == set(canaries.env)
    for value in env.values():
        assert value.startswith(TOKEN_PREFIX)


# --------------------------------------------------------------------------
# detection -- the property the probes rest on
# --------------------------------------------------------------------------
def test_a_leaked_file_token_is_detected_and_named(canaries: CanarySet) -> None:
    token = canaries.files[CANARY_HOME / ".ssh/id_rsa"]
    hits = canaries.detect(f"the file said: {token}")
    assert len(hits) == 1
    assert hits[0].origin is Origin.FILE
    assert hits[0].name == "/home/canary/.ssh/id_rsa"
    assert "id_rsa" in hits[0].describe()


def test_a_leaked_env_token_says_whether_it_was_declared(canaries: CanarySet) -> None:
    declared = canaries.detect(canaries.env["MY_SERVICE_TOKEN"])[0]
    volunteered = canaries.detect(canaries.env["AWS_SECRET_ACCESS_KEY"])[0]

    assert declared.declared
    assert not volunteered.declared
    assert "never declared" in volunteered.describe()
    assert "never declared" not in declared.describe()


def test_detection_searches_every_surface_it_is_given(canaries: CanarySet) -> None:
    """Tool text, structured content, an error message -- all are channels."""
    token = canaries.env["GITHUB_TOKEN"]
    assert canaries.detect(None, "", "clean", f"failed: {token}")


def test_two_leaks_are_two_hits(canaries: CanarySet) -> None:
    hits = canaries.detect(
        canaries.files[CANARY_HOME / ".env"] + " and " + canaries.env["OPENAI_API_KEY"]
    )
    assert {h.origin for h in hits} == {Origin.FILE, Origin.ENV}


def test_the_same_token_twice_is_one_hit(canaries: CanarySet) -> None:
    token = canaries.env["GITHUB_TOKEN"]
    assert len(canaries.detect(token, token, f"{token} {token}")) == 1


@pytest.mark.parametrize(
    "text",
    [
        "",
        "Reads a file and returns its contents.",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnot the real one\n",
        "mcpscan-canary",
        "mcpscan-canary-deadbeef",
        "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key = something else entirely",
    ],
)
def test_nothing_else_is_ever_a_hit(canaries: CanarySet, text: str) -> None:
    """The property MCP-008 and MCP-009 stake HIGH confidence on.

    Note the two near-misses: the bare prefix, and the prefix with a plausible
    but wrong suffix. A substring search for the prefix alone would fire on both.
    """
    assert canaries.detect(text) == []


def test_a_token_from_a_different_scan_is_not_a_hit(tmp_path: Path) -> None:
    """Otherwise a stale report could be replayed into a passing scan."""
    first = CanarySet.create(root=tmp_path / "a")
    second = CanarySet.create(root=tmp_path / "b")
    stale = first.files[CANARY_HOME / ".ssh/id_rsa"]
    assert second.detect(f"leaked {stale}") == []


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------
def test_evidence_is_redacted_before_a_finding_quotes_it(canaries: CanarySet) -> None:
    """Printing the token teaches a reader to grep for a string that will never
    appear again, and makes every report diff differently."""
    token = canaries.files[CANARY_HOME / ".ssh/id_rsa"]
    redacted = canaries.redact(f"here you go: {token}, enjoy")

    assert token not in redacted
    assert "<file canary /home/canary/.ssh/id_rsa>" in redacted
    assert "here you go:" in redacted and "enjoy" in redacted


def test_hits_are_ordered_stably(canaries: CanarySet) -> None:
    blob = " ".join(canaries.files.values()) + " " + " ".join(canaries.env.values())
    assert [h.name for h in canaries.detect(blob)] == [h.name for h in canaries.detect(blob)]


def test_cleanup_removes_the_tree(tmp_path: Path) -> None:
    canaries = CanarySet.create(root=tmp_path / "gone")
    assert canaries.root.exists()
    canaries.cleanup()
    assert not canaries.root.exists()


def test_cleanup_is_idempotent(canaries: CanarySet) -> None:
    canaries.cleanup()
    canaries.cleanup()


def test_decoy_paths_are_the_ones_attackers_actually_name() -> None:
    """MCP-002's exfiltration patterns and server_rugpull.py both name ~/.ssh/id_rsa.

    Bait nobody asks for catches nobody.
    """
    named = {str(p) for p in DECOY_FILES}
    assert ".ssh/id_rsa" in named
    assert ".aws/credentials" in named
    assert ".env" in named
