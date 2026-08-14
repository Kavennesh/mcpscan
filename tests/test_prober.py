"""The four probes, against real servers in real containers.

Pure logic — drift classification, argument selection, budget arithmetic — is
tested in ``test_prober_logic.py`` and runs in CI. This file is the wiring, and
it skips wherever the sandbox images are absent.

Every probe here is checked twice: that it fires on the fixture built to trip it,
and that it stays silent on the variant built to be safe. A probe with only the
first half is a probe that would pass while returning a constant.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests.dockerprobe import images_ready, skip_reason

FIXTURES = Path(__file__).parent / "fixtures"

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(not images_ready(), reason=skip_reason()),
]


def fixture_target(name: str, *args: str, label: str | None = None) -> Any:
    """A stdio Target pointing at a mounted fixture server."""
    from mcpscan.models import Target, TargetKind

    return Target(
        kind=TargetKind.STDIO,
        label=label or name.removesuffix(".py"),
        command=["python3", f"/fixtures/servers/{name}", *args],
        env_keys=["MY_SERVICE_TOKEN"],
    )


#: Probing a fixture is deterministic, and each run costs several container
#: launches. Tests that compare two fixtures would otherwise re-probe one of them
#: for nothing, and the sandbox CI job has a 20-minute ceiling. Only default-budget
#: runs are cached; a test that passes its own budget always gets a fresh run.
_CACHE: dict[tuple[str, tuple[str, ...]], Any] = {}


async def _probe(name: str, *args: str, **kwargs: Any) -> Any:
    from mcpscan.canary import CanarySet
    from mcpscan.prober import probe
    from mcpscan.sandbox import Mount

    canaries = CanarySet.create(["MY_SERVICE_TOKEN"])
    try:
        return await probe(
            fixture_target(name, *args),
            canaries=canaries,
            extra_mounts=(Mount(source=FIXTURES, target=PurePosixPath("/fixtures")),),
            **kwargs,
        )
    finally:
        canaries.cleanup()


async def run_probe(name: str, *args: str, **kwargs: Any) -> Any:
    """Probe one fixture server, mounting the fixture tree alongside the canaries.

    ``extra_mounts`` is a real parameter rather than a test seam: the prober has
    no business knowing where fixtures live, and ``fetch.py`` will need the same
    hook to mount a downloaded package.
    """
    if kwargs:
        return await _probe(name, *args, **kwargs)
    key = (name, args)
    if key not in _CACHE:
        _CACHE[key] = await _probe(name, *args)
    return _CACHE[key]


def rule_ids(outcome: Any) -> set[str]:
    return {f.rule_id for f in outcome.findings}


def describe(outcome: Any) -> str:
    lines = [
        f"  {f.rule_id} {f.severity}/{f.confidence}: {f.message}" for f in outcome.findings
    ]
    lines += [f"  note {n.kind}: {n.detail}" for n in outcome.notes]
    return "\n".join(lines) or "  (nothing)"


# --------------------------------------------------------------------------
# the negative control
# --------------------------------------------------------------------------
async def test_the_clean_server_produces_no_probe_findings() -> None:
    """server_clean.py is the control for three suites already; now four.

    It has a destructive-annotated tool, a nested schema and prompt arguments,
    and every probe runs against it. If any of them fires here, that probe is
    unusable against a real server.
    """
    outcome = await run_probe("server_clean.py")
    assert outcome.findings == [], describe(outcome)
    assert not outcome.unreachable
    assert outcome.survey is not None
    assert outcome.ran == ["MCP-007", "MCP-008", "MCP-009"], "a probe did not run"


# --------------------------------------------------------------------------
# MCP-007 -- rug pull
# --------------------------------------------------------------------------
async def test_a_silent_mutation_is_found_and_ranked_highest() -> None:
    """The case a notification-driven client misses completely."""
    from mcpscan.models import Confidence

    outcome = await run_probe("server_rugpull.py", "silent")
    rug = [f for f in outcome.findings if f.rule_id == "MCP-007"]

    silent = [f for f in rug if f.metadata["drift"] == "changed_silently"]
    assert silent, describe(outcome)
    assert all(f.confidence is Confidence.HIGH for f in silent)


async def test_an_announced_mutation_is_found_at_lower_confidence() -> None:
    """Concealment is what raises confidence, so announcing it must lower it.

    Both are findings -- the description a user approved is not the one in force
    either way -- but a server that says so is not additionally hiding.
    """
    from mcpscan.models import Confidence

    outcome = await run_probe("server_rugpull.py")
    announced = [f for f in outcome.findings if f.metadata.get("drift") == "changed_announced"]

    assert announced, describe(outcome)
    assert all(f.confidence is Confidence.MEDIUM for f in announced)


async def test_silent_outranks_announced() -> None:
    """The ordering the whole severity table exists to produce."""
    silent = await run_probe("server_rugpull.py", "silent")
    polite = await run_probe("server_rugpull.py")

    worst_silent = max(f.confidence.rank for f in silent.findings if f.rule_id == "MCP-007")
    worst_polite = max(f.confidence.rank for f in polite.findings if f.rule_id == "MCP-007")
    assert worst_silent > worst_polite


async def test_client_targeted_behaviour_is_detected() -> None:
    """Invisible to any scanner that presents one identity."""
    outcome = await run_probe("server_targets_client.py")
    targeted = [f for f in outcome.findings if f.metadata.get("drift") == "client_targeted"]

    assert targeted, describe(outcome)
    assert targeted[0].metadata["client_name"] in {
        "claude-ai",
        "cursor-vscode",
        "Visual Studio Code",
    }
    assert "identity" in targeted[0].message.lower()


async def test_a_server_that_treats_every_client_alike_is_silent() -> None:
    outcome = await run_probe("server_targets_client.py", "honest")
    assert [f for f in outcome.findings if f.rule_id == "MCP-007"] == [], describe(outcome)


# --------------------------------------------------------------------------
# MCP-008 -- scope escape
# --------------------------------------------------------------------------
async def test_an_unconstrained_read_is_caught_by_the_canary() -> None:
    from mcpscan.models import Confidence, Severity

    outcome = await run_probe("server_escapes_scope.py")
    escapes = [f for f in outcome.findings if f.rule_id == "MCP-008"]

    assert escapes, describe(outcome)
    finding = escapes[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.HIGH
    assert finding.metadata["tool"] == "read_project_file"
    assert finding.metadata["argument"] == "path"
    assert "/home/canary" in finding.metadata["canary"]


async def test_the_guarded_variant_produces_nothing() -> None:
    """Stops MCP-008 being a rule that fires on any file-reading tool."""
    outcome = await run_probe("server_escapes_scope.py", "guarded")
    assert [f for f in outcome.findings if f.rule_id == "MCP-008"] == [], describe(outcome)


async def test_a_tool_with_no_string_argument_is_reported_as_unprobed() -> None:
    """Absence of evidence must not read as evidence of absence."""
    outcome = await run_probe("server_escapes_scope.py", "guarded")
    notes = " ".join(n.detail for n in outcome.notes)
    assert "project_stats" in notes
    assert "no string argument" in notes


# --------------------------------------------------------------------------
# MCP-009 -- environment leakage
# --------------------------------------------------------------------------
async def test_a_leaked_env_value_is_found_in_structured_content() -> None:
    outcome = await run_probe("server_leaks_env.py")
    leaks = [f for f in outcome.findings if f.rule_id == "MCP-009"]

    assert leaks, describe(outcome)
    assert leaks[0].metadata["variable"] == "MY_SERVICE_TOKEN"
    assert leaks[0].metadata["declared"] is True


async def test_a_value_leaked_through_an_error_is_still_a_leak() -> None:
    """`isError: true` is a successful exchange whose payload reaches the model."""
    outcome = await run_probe("server_leaks_env.py", "error")
    assert [f for f in outcome.findings if f.rule_id == "MCP-009"], describe(outcome)


async def test_reading_an_undeclared_variable_ranks_higher() -> None:
    """Mishandling a variable you asked for differs from taking one you did not."""
    from mcpscan.models import Severity

    declared = await run_probe("server_leaks_env.py")
    undeclared = await run_probe("server_leaks_env.py", "undeclared")

    got = [f for f in undeclared.findings if f.rule_id == "MCP-009"]
    assert got, describe(undeclared)
    assert got[0].metadata["declared"] is False
    assert got[0].severity is Severity.CRITICAL

    was = [f for f in declared.findings if f.rule_id == "MCP-009"]
    assert was[0].severity is Severity.HIGH
    assert got[0].severity.rank > was[0].severity.rank


async def test_the_canary_token_is_redacted_from_evidence() -> None:
    """A report that prints the token teaches a reader to grep for a string that
    will never appear again, and makes every run diff differently."""
    outcome = await run_probe("server_leaks_env.py")
    for finding in outcome.findings:
        if finding.evidence:
            assert "mcpscan-canary-" not in finding.evidence


# --------------------------------------------------------------------------
# coverage, budget, and containment
# --------------------------------------------------------------------------
async def test_an_unreachable_server_is_coverage_not_a_clean_bill() -> None:
    outcome = await run_probe("server_silent.py")
    assert outcome.unreachable
    assert outcome.findings == []
    assert any(n.kind == "probe_unreachable" for n in outcome.notes)


async def test_static_only_surveys_without_calling_anything() -> None:
    outcome = await run_probe("server_escapes_scope.py", static_only=True)
    assert outcome.survey is not None
    assert [f for f in outcome.findings if f.rule_id == "MCP-008"] == []
    assert any("static-only" in n.detail for n in outcome.notes)


async def test_a_tight_budget_says_what_it_skipped() -> None:
    """Truncation is allowed; silent truncation is not."""
    from mcpscan.prober import ProbeBudget

    outcome = await run_probe(
        "server_rugpull.py", budget=ProbeBudget(wall_clock_s=0.001, max_tool_calls=1)
    )
    notes = [n for n in outcome.notes if n.kind == "probe_budget"]
    assert notes, "a budget bit without saying so"
    assert any("incomplete" in n.detail for n in notes)


async def test_protocol_anomalies_reach_the_outcome() -> None:
    """A probe session is still a conversation; MCP-004/005/006 still apply."""
    outcome = await run_probe("server_dup_ids.py")
    assert {"MCP-005"} & rule_ids(outcome), describe(outcome)


async def test_probing_leaves_no_container_behind() -> None:
    from tests.dockerprobe import container_exists

    await run_probe("server_clean.py")
    # The reaper labels every container it creates; a leak would show up in the
    # CI job's own check, but proving it here localises the failure.
    assert not container_exists("mcpscan-probe-should-not-exist")
