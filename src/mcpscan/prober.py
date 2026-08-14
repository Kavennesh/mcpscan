"""Driving a live server, and the four questions only a running one can answer.

Everything needed for this existed after step 3 and nothing connected it:
``SandboxHandle.session`` opens a container, ``StdioTransport`` frames JSON-RPC
over it, ``MCPClient.survey`` walks the whole surface, and
``Subject.from_survey`` — written in step 4, never called — feeds that survey to
the same rules ``--path`` runs. This module is the wire between them, plus the
probes that need more than one look at a server to mean anything.

Two design commitments run through it.

**Nothing silently shrinks.** Every cap that bites emits a ``CoverageNote``
naming what was skipped. A scanner that quietly probes nine of forty tools and
prints "no findings" is worse than one that refuses to start, because the second
kind of failure is visible. The budget exists to keep a scan usable in CI, not to
let it under-report without saying so.

**Probing means calling.** The scope-escape probe invokes the target's declared
tools with hostile arguments, which is the only way to learn what they will do.
That is safe because the container has no network, a read-only root, a 64 MB
tmpfs, no capabilities, and a hard wall clock — the sandbox is what makes an
aggressive probe a reasonable thing to do, and it is why there is no flag to run
one outside it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

from mcpscan import anomalies as anomaly_map
from mcpscan.canary import CanarySet, env_for
from mcpscan.client import CLIENT_NAME, HandshakeError, MCPClient, ServerSurvey, tool_fingerprint
from mcpscan.engine import CoverageNote
from mcpscan.models import Finding, Target
from mcpscan.probes import (
    DriftKind,
    ToolDrift,
    env_leak_finding,
    rug_pull_finding,
    scope_escape_finding,
)
from mcpscan.sandbox import Image, Limits, Mount, SandboxError, SandboxHandle, SandboxSession
from mcpscan.transport import StdioTransport, TransportClosed, TransportTimeout

#: Identities to present when looking for client-conditional behaviour. Real
#: names, because a server that discriminates does so against the clients it
#: expects to meet -- a made-up name would be treated as an unknown client and
#: tell us nothing. The scan is already gated behind `ensure_consent`.
IMPERSONATED_CLIENTS: Final = ("claude-ai", "cursor-vscode", "Visual Studio Code")

#: Traversal shapes, ordered cheapest-first so a truncated run still covers the
#: obvious ones. Each targets the decoy planted by `canary.py`.
TRAVERSAL_PAYLOADS: Final = (
    "/home/canary/.ssh/id_rsa",
    "../../../../home/canary/.ssh/id_rsa",
    "~/.ssh/id_rsa",
    "/home/canary/.aws/credentials",
    "....//....//....//....//home/canary/.ssh/id_rsa",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fhome%2fcanary%2f.ssh%2fid_rsa",
    "/proc/self/environ",
    "file:///home/canary/.ssh/id_rsa",
    "..\\..\\..\\..\\home\\canary\\.ssh\\id_rsa",
    "/home/canary/.env",
    "../../../../home/canary/.config/gh/hosts.yml",
    "\\\\?\\/home/canary/.ssh/id_rsa",
)

#: How long to wait before the delay condition re-lists.
DRIFT_DELAY_S: Final = 1.0

#: Where a local project is mounted. The runner image already sets
#: ``WORKDIR /target``, so a relative command resolves without rewriting.
WORKSPACE: Final = PurePosixPath("/target")


def localise(
    command: Sequence[str], workspace: Path | None = None
) -> tuple[list[str], Mount | None]:
    """Rewrite a command that names local files so it resolves inside the container.

    ``mcpscan scan --stdio "node ./server.js"`` is the obvious thing to type and
    cannot work unmodified: the container has its own filesystem and has never
    heard of the caller's directory. So when a token names a file that exists
    under the workspace, the workspace is mounted read-only at ``/target`` and
    the token is rewritten to point there.

    Read-only, because a scanner that let a target write to the source tree it
    was scanning would be a worse problem than the one it was looking for.
    Returns the command unchanged and no mount when nothing is local -- an
    installed binary or a package already inside the image needs neither.
    """
    root = (workspace or Path.cwd()).resolve()
    rewritten: list[str] = []
    needed = False

    for token in command:
        candidate = Path(token)
        try:
            resolved = candidate.resolve()
        except OSError:
            rewritten.append(token)
            continue
        if not resolved.exists():
            rewritten.append(token)
            continue
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            # Outside the workspace. Mounting an arbitrary ancestor would hand a
            # target more of the filesystem than the user asked to scan.
            rewritten.append(token)
            continue
        rewritten.append(str(WORKSPACE / relative))
        needed = True

    if not needed:
        return list(command), None
    return rewritten, Mount(source=root, target=WORKSPACE, read_only=True)


@dataclass(frozen=True, slots=True)
class ProbeBudget:
    """What a scan may spend.

    Allowances are **per probe**, not a shared pool. A single pool looks tidier
    and is wrong: the rug-pull probe launches a container per condition, so it
    drains a shared budget before the scope-escape and env-leak probes get a
    turn, and the scan reports "no findings" for two probes that never ran. The
    wall clock is the only global cap, and it is a backstop rather than an
    allocator.
    """

    #: Re-list conditions. Three fixed, plus one container per client identity.
    rug_pull_clients: int = 1
    payloads_per_tool: int = 4
    max_tool_calls: int = 40
    wall_clock_s: float = 90.0
    #: Per-container budget, handed to `Limits`.
    session_wall_clock_s: float = 30.0

    @property
    def rug_pull_conditions(self) -> int:
        return 3 + self.rug_pull_clients

    @classmethod
    def deep(cls) -> ProbeBudget:
        return cls(
            rug_pull_clients=len(IMPERSONATED_CLIENTS),
            payloads_per_tool=len(TRAVERSAL_PAYLOADS),
            max_tool_calls=200,
            wall_clock_s=600.0,
            session_wall_clock_s=60.0,
        )


@dataclass(slots=True)
class ProbeOutcome:
    """Everything one target's probing produced."""

    survey: ServerSurvey | None = None
    findings: list[Finding] = field(default_factory=list)
    notes: list[CoverageNote] = field(default_factory=list)
    ran: list[str] = field(default_factory=list)
    #: True when the handshake never completed, so nothing was examined.
    unreachable: bool = False

    def note(self, kind: str, detail: str) -> None:
        self.notes.append(CoverageNote(kind=kind, detail=detail))


class Spend:
    """Tracks the budget and records every cap that bites.

    The wall clock is global; launch allowances are not. See `ProbeBudget`.
    """

    __slots__ = ("_deadline", "budget", "launches", "outcome", "tool_calls")

    def __init__(self, budget: ProbeBudget, outcome: ProbeOutcome) -> None:
        self.budget = budget
        self.outcome = outcome
        self.launches = 0
        self.tool_calls = 0
        self._deadline = time.monotonic() + budget.wall_clock_s

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self._deadline

    def may_launch(self, what: str) -> bool:
        """Whether there is still wall clock left to launch a container."""
        if self.expired:
            self.outcome.note(
                "probe_budget",
                f"{what} skipped: the {self.budget.wall_clock_s:.0f}s probe budget "
                f"was spent after {self.launches} container launch(es). Run with "
                "--deep for a longer one; results are incomplete.",
            )
            return False
        self.launches += 1
        return True

    def may_call(self) -> bool:
        if self.tool_calls >= self.budget.max_tool_calls or self.expired:
            return False
        self.tool_calls += 1
        return True


# --------------------------------------------------------------------------
# connecting
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class Connector:
    """How to open a session on a target: canaries, budget, and any extra mounts.

    Carried as one object rather than threaded as four parameters through every
    probe, and it is the seam a caller uses to mount something the prober has no
    business knowing about -- a fixture tree in the test suite, a fetched package
    in ``fetch.py``.
    """

    canaries: CanarySet
    wall_clock_s: float = 30.0
    extra_mounts: tuple[Mount, ...] = ()
    #: Root a local command is resolved against. Defaults to the caller's cwd.
    workspace: Path | None = None
    #: Extra environment the target needs to run at all -- PYTHONPATH for a
    #: fetched Python package. Merged after the canaries, never over them.
    extra_env: Mapping[str, str] | None = None

    @asynccontextmanager
    async def open(
        self, target: Target, *, client_name: str | None = None
    ) -> AsyncIterator[tuple[SandboxSession, StdioTransport, MCPClient]]:
        """Launch ``target`` in a container and yield a live conversation.

        The ordering is the one step 3's suite pins: build the transport inside
        the session so its reader task has a live pipe, and ``aclose()`` it in a
        ``finally`` *before* the session context exits, so the reader never
        outlives the session it reads from.
        """
        if not target.command:
            raise SandboxError(f"{target.label}: stdio target has no command")

        command, workspace = localise(target.command, self.workspace)
        mounts = (self.canaries.mount(), *self.extra_mounts)
        if workspace is not None:
            mounts = (*mounts, workspace)

        async with SandboxHandle.session(
            command,
            image=Image.RUNNER,
            limits=Limits(wall_clock_s=self.wall_clock_s),
            env=env_for(self.canaries, self.extra_env),
            mounts=mounts,
        ) as session:
            transport = StdioTransport(session)
            try:
                yield session, transport, MCPClient(transport, client_name=client_name)
            finally:
                await transport.aclose()


@dataclass(frozen=True, slots=True)
class Look:
    """One look at a server: the tools it served, and what it said while doing so.

    Only the baseline carries a full ``survey``. A re-list needs ``tools/list``
    and nothing else, and asking for resources and prompts as well costs a
    round trip each -- on a server that answers those methods with silence
    rather than an error, that is the transport's 10s timeout, three times, per
    condition. Surveying what the probe does not compare is how a 6-second check
    becomes a 90-second one.
    """

    tools: list[dict[str, Any]]
    fingerprints: dict[str, str]
    announced: bool
    client_name: str
    survey: ServerSurvey | None = None


async def take_look(
    target: Target,
    connector: Connector,
    *,
    client_name: str | None = None,
    exercise: bool = False,
    reinitialise: bool = False,
    delay_s: float = 0.0,
) -> Look | None:
    """Survey a server once, optionally exercising it first. ``None`` if unreachable.

    ``announced`` records whether the server sent
    ``notifications/tools/list_changed`` before the final listing. That single
    bit is what separates a change from a concealed change, and it is only
    observable by holding the session open across the exercise.
    """
    async with connector.open(target, client_name=client_name) as (_, transport, client):
        try:
            await client.initialize()
        except HandshakeError:
            return None

        if exercise:
            await _exercise(client)
        if reinitialise:
            try:
                await client.initialize()
            except HandshakeError:
                pass
        if delay_s:
            await asyncio.sleep(delay_s)

        # Let a notification emitted during the exercise land before we look.
        await transport.settle(0.2)
        announced = "notifications/tools/list_changed" in transport.notification_methods()

        try:
            tools = await client.list_tools()
        except (TransportTimeout, TransportClosed):
            return None

        return Look(
            tools=tools,
            fingerprints=tool_fingerprint(tools),
            announced=announced,
            client_name=client.client_name,
        )


async def _exercise(client: MCPClient) -> None:
    """Call one tool, so a server keyed on being used has been used.

    Arguments are benign here -- the point is to trip a trust counter, not to
    test the tool. `server_rugpull.py` arms on any `tools/call` at all.
    """
    tools = client.profile and await client.list_tools() or []
    for tool in tools[:1]:
        name = tool.get("name")
        if isinstance(name, str):
            await client.call_tool(name, _benign_arguments(tool), timeout=10.0)


def _benign_arguments(tool: Mapping[str, Any]) -> dict[str, Any]:
    """Plausible values for a tool's required string properties."""
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return {}
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    required = schema.get("required")
    wanted = set(required) if isinstance(required, list) else set(properties)
    return {
        key: "mcpscan"
        for key, spec in properties.items()
        if key in wanted and isinstance(spec, dict) and spec.get("type") == "string"
    }


# --------------------------------------------------------------------------
# MCP-007 -- rug pull
# --------------------------------------------------------------------------
def diff_looks(
    baseline: Look,
    later: Look,
    condition: str,
    *,
    client_targeted: bool = False,
) -> list[ToolDrift]:
    """Classify what changed between two looks. Pure -- CI tests it directly."""
    drifts: list[ToolDrift] = []
    index_of = {
        name: i
        for i, tool in enumerate(later.tools)
        if isinstance(name := tool.get("name"), str)
    }
    described = _descriptions(later.tools)
    was = _descriptions(baseline.tools)

    for name in sorted(set(baseline.fingerprints) | set(later.fingerprints)):
        before = baseline.fingerprints.get(name)
        after = later.fingerprints.get(name)

        if before is not None and after is None:
            kind = DriftKind.VANISHED
        elif before is None and after is not None:
            kind = DriftKind.APPEARED
        elif before == after:
            continue
        elif client_targeted:
            kind = DriftKind.CLIENT_TARGETED
        elif later.announced:
            kind = DriftKind.CHANGED_ANNOUNCED
        else:
            kind = DriftKind.CHANGED_SILENTLY

        drifts.append(
            ToolDrift(
                tool=name,
                kind=kind,
                condition=condition,
                before=was.get(name),
                after=described.get(name),
                index=index_of.get(name),
                client_name=later.client_name if client_targeted else None,
            )
        )
    return drifts


def _descriptions(tools: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for tool in tools:
        name = tool.get("name")
        description = tool.get("description")
        if isinstance(name, str) and isinstance(description, str):
            out[name] = description
    return out


async def probe_rug_pull(
    target: Target,
    baseline: Look,
    *,
    connector: Connector,
    spend: Spend,
    outcome: ProbeOutcome,
) -> None:
    """Re-list under four conditions and diff each against the baseline.

    Each condition gets a fresh container, so the server sees a genuinely new
    client rather than a second look from one it already met.
    """
    conditions: list[tuple[str, dict[str, Any], bool]] = [
        ("after calling a tool", {"exercise": True}, False),
        ("after a second initialize", {"reinitialise": True}, False),
        ("after a delay", {"delay_s": DRIFT_DELAY_S}, False),
    ]
    for name in IMPERSONATED_CLIENTS[: spend.budget.rug_pull_clients]:
        conditions.append((f"under clientInfo.name={name!r}", {"client_name": name}, True))
    if spend.budget.rug_pull_clients < len(IMPERSONATED_CLIENTS):
        skipped = IMPERSONATED_CLIENTS[spend.budget.rug_pull_clients :]
        outcome.note(
            "probe_budget",
            "rug pull did not present "
            + ", ".join(repr(n) for n in skipped)
            + " as client identities. Run with --deep to cover them.",
        )

    for label, kwargs, targeted in conditions:
        if not spend.may_launch(f"rug-pull check {label}"):
            return
        later = await take_look(target, connector, **kwargs)
        if later is None:
            outcome.note("probe_unreachable", f"rug-pull check {label}: server did not respond")
            continue
        for drift in diff_looks(baseline, later, label, client_targeted=targeted):
            outcome.findings.append(rug_pull_finding(drift, subject=target.label))


# --------------------------------------------------------------------------
# MCP-008 -- scope escape
# --------------------------------------------------------------------------
def fillable_arguments(tool: Mapping[str, Any]) -> list[str]:
    """String-typed properties a traversal payload can be put in.

    Read off ``inputSchema`` rather than guessed. A tool with no string property
    is not probed, and says so -- inventing an argument name would produce a
    call the server rejects and an absence of evidence that looks like safety.
    """
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    return [
        key
        for key, spec in properties.items()
        if isinstance(spec, dict) and spec.get("type") == "string"
    ]


async def probe_scope_escape(
    target: Target,
    baseline: Look,
    *,
    connector: Connector,
    spend: Spend,
    outcome: ProbeOutcome,
) -> None:
    """Call every declared tool with traversal payloads and watch for a canary."""
    tools = baseline.tools
    if not tools:
        outcome.note("probe_skipped", "scope escape: the server declares no tools")
        return
    if not spend.may_launch("scope-escape probe"):
        return

    unprobed: list[str] = []
    payloads = TRAVERSAL_PAYLOADS[: spend.budget.payloads_per_tool]

    async with connector.open(target) as (_, transport, client):
        try:
            await client.initialize()
        except HandshakeError:
            outcome.note("probe_unreachable", "scope escape: handshake failed")
            return

        for index, tool in enumerate(tools):
            name = tool.get("name")
            if not isinstance(name, str):
                continue
            arguments = fillable_arguments(tool)
            if not arguments:
                unprobed.append(name)
                continue

            if await _escape_one(
                client, name, index, arguments, payloads,
                connector.canaries, spend, outcome, target,
            ):
                break

        _collect_anomalies(transport, outcome, target)

    if unprobed:
        outcome.note(
            "probe_skipped",
            f"scope escape did not probe {len(unprobed)} tool(s) with no string "
            f"argument to fill: {', '.join(sorted(unprobed))}",
        )


async def _escape_one(
    client: MCPClient,
    name: str,
    index: int,
    arguments: Sequence[str],
    payloads: Sequence[str],
    canaries: CanarySet,
    spend: Spend,
    outcome: ProbeOutcome,
    target: Target,
) -> bool:
    """Probe one tool. Returns True when the call budget ran out."""
    for argument in arguments:
        for payload in payloads:
            if not spend.may_call():
                outcome.note(
                    "probe_budget",
                    f"scope escape stopped after {spend.tool_calls} tool calls; "
                    "remaining tools were not probed. Run with --deep.",
                )
                return True

            result = await client.call_tool(name, {argument: payload}, timeout=10.0)
            hits = canaries.detect(result.text, _render(result.structured))
            if hits:
                outcome.findings.append(
                    scope_escape_finding(
                        name, argument, payload, hits[0], index=index, subject=target.label
                    )
                )
                # One proof per tool is enough; more payloads only repeat it.
                return False
    return False


def _render(value: object) -> str | None:
    if value is None:
        return None
    return repr(value)


# --------------------------------------------------------------------------
# MCP-009 -- environment leakage
# --------------------------------------------------------------------------
async def probe_env_leak(
    target: Target,
    baseline: Look,
    *,
    connector: Connector,
    spend: Spend,
    outcome: ProbeOutcome,
) -> None:
    """Search every surface a server can speak through for an env canary.

    The handshake `instructions` and any resource or prompt content are searched
    too, not just tool output: a value that reaches the model's context has
    leaked regardless of which field carried it.
    """
    if not spend.may_launch("env-leak probe"):
        return

    canaries = connector.canaries
    if baseline.survey is None:
        return
    profile = baseline.survey.profile
    for hit in canaries.detect(profile.instructions):
        outcome.findings.append(
            env_leak_finding(
                "The server's initialize instructions",
                hit,
                pointer="#/instructions",
                excerpt=canaries.redact(profile.instructions or ""),
                subject=target.label,
            )
        )

    async with connector.open(target) as (_, transport, client):
        try:
            await client.initialize()
        except HandshakeError:
            outcome.note("probe_unreachable", "env leak: handshake failed")
            return

        for index, tool in enumerate(baseline.tools):
            name = tool.get("name")
            if not isinstance(name, str) or not spend.may_call():
                continue
            result = await client.call_tool(name, _benign_arguments(tool), timeout=10.0)
            surfaces = [result.text, _render(result.structured), _render(result.protocol_error)]
            for hit in canaries.detect(*surfaces):
                outcome.findings.append(
                    env_leak_finding(
                        f"Tool {name!r}",
                        hit,
                        pointer=f"#/tools/{index}",
                        excerpt=canaries.redact(result.text)[:200],
                        subject=target.label,
                    )
                )

        for resource in baseline.survey.resources if baseline.survey else []:
            uri = resource.get("uri")
            if not isinstance(uri, str) or not spend.may_call():
                continue
            for content in await client.read_resource(uri):
                text = content.get("text")
                if not isinstance(text, str):
                    continue
                for hit in canaries.detect(text):
                    outcome.findings.append(
                        env_leak_finding(
                            f"Resource {uri!r}",
                            hit,
                            excerpt=canaries.redact(text)[:200],
                            subject=target.label,
                        )
                    )

        _collect_anomalies(transport, outcome, target)


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------
def _collect_anomalies(
    transport: StdioTransport, outcome: ProbeOutcome, target: Target
) -> None:
    """Fold a session's protocol anomalies into the outcome, de-duplicated."""
    findings, notes = anomaly_map.to_findings(transport.anomalies.items, subject=target.label)
    seen = {(f.rule_id, f.message) for f in outcome.findings}
    outcome.findings.extend(f for f in findings if (f.rule_id, f.message) not in seen)
    known = {(n.kind, n.detail) for n in outcome.notes}
    outcome.notes.extend(n for n in notes if (n.kind, n.detail) not in known)


async def probe(
    target: Target,
    *,
    canaries: CanarySet,
    budget: ProbeBudget | None = None,
    static_only: bool = False,
    extra_mounts: Sequence[Mount] = (),
    workspace: Path | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> ProbeOutcome:
    """Survey ``target``, then run the probes it can afford.

    The baseline survey is taken first and reused: every probe needs to know what
    the server claims before it can say anything about what it does.
    """
    budget = budget or ProbeBudget()
    outcome = ProbeOutcome()
    spend = Spend(budget, outcome)
    connector = Connector(
        canaries=canaries,
        wall_clock_s=budget.session_wall_clock_s,
        extra_mounts=tuple(extra_mounts),
        workspace=workspace,
        extra_env=extra_env,
    )

    if not spend.may_launch("baseline survey"):
        outcome.unreachable = True
        return outcome

    baseline = await _baseline(target, connector, outcome)
    if baseline is None:
        outcome.unreachable = True
        return outcome

    outcome.survey = baseline.survey

    if static_only:
        outcome.note(
            "probe_skipped",
            "--static-only: the server was surveyed and the metadata rules ran, "
            "but no probe called a tool.",
        )
        return outcome

    for name, runner in (
        ("MCP-007", probe_rug_pull),
        ("MCP-008", probe_scope_escape),
        ("MCP-009", probe_env_leak),
    ):
        try:
            await runner(target, baseline, connector=connector, spend=spend, outcome=outcome)
            outcome.ran.append(name)
        except SandboxError as exc:
            # The sandbox failing at its own job is not a finding about the target.
            outcome.note("probe_error", f"{name} could not run: {exc}")

    return outcome


async def _baseline(
    target: Target, connector: Connector, outcome: ProbeOutcome
) -> Look | None:
    async with connector.open(target) as (_, transport, client):
        try:
            await client.initialize()
            survey = await client.survey()
        except (HandshakeError, TransportTimeout, TransportClosed) as exc:
            outcome.note("probe_unreachable", f"{target.label}: {exc}")
            _collect_anomalies(transport, outcome, target)
            return None

        _collect_anomalies(transport, outcome, target)
        return Look(
            tools=survey.tools,
            fingerprints=tool_fingerprint(survey.tools),
            announced=False,
            client_name=client.client_name or CLIENT_NAME,
            survey=survey,
        )
