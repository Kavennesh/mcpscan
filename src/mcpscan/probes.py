"""What the dynamic probes report, and how heavily.

Three rule ids, held here as :class:`RuleMeta` constants exactly the way
``anomalies.py`` holds MCP-004/005/006 — outside ``RuleSet``, because these are
not rules the engine evaluates over a document. They are conclusions drawn from
having *run* the server, and nothing static can reach them.

The severity table is the interesting part, and one idea drives it:
**concealment raises confidence**. A server that changes its tool list and
announces the change with ``notifications/tools/list_changed`` is doing something
the protocol has a word for; a client that re-lists on the notification sees the
new description and can act on it. A server that changes the same list and says
nothing is relying on the client not to look. The second is not a worse *change*,
it is a change plus an attempt to hide it, and that attempt is evidence in a way
the mutation alone is not.

MCP-008 and MCP-009 report at HIGH confidence without the benign corpora that
gate every pattern rule, which needs justifying. They are allowed to because
detection is an exact match on a token generated seconds earlier and written to
exactly one place — see ``canary.py``. There is no threshold and no phrasing to
argue about, so there is nothing for a corpus to calibrate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from mcpscan.canary import CanaryHit, Origin
from mcpscan.document import pointer
from mcpscan.engine import RuleMeta
from mcpscan.models import Confidence, Finding, Location, Severity

RUG_PULL = RuleMeta(
    id="MCP-007",
    title="Tool definition changed after inspection",
    severity=Severity.HIGH,
    description=(
        "A server whose tool list is not the same on the second look as it was "
        "on the first. mcpscan hashes every tool by the fields that steer a "
        "model -- title, description, schemas, annotations -- then re-lists "
        "under several conditions and diffs: after a tool has been called, "
        "after time has passed, and while presenting a different client "
        "identity. Concealment raises confidence, because a server that mutates "
        "silently is doing something a server that announces a change is not."
    ),
    remediation=(
        "Pin the server to a known version and check it with `mcpscan verify` on "
        "every build. A tool list that changes after approval means the "
        "description a user reviewed is not the description the model is acting "
        "on, and nothing in the protocol requires a server to announce that."
    ),
)

SCOPE_ESCAPE = RuleMeta(
    id="MCP-008",
    title="Tool read outside its declared scope",
    severity=Severity.CRITICAL,
    description=(
        "A tool called with a traversal argument that returned the contents of "
        "a decoy file planted outside the directory it is documented to serve. "
        "Detection is an exact match on a token generated seconds earlier and "
        "written nowhere the tool was entitled to read, so there is no benign "
        "explanation for it appearing in the response and no corpus of false "
        "positives behind the rule."
    ),
    remediation=(
        "Resolve and constrain every caller-supplied path before opening it: "
        "reject traversal, resolve symlinks, and check the result is still inside "
        "the directory the tool is documented to serve. The model chooses these "
        "arguments and is reading descriptions written by the same server."
    ),
)

ENV_LEAK = RuleMeta(
    id="MCP-009",
    title="Environment secret disclosed in a server response",
    severity=Severity.HIGH,
    description=(
        "A value from the server's environment coming back in a tool result, a "
        "resource, a prompt or an error message. Every environment value is a "
        "canary generated for this scan and injected only into the target's "
        "process, so a match cannot have arrived any other way. Severity rises "
        "when the variable was never declared: echoing a variable the server "
        "asked for is careless, echoing one it never mentioned means it went "
        "looking."
    ),
    remediation=(
        "Never echo environment variables into tool output, structured content or "
        "error messages. A value that reaches a response reaches the model's "
        "context, the transcript, and whatever logs that transcript."
    ),
)


def rule_metas() -> list[RuleMeta]:
    """Every probe rule. Used by the docs check and, at step 7, by SARIF."""
    return [RUG_PULL, SCOPE_ESCAPE, ENV_LEAK]


# --------------------------------------------------------------------------
# MCP-007
# --------------------------------------------------------------------------
class DriftKind(StrEnum):
    """What changed about a tool between two listings of the same server."""

    #: Definition changed with no `notifications/tools/list_changed` first.
    CHANGED_SILENTLY = "changed_silently"
    #: Definition changed, and the server announced it.
    CHANGED_ANNOUNCED = "changed_announced"
    #: The server serves a different definition to a different client identity.
    CLIENT_TARGETED = "client_targeted"
    #: A tool that was not in the first listing.
    APPEARED = "appeared"
    #: A tool that was in the first listing and is not in the second.
    VANISHED = "vanished"


@dataclass(frozen=True, slots=True)
class _Rank:
    severity: Severity
    confidence: Confidence
    summary: str


#: Concealment raises confidence. See the module docstring.
DRIFT_RANKS: Final[dict[DriftKind, _Rank]] = {
    DriftKind.CHANGED_SILENTLY: _Rank(
        Severity.HIGH,
        Confidence.HIGH,
        "changed its definition without sending notifications/tools/list_changed. "
        "A client that re-lists only when told to would still be acting on the "
        "definition it approved.",
    ),
    DriftKind.CHANGED_ANNOUNCED: _Rank(
        Severity.HIGH,
        Confidence.MEDIUM,
        "changed its definition after the server was exercised. The change was "
        "announced, so a client that re-lists on notification would see it -- but "
        "the description a user approved is no longer the one in force.",
    ),
    DriftKind.CLIENT_TARGETED: _Rank(
        Severity.HIGH,
        Confidence.HIGH,
        "is served differently depending on the client identity presented. "
        "Behaviour conditioned on who is asking is behaviour designed not to be "
        "seen by whoever is reviewing.",
    ),
    DriftKind.APPEARED: _Rank(
        Severity.HIGH,
        Confidence.HIGH,
        "appeared after the server was exercised and was absent from the first "
        "listing. A tool that materialises after approval was never approved.",
    ),
    DriftKind.VANISHED: _Rank(
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "was in the first listing and absent from the second. Less pointed than a "
        "tool appearing, but the surface is not what it was reported to be.",
    ),
}


@dataclass(frozen=True, slots=True)
class ToolDrift:
    """One tool that differs between two listings."""

    tool: str
    kind: DriftKind
    #: Which probe condition surfaced it, e.g. "after calling a tool".
    condition: str
    #: The value of the field this drift is *about*, before and after. Which
    #: field that is depends on `fields`; the location says so out loud.
    before: str | None = None
    after: str | None = None
    #: Index in the **baseline** listing -- the one the report's survey artefact
    #: is written from. `None` for a tool that only exists in the later listing,
    #: which is nowhere in the baseline to point at. Not the later index: a
    #: server free to reorder its tools is exactly the server this rule is for.
    baseline_index: int | None = None
    #: The identity presented, when this was a client-targeted difference.
    client_name: str | None = None
    #: Which of `client.SALIENT_KEYS` differ. Empty for a tool that appeared or
    #: vanished, where the whole definition is the change.
    fields: tuple[str, ...] = ()


def _drift_location(drift: ToolDrift) -> Location:
    """The most specific place in the baseline that this drift is about.

    A rug pull is a change to a *field*, and the drift knows which one whenever
    exactly one changed -- so the finding says `#/tools/3/description` rather
    than `#/tools/3`, and a report can underline the text that is no longer in
    force instead of the brace above it. Two fields changing at once has no
    single location, and the tool object is then the honest answer; `fields`
    still names them.
    """
    if drift.baseline_index is None:
        return Location(pointer=f"#/_probe/rug-pull/{drift.tool}")
    if len(drift.fields) == 1:
        return Location(pointer=pointer("tools", drift.baseline_index, drift.fields[0]))
    return Location(pointer=pointer("tools", drift.baseline_index))


def rug_pull_finding(drift: ToolDrift, *, subject: str = "") -> Finding:
    rank = DRIFT_RANKS[drift.kind]
    where = _drift_location(drift)

    detail = f"Tool {drift.tool!r} {rank.summary}"
    if drift.fields:
        detail += f" Changed: {', '.join(drift.fields)}."
    if drift.client_name:
        detail += f" Identity presented: {drift.client_name!r}."

    metadata: dict[str, Any] = {
        "probe": "rug_pull",
        "drift": drift.kind.value,
        "tool": drift.tool,
        "condition": drift.condition,
    }
    if drift.fields:
        metadata["fields"] = list(drift.fields)
    if drift.client_name:
        metadata["client_name"] = drift.client_name
    # The two halves, kept apart as well as flattened into `evidence`. A report
    # that draws a real diff cannot work from the flattened form, for two
    # reasons that only show up on real input:
    #
    #   `evidence` is capped at EVIDENCE_CHARS, so a 300-character description
    #   -- unremarkable -- pushes the `+` row off the end entirely and the diff
    #   silently becomes a one-sided quote of the old text;
    #
    #   and `before`/`after` are the server's own strings, so one containing a
    #   newline and a `+ ` writes a row of its own into the flattened output.
    #   A rug pull is precisely the finding where a server is trying to control
    #   what a reviewer sees, so letting it author diff rows is the wrong
    #   default. Both halves are already bounded by `prober.FIELD_SAMPLE_CHARS`.
    if drift.before is not None:
        metadata["before"] = drift.before
    if drift.after is not None:
        metadata["after"] = drift.after

    return Finding(
        rule_id=RUG_PULL.id,
        title=RUG_PULL.title,
        severity=rank.severity,
        confidence=rank.confidence,
        message=f"{detail} Observed {drift.condition}.",
        location=where,
        evidence=_diff(drift.before, drift.after),
        subject=subject,
        remediation=RUG_PULL.remediation,
        # No per-drift anchor: the page presents the five shapes as one table,
        # which reads better than five headings, and an anchor pointing at a
        # heading that does not exist is worse than no anchor.
        help_uri=RUG_PULL.help_uri,
        metadata=metadata,
    )


def _diff(before: str | None, after: str | None) -> str | None:
    """The two descriptions, so a reader sees what changed without re-running."""
    if before is None and after is None:
        return None
    if before is None:
        return f"+ {after}"
    if after is None:
        return f"- {before}"
    return f"- {before}\n+ {after}"


# --------------------------------------------------------------------------
# MCP-008
# --------------------------------------------------------------------------
def scope_escape_finding(
    tool: str,
    argument: str,
    payload: str,
    hit: CanaryHit,
    *,
    index: int | None = None,
    subject: str = "",
) -> Finding:
    """A tool returned the contents of a file it was never meant to reach."""
    where = (
        Location(pointer=f"#/tools/{index}")
        if index is not None
        else Location(pointer=f"#/_probe/scope-escape/{tool}")
    )
    return Finding(
        rule_id=SCOPE_ESCAPE.id,
        title=SCOPE_ESCAPE.title,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        message=(
            f"Tool {tool!r} returned {hit.describe()} when {argument!r} was set to "
            f"a traversal path. The response contained a token planted in that "
            f"file moments earlier, so the tool read it."
        ),
        location=where,
        evidence=f"{argument}={payload}",
        subject=subject,
        remediation=SCOPE_ESCAPE.remediation,
        help_uri=SCOPE_ESCAPE.help_uri,
        metadata={
            "probe": "scope_escape",
            "tool": tool,
            "argument": argument,
            "payload": payload,
            "canary": hit.name,
        },
    )


# --------------------------------------------------------------------------
# MCP-009
# --------------------------------------------------------------------------
def env_leak_finding(
    surface: str,
    hit: CanaryHit,
    *,
    pointer: str | None = None,
    excerpt: str | None = None,
    subject: str = "",
) -> Finding:
    """A canary environment value came back in a response.

    Severity rises when the variable was never declared: reading a variable the
    target asked for and then echoing it is careless, while reading one it never
    mentioned means it went looking.
    """
    undeclared = hit.origin is Origin.ENV and not hit.declared
    return Finding(
        rule_id=ENV_LEAK.id,
        title=ENV_LEAK.title,
        severity=Severity.CRITICAL if undeclared else Severity.HIGH,
        confidence=Confidence.HIGH,
        message=(
            f"{surface} disclosed {hit.describe()}. The value was generated for "
            "this scan and injected only into the target's environment, so it "
            "cannot have arrived any other way."
        ),
        location=Location(pointer=pointer or f"#/_probe/env-leak/{hit.name}"),
        evidence=excerpt,
        subject=subject,
        remediation=ENV_LEAK.remediation,
        help_uri=f"{ENV_LEAK.help_uri}#undeclared" if undeclared else ENV_LEAK.help_uri,
        metadata={
            "probe": "env_leak",
            "variable": hit.name,
            "declared": hit.declared,
            "surface": surface,
        },
    )
