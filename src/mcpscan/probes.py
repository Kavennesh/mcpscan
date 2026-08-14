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
from mcpscan.engine import RuleMeta
from mcpscan.models import Confidence, Finding, Location, Severity

RUG_PULL = RuleMeta(
    id="MCP-007",
    title="Tool definition changed after inspection",
    severity=Severity.HIGH,
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
    before: str | None = None
    after: str | None = None
    #: Index in the later listing, when the tool is in it.
    index: int | None = None
    #: The identity presented, when this was a client-targeted difference.
    client_name: str | None = None


def rug_pull_finding(drift: ToolDrift, *, subject: str = "") -> Finding:
    rank = DRIFT_RANKS[drift.kind]
    where = (
        Location(pointer=f"#/tools/{drift.index}")
        if drift.index is not None
        else Location(pointer=f"#/_probe/rug-pull/{drift.tool}")
    )

    detail = f"Tool {drift.tool!r} {rank.summary}"
    if drift.client_name:
        detail += f" Identity presented: {drift.client_name!r}."

    metadata: dict[str, Any] = {
        "probe": "rug_pull",
        "drift": drift.kind.value,
        "tool": drift.tool,
        "condition": drift.condition,
    }
    if drift.client_name:
        metadata["client_name"] = drift.client_name

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
