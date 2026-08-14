"""Turning what a target did wrong on the wire into findings a reader can act on.

Step 3 records nineteen kinds of :class:`~mcpscan.models.ProtocolAnomaly` and
reports none of them. This is where that gap closes, and the interesting part is
what does *not* become a finding.

**Not every anomaly is a security finding.** A server that prints an npm
deprecation banner on its protocol channel is violating the spec and telling you
something about how carefully it was built, but it is hygiene, not an attack.
Mapping all nineteen kinds at MEDIUM would produce a report where the fifteenth
copy of "non-JSON on stdout" buries the one duplicate-id that mattered, and a
report like that gets skimmed -- which is the failure mode this whole tool is
built to avoid.

So three dispositions:

*Finding.* The target did something a correct server would not, and it has
security consequence. Fifteen kinds, under three rule ids.

*Aggregated finding.* Same, but the kind can fire hundreds of times in one scan.
At most one finding, carrying ``occurrences``. Without this a chatty server
produces four hundred INFO findings from four hundred banner lines.

*Coverage note.* The scan could not do something. Four kinds, and none of them is
the target's fault: a page cap is *our* truncation, a timeout is what we could not
ask. These belong with "MCP-003 skipped: no source available", not among findings
-- a report where the scanner talks about itself in the findings list is a report
that cannot be triaged.

Severity is per-kind rather than per-rule. SARIF models this exactly: a rule's
properties are fixed, a result's level is not.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from mcpscan.engine import CoverageNote, RuleMeta
from mcpscan.models import AnomalyKind, Confidence, Finding, Location, ProtocolAnomaly, Severity

FRAMING = RuleMeta(
    id="MCP-004",
    title="Malformed protocol framing",
    severity=Severity.MEDIUM,
    remediation=(
        "Emit only newline-delimited JSON-RPC on stdout, one message per line, "
        "UTF-8, with no embedded newlines. Logging and diagnostics belong on "
        "stderr, which the 2025-11-25 stdio transport reserves for exactly that."
    ),
)

CORRELATION = RuleMeta(
    id="MCP-005",
    title="Response correlation abuse",
    severity=Severity.HIGH,
    remediation=(
        "Answer each request id exactly once and never send a response for an id "
        "the client did not issue. A client that accepts either can have state it "
        "has already acted on replaced underneath it."
    ),
)

CONFORMANCE = RuleMeta(
    id="MCP-006",
    title="Protocol conformance and capability mismatch",
    severity=Severity.HIGH,
    remediation=(
        "Declare every capability the server actually serves, terminate "
        "pagination, and negotiate the latest protocol revision supported. A "
        "surface that is not declared is a surface nothing reviews."
    ),
)


@dataclass(frozen=True, slots=True)
class Mapping:
    """How one anomaly kind is reported."""

    rule: RuleMeta
    severity: Severity
    confidence: Confidence
    summary: str
    #: Collapse to one finding per scan carrying ``occurrences``.
    aggregate: bool = False

    def anchor(self, kind: AnomalyKind) -> str:
        return f"{self.rule.help_uri}#{kind.value.replace('_', '-')}"


#: The table. Every entry is a judgement about whether a reader should act, and
#: the summary says why in one line.
MAPPINGS: Final[dict[AnomalyKind, Mapping]] = {
    # -- MCP-004: framing ------------------------------------------------
    AnomalyKind.EMBEDDED_NEWLINE: Mapping(
        FRAMING, Severity.MEDIUM, Confidence.HIGH,
        "A literal newline split one message into two. Framing confusion is a "
        "primitive: what the client parses is not what the server thinks it sent.",
    ),
    AnomalyKind.JSON_TOO_DEEP: Mapping(
        FRAMING, Severity.MEDIUM, Confidence.HIGH,
        "Nesting deep enough to exhaust a recursive parser. No legitimate MCP "
        "message is thousands of levels deep.",
    ),
    AnomalyKind.OVERSIZED_LINE: Mapping(
        FRAMING, Severity.MEDIUM, Confidence.MEDIUM,
        "A message with no terminating newline, large enough to exhaust a client "
        "that reads a line at a time. Either an attack or a badly broken server.",
        aggregate=True,
    ),
    AnomalyKind.BATCH_ARRAY: Mapping(
        FRAMING, Severity.LOW, Confidence.HIGH,
        "A JSON-RPC batch array. Batching was removed in revision 2025-06-18, so "
        "this is either a stale implementation or a probe for one.",
    ),
    AnomalyKind.RESULT_AND_ERROR: Mapping(
        FRAMING, Severity.LOW, Confidence.HIGH,
        "A response carrying both 'result' and 'error'. Two clients may resolve "
        "the ambiguity differently, which is a place to hide behaviour.",
    ),
    AnomalyKind.BAD_UTF8: Mapping(
        FRAMING, Severity.LOW, Confidence.HIGH,
        "Invalid UTF-8 on the protocol channel, which the spec requires to be "
        "UTF-8. Encoding confusion changes what downstream readers see.",
        aggregate=True,
    ),
    AnomalyKind.NON_JSON_STDOUT: Mapping(
        FRAMING, Severity.INFO, Confidence.HIGH,
        "Non-MCP content on stdout -- banners, warnings, progress. Hygiene "
        "rather than attack, but stdout is the protocol channel and noise there "
        "is where a payload hides.",
        aggregate=True,
    ),
    AnomalyKind.MISSING_JSONRPC: Mapping(
        FRAMING, Severity.INFO, Confidence.HIGH,
        "Messages without a correct 'jsonrpc' field. Conformance sloppiness.",
        aggregate=True,
    ),
    AnomalyKind.MALFORMED_MESSAGE: Mapping(
        FRAMING, Severity.INFO, Confidence.MEDIUM,
        "Messages that are not a well-formed request, response or notification.",
        aggregate=True,
    ),
    # -- MCP-005: correlation --------------------------------------------
    AnomalyKind.DUPLICATE_ID: Mapping(
        CORRELATION, Severity.HIGH, Confidence.HIGH,
        "A second response for an id already answered. The client has acted on "
        "the first; the second overwrites state that was already trusted.",
    ),
    AnomalyKind.UNSOLICITED_RESPONSE: Mapping(
        CORRELATION, Severity.HIGH, Confidence.HIGH,
        "A response for a request that was never sent. Ids are sequential, so "
        "this is an attempt to answer a question the client is about to ask.",
    ),
    AnomalyKind.UNEXPECTED_SERVER_REQUEST: Mapping(
        CORRELATION, Severity.MEDIUM, Confidence.HIGH,
        "The server issued a request for a capability that was never negotiated.",
    ),
    # -- MCP-006: conformance --------------------------------------------
    AnomalyKind.UNDECLARED_CAPABILITY: Mapping(
        CONFORMANCE, Severity.HIGH, Confidence.HIGH,
        "The server serves a capability it did not declare. Anything reviewing "
        "the declared capability block sees a smaller surface than exists.",
    ),
    AnomalyKind.CURSOR_LOOP: Mapping(
        CONFORMANCE, Severity.MEDIUM, Confidence.HIGH,
        "Pagination that does not terminate. A client looping until 'nextCursor' "
        "is absent loops until it dies.",
    ),
    AnomalyKind.VERSION_DOWNGRADE: Mapping(
        CONFORMANCE, Severity.LOW, Confidence.HIGH,
        "The server answered with an older protocol revision than was offered. "
        "Older revisions carry weaker rules, and the server chose the ground.",
    ),
}

#: Kinds that describe what the *scan* could not do. Never findings.
COVERAGE_KINDS: Final[dict[AnomalyKind, str]] = {
    AnomalyKind.PAGE_CAP: "listing truncated at the page cap; results are incomplete",
    AnomalyKind.REQUEST_TIMEOUT: "a request went unanswered; that surface was not examined",
    AnomalyKind.TRANSPORT_CLOSED: "the target's stdout closed early; the scan did not finish",
    AnomalyKind.UNSUPPORTED_VERSION: "no shared protocol revision; the scan never started",
}


def unmapped_kinds() -> set[AnomalyKind]:
    """Kinds that are neither a finding nor a coverage note.

    Always empty, and a test asserts it. A kind added to the enum without a
    decision here would otherwise be detected and silently dropped, which is the
    exact failure step 3 left behind and this module exists to end.
    """
    return set(AnomalyKind) - set(MAPPINGS) - set(COVERAGE_KINDS)


def rule_metas() -> list[RuleMeta]:
    return [FRAMING, CORRELATION, CONFORMANCE]


def to_findings(
    anomalies: Sequence[ProtocolAnomaly],
    *,
    subject: str = "",
) -> tuple[list[Finding], list[CoverageNote]]:
    """Split an anomaly log into findings and coverage notes.

    Aggregated kinds collapse to their first occurrence, carrying the count and
    keeping that first sample as evidence. Arrival order is preserved among the
    rest, because ordering *is* the evidence -- "the tool list changed after we
    called it" is a rug pull, and the same two listings the other way round are
    nothing.
    """
    findings: list[Finding] = []
    notes: list[CoverageNote] = []
    counts: dict[AnomalyKind, int] = {}
    first: dict[AnomalyKind, ProtocolAnomaly] = {}

    for anomaly in anomalies:
        if anomaly.kind in COVERAGE_KINDS:
            notes.append(CoverageNote(kind=anomaly.kind.value, detail=anomaly.detail))
            continue

        mapping = MAPPINGS.get(anomaly.kind)
        if mapping is None:
            # Unreachable while `unmapped_kinds()` is empty, which a test pins.
            # Recorded rather than dropped so a future kind surfaces as coverage
            # instead of vanishing.
            notes.append(
                CoverageNote(
                    kind="unmapped_anomaly",
                    detail=f"{anomaly.kind.value}: {anomaly.detail}",
                )
            )
            continue

        counts[anomaly.kind] = counts.get(anomaly.kind, 0) + 1
        if mapping.aggregate:
            first.setdefault(anomaly.kind, anomaly)
            continue
        findings.append(_finding(anomaly, mapping, subject, occurrences=1))

    for kind, anomaly in first.items():
        findings.append(
            _finding(anomaly, MAPPINGS[kind], subject, occurrences=counts[kind])
        )

    findings.sort(key=lambda f: f.sort_key)
    return findings, notes


def _finding(
    anomaly: ProtocolAnomaly,
    mapping: Mapping,
    subject: str,
    *,
    occurrences: int,
) -> Finding:
    message = mapping.summary
    if occurrences > 1:
        message = f"{message} Seen {occurrences} times."

    return Finding(
        rule_id=mapping.rule.id,
        title=mapping.rule.title,
        severity=mapping.severity,
        confidence=mapping.confidence,
        message=message,
        # Anomalies have no file and no JSON pointer into served metadata, so
        # they are located by arrival order -- which is the evidence anyway.
        location=Location(pointer=f"#/_transport/{anomaly.seq}"),
        evidence=_evidence(anomaly),
        subject=subject,
        remediation=mapping.rule.remediation,
        help_uri=mapping.anchor(anomaly.kind),
        metadata={
            "kind": anomaly.kind.value,
            "detail": anomaly.detail,
            "occurrences": occurrences,
            "seq": anomaly.seq,
        },
    )


def _evidence(anomaly: ProtocolAnomaly) -> str | None:
    if anomaly.raw is None:
        return None
    return anomaly.raw.decode("utf-8", "replace")


def notes_for(kinds: Iterable[AnomalyKind]) -> list[str]:
    """Human-readable coverage reasons, for the text reporter."""
    return [COVERAGE_KINDS[kind] for kind in kinds if kind in COVERAGE_KINDS]
