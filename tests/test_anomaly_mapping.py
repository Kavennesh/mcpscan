"""The AnomalyKind -> Finding table, asserted row by row.

Step 3 detects nineteen kinds of protocol anomaly and reports none. This is the
table that closes that gap, and the reason it is asserted exhaustively is that
the interesting decisions are the ones *against* reporting:

- four kinds are coverage notes, not findings, because they describe what the
  scan could not do rather than what the target did wrong;
- five are aggregated, because a chatty server fires them hundreds of times and
  hundreds of identical INFO findings is a report nobody reads;
- the severities are spread from INFO to HIGH deliberately. An npm banner and a
  duplicate-id overwrite are both spec violations and are not both worth waking
  someone up for.

The exhaustiveness test is the one that matters long-term: a kind added to the
enum without a decision here fails the build instead of being silently detected
and dropped, which is the exact failure this module exists to end.
"""

from __future__ import annotations

import pytest

from mcpscan.anomalies import (
    COVERAGE_KINDS,
    MAPPINGS,
    rule_metas,
    to_findings,
    unmapped_kinds,
)
from mcpscan.models import AnomalyKind, Confidence, ProtocolAnomaly, Severity


def anomaly(kind: AnomalyKind, seq: int = 0, raw: bytes | None = None) -> ProtocolAnomaly:
    return ProtocolAnomaly(kind=kind, detail=f"{kind.value} happened", seq=seq, raw=raw)


# --------------------------------------------------------------------------
# exhaustiveness
# --------------------------------------------------------------------------
def test_every_anomaly_kind_has_a_decision() -> None:
    """A kind added later must fail here rather than vanish silently."""
    assert unmapped_kinds() == set()


def test_the_split_is_fifteen_findings_and_four_coverage_notes() -> None:
    assert len(AnomalyKind) == 19
    assert len(MAPPINGS) == 15
    assert len(COVERAGE_KINDS) == 4


def test_no_kind_is_both_a_finding_and_a_coverage_note() -> None:
    assert set(MAPPINGS) & set(COVERAGE_KINDS) == set()


def test_all_nineteen_kinds_round_trip() -> None:
    """One of each in, fifteen findings and four notes out."""
    log = [anomaly(kind, seq=index) for index, kind in enumerate(AnomalyKind)]
    findings, notes = to_findings(log)

    assert len(findings) == 15
    assert len(notes) == 4
    assert {n.kind for n in notes} == {k.value for k in COVERAGE_KINDS}


# --------------------------------------------------------------------------
# the table, row by row
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("kind", "rule_id", "severity", "confidence"),
    [
        # MCP-004 -- framing
        (AnomalyKind.EMBEDDED_NEWLINE, "MCP-004", Severity.MEDIUM, Confidence.HIGH),
        (AnomalyKind.JSON_TOO_DEEP, "MCP-004", Severity.MEDIUM, Confidence.HIGH),
        (AnomalyKind.OVERSIZED_LINE, "MCP-004", Severity.MEDIUM, Confidence.MEDIUM),
        (AnomalyKind.BATCH_ARRAY, "MCP-004", Severity.LOW, Confidence.HIGH),
        (AnomalyKind.RESULT_AND_ERROR, "MCP-004", Severity.LOW, Confidence.HIGH),
        (AnomalyKind.BAD_UTF8, "MCP-004", Severity.LOW, Confidence.HIGH),
        (AnomalyKind.NON_JSON_STDOUT, "MCP-004", Severity.INFO, Confidence.HIGH),
        (AnomalyKind.MISSING_JSONRPC, "MCP-004", Severity.INFO, Confidence.HIGH),
        (AnomalyKind.MALFORMED_MESSAGE, "MCP-004", Severity.INFO, Confidence.MEDIUM),
        # MCP-005 -- correlation
        (AnomalyKind.DUPLICATE_ID, "MCP-005", Severity.HIGH, Confidence.HIGH),
        (AnomalyKind.UNSOLICITED_RESPONSE, "MCP-005", Severity.HIGH, Confidence.HIGH),
        (AnomalyKind.UNEXPECTED_SERVER_REQUEST, "MCP-005", Severity.MEDIUM, Confidence.HIGH),
        # MCP-006 -- conformance
        (AnomalyKind.UNDECLARED_CAPABILITY, "MCP-006", Severity.HIGH, Confidence.HIGH),
        (AnomalyKind.CURSOR_LOOP, "MCP-006", Severity.MEDIUM, Confidence.HIGH),
        (AnomalyKind.VERSION_DOWNGRADE, "MCP-006", Severity.LOW, Confidence.HIGH),
    ],
)
def test_each_kind_maps_as_documented(
    kind: AnomalyKind, rule_id: str, severity: Severity, confidence: Confidence
) -> None:
    findings, notes = to_findings([anomaly(kind)])
    assert notes == []
    assert len(findings) == 1

    finding = findings[0]
    assert finding.rule_id == rule_id
    assert finding.severity is severity
    assert finding.confidence is confidence
    assert finding.metadata["kind"] == kind.value


@pytest.mark.parametrize("kind", sorted(COVERAGE_KINDS, key=lambda k: k.value))
def test_coverage_kinds_produce_no_findings(kind: AnomalyKind) -> None:
    """The scanner talking about itself belongs in coverage, not in findings."""
    findings, notes = to_findings([anomaly(kind)])
    assert findings == []
    assert len(notes) == 1
    assert notes[0].kind == kind.value


def test_hygiene_sits_below_the_default_fail_on() -> None:
    """An npm banner must not fail a build. That is the whole point of INFO."""
    findings, _ = to_findings([anomaly(AnomalyKind.NON_JSON_STDOUT)])
    assert findings[0].severity.rank < Severity.HIGH.rank


def test_correlation_abuse_sits_above_it() -> None:
    findings, _ = to_findings([anomaly(AnomalyKind.DUPLICATE_ID)])
    assert findings[0].severity.rank >= Severity.HIGH.rank


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------
def test_four_hundred_banner_lines_collapse_to_one_finding() -> None:
    """The concrete form of the flooding this table exists to prevent."""
    log = [anomaly(AnomalyKind.NON_JSON_STDOUT, seq=i) for i in range(400)]
    findings, _ = to_findings(log)

    assert len(findings) == 1
    assert findings[0].metadata["occurrences"] == 400
    assert "400 times" in findings[0].message


def test_aggregation_keeps_the_first_sample_as_evidence() -> None:
    log = [
        anomaly(AnomalyKind.NON_JSON_STDOUT, seq=0, raw=b"npm WARN first"),
        anomaly(AnomalyKind.NON_JSON_STDOUT, seq=1, raw=b"npm WARN second"),
    ]
    findings, _ = to_findings(log)
    assert findings[0].evidence == "npm WARN first"
    assert findings[0].metadata["seq"] == 0


def test_non_aggregated_kinds_are_reported_every_time() -> None:
    """A second duplicate-id is a second attempt, not a repeat of the first."""
    log = [anomaly(AnomalyKind.DUPLICATE_ID, seq=i) for i in range(3)]
    findings, _ = to_findings(log)
    assert len(findings) == 3
    assert [f.metadata["seq"] for f in findings] == [0, 1, 2]


def test_a_single_occurrence_does_not_claim_a_count() -> None:
    findings, _ = to_findings([anomaly(AnomalyKind.NON_JSON_STDOUT)])
    assert "times" not in findings[0].message
    assert findings[0].metadata["occurrences"] == 1


# --------------------------------------------------------------------------
# what a finding says
# --------------------------------------------------------------------------
def test_findings_are_located_by_arrival_order() -> None:
    """Anomalies have no file and no pointer into served metadata.

    Arrival order is the evidence anyway -- "the tool list changed after we
    called it" is a rug pull and the reverse order is nothing.
    """
    findings, _ = to_findings([anomaly(AnomalyKind.DUPLICATE_ID, seq=7)])
    assert findings[0].location.pointer == "#/_transport/7"
    assert findings[0].location.path is None


def test_every_finding_carries_remediation_and_a_help_anchor() -> None:
    for kind, mapping in MAPPINGS.items():
        findings, _ = to_findings([anomaly(kind)])
        finding = findings[0]
        assert len(finding.remediation) > 30
        assert finding.help_uri == f"docs/rules/{mapping.rule.id}.md#{kind.value.replace('_', '-')}"


def test_the_subject_is_carried_through() -> None:
    findings, _ = to_findings([anomaly(AnomalyKind.DUPLICATE_ID)], subject="acme")
    assert findings[0].subject == "acme"


def test_findings_are_sorted_worst_first() -> None:
    log = [anomaly(kind, seq=i) for i, kind in enumerate(AnomalyKind)]
    findings, _ = to_findings(log)
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_raw_evidence_survives_invalid_utf8() -> None:
    """The bad-utf8 kind carries bytes that are, by definition, not decodable."""
    findings, _ = to_findings([anomaly(AnomalyKind.BAD_UTF8, raw=b"\xff\xfe bad")])
    assert findings[0].evidence is not None


def test_the_three_rules_are_distinct_and_documented() -> None:
    metas = rule_metas()
    assert [m.id for m in metas] == ["MCP-004", "MCP-005", "MCP-006"]
    for meta in metas:
        assert len(meta.remediation) > 30
        assert meta.help_uri == f"docs/rules/{meta.id}.md"


def test_an_empty_log_produces_nothing() -> None:
    assert to_findings([]) == ([], [])
