"""Serialising a scan. JSON now, SARIF at step 7, HTML at step 8.

Everything here goes through :class:`~mcpscan.models.Finding` rather than around
it. ``CLAUDE.md`` calls it "the single shape all report formats serialise from",
and the way that stops being true is a format reaching past it for something
convenient -- so the rule is that a field a report needs is a field `Finding`
grows.

Two structural choices worth stating:

**``coverage`` is a top-level sibling of ``findings``, not a footnote inside it.**
"No findings" and "no analysis" must stay distinguishable in a machine-readable
report for exactly the reason they must in the text one: a CI job that reads
``findings: []`` and concludes "clean" is worse off than one that read nothing,
because now it believes something. A consumer that ignores ``coverage`` is making
that mistake deliberately rather than by accident.

**Field names are stable and snake_case**, and the SARIF mapping is written down
below rather than rediscovered at step 7.

``generated_at`` is the first clock in this codebase outside ``sandbox.py``. It
stays confined to this module and is injectable, so tests get byte-stable output.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Final

from mcpscan import __version__
from mcpscan.analyser import AnalysisResult
from mcpscan.models import Finding, Location, Severity, Target

#: Bumped only when a consumer would break. New optional fields do not bump it;
#: renaming or removing one does.
SCHEMA_VERSION: Final = 1

TOOL_NAME: Final = "mcpscan"
#: From installed metadata, not a literal. A report that names the wrong release
#: is a report nobody can correlate with a build.
TOOL_VERSION: Final = __version__

# ---------------------------------------------------------------------------
# SARIF mapping. Written down here at step 5 so it was derived from the shape
# that exists rather than reverse-engineered later; `sarif.py` implements it.
# Two lines were wrong when they were written, and are corrected below.
#
#   rule_id              -> result.ruleId
#   severity             -> result.level (critical/high -> error, medium ->
#                           warning, low/info -> note) + properties.severity
#   confidence           -> result.properties.confidence
#   message              -> result.message.text
#   remediation          -> reportingDescriptor.help.text / help.markdown
#   help_uri             -> reportingDescriptor.helpUri, minus any `#anchor`;
#                           the anchored form is per-finding and cannot live on
#                           a per-rule descriptor, so it goes in properties.
#   location.path        -> physicalLocation.artifactLocation.uri
#   location.start_line  -> physicalLocation.region.startLine
#   location.end_line    -> physicalLocation.region.endLine
#   location.span.byte_* -> result.properties.span, and *nowhere else*.
#                           NOT region.byteOffset: SARIF defines that relative
#                           to the artifact, and a Span indexes one field's text
#                           (`Span.of(field_.text, ...)`, engine.py). Against a
#                           source file those offsets name arbitrary bytes.
#   location.pointer     -> logicalLocation.fullyQualifiedName
#   evidence             -> result.properties.evidence, and region.snippet.text
#                           where a region exists. Not the artifact's bytes in
#                           that region -- it is the decoded, capped excerpt --
#                           but it is the text a reader needs and the one SARIF
#                           renders when the file is not in the commit.
#   related              -> result.relatedLocations
#   metadata             -> result.properties
# ---------------------------------------------------------------------------


def now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def location_json(location: Location) -> dict[str, Any]:
    """Only the coordinate systems this location actually has.

    Emitting nulls for the half that does not apply would make every consumer
    write the same "is this a source finding or a wire finding" branch, and would
    hide that the distinction is real.
    """
    payload: dict[str, Any] = {}
    if location.path is not None:
        payload["path"] = str(location.path)
        if location.start_line is not None:
            payload["start_line"] = location.start_line
        if location.end_line is not None:
            payload["end_line"] = location.end_line
    if location.pointer is not None:
        payload["pointer"] = location.pointer
    if location.span is not None:
        payload["span"] = {
            "start": location.span.start,
            "end": location.span.end,
            "byte_start": location.span.byte_start,
            "byte_end": location.span.byte_end,
        }
    return payload


def finding_json(finding: Finding) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "message": finding.message,
        "subject": finding.subject,
        "location": location_json(finding.location),
    }
    if finding.related:
        payload["related"] = [location_json(item) for item in finding.related]
    if finding.evidence is not None:
        payload["evidence"] = finding.evidence
    if finding.remediation:
        payload["remediation"] = finding.remediation
    if finding.help_uri:
        payload["help_uri"] = finding.help_uri
    if finding.metadata:
        payload["metadata"] = finding.metadata
    return payload


def target_json(target: Target) -> dict[str, Any]:
    detail = {
        "stdio": lambda: " ".join(target.command or []),
        "http": lambda: target.url or "",
        "path": lambda: str(target.path or ""),
    }[target.kind.value]()
    return {"label": target.label, "kind": target.kind.value, "detail": detail}


def summarise(findings: Sequence[Finding], fail_on: Severity) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
    actionable = [f for f in findings if f.severity.rank >= fail_on.rank]
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "fail_on": fail_on.value,
        "at_or_above_fail_on": len(actionable),
    }


def coverage_json(results: Sequence[tuple[Target, AnalysisResult]]) -> dict[str, Any]:
    """What was and was not analysed, folded across every target.

    Extracted from :func:`build` so SARIF carries the identical block rather
    than a second, drifting serialisation of the same fields. A consumer that
    ignores it is deciding to conflate "found nothing" with "looked at nothing";
    a consumer that cannot find it has been forced into that mistake.
    """
    files_scanned = 0
    ran: list[str] = []
    skipped: list[dict[str, str]] = []
    unparsed: list[dict[str, str]] = []
    notes: list[dict[str, str]] = []

    for _, result in results:
        files_scanned += result.files_scanned
        for rule_id in result.ran:
            if rule_id not in ran:
                ran.append(rule_id)
        skipped.extend({"rule_id": r, "reason": why} for r, why in result.skipped)
        unparsed.extend({"path": str(p), "reason": why} for p, why in result.unparsed)
        notes.extend({"kind": n.kind, "detail": n.detail} for n in result.notes)

    return {
        "files_scanned": files_scanned,
        "rules_run": ran,
        "rules_skipped": skipped,
        "unparsed": unparsed,
        "notes": notes,
    }


def sorted_findings(results: Sequence[tuple[Target, AnalysisResult]]) -> list[Finding]:
    """Every finding from every target, worst first. One order, one place."""
    findings: list[Finding] = []
    for _, result in results:
        findings.extend(result.findings)
    findings.sort(key=lambda f: f.sort_key)
    return findings


def build(
    results: Sequence[tuple[Target, AnalysisResult]],
    *,
    fail_on: Severity,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """The whole report as a plain dict, ready for ``json.dumps``."""
    findings = sorted_findings(results)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "generated_at": generated_at if generated_at is not None else now_utc(),
        "targets": [target_json(target) for target, _ in results],
        "coverage": coverage_json(results),
        "summary": summarise(findings, fail_on),
        "findings": [finding_json(finding) for finding in findings],
    }


def render(
    results: Sequence[tuple[Target, AnalysisResult]],
    *,
    fail_on: Severity,
    generated_at: str | None = None,
) -> str:
    """Pretty-printed JSON with a trailing newline, stable key order.

    ``sort_keys`` is deliberately off: the key order above is the order a human
    reads them in, and machine consumers do not care. Findings are already sorted
    worst-first by :attr:`Finding.sort_key`.
    """
    payload = build(results, fail_on=fail_on, generated_at=generated_at)
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
