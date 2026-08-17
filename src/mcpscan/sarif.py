"""SARIF 2.1.0, the format that puts a finding where a developer will see it.

``report.py`` carries the mapping this implements; it was written at step 5 so it
would be derived from the shape that exists rather than reverse-engineered from
it. Two lines of it turned out to be wrong and are corrected there.

Everything here still goes through :class:`~mcpscan.models.Finding`. The one
thing SARIF needs that a `Finding` cannot hold is **a file for a finding that has
none** -- a live server's metadata exists only on the wire -- and that is what
``document.serialise`` and the ``.mcpscan/`` artefact are for. GitHub silently
discards a result with no ``physicalLocation``, so without it a scan of a server
that failed nine ways would upload as a clean run, which is the exact conflation
``coverage`` exists to prevent.

Four decisions worth stating, because each looks arbitrary and is not.

**No ``automationDetails``.** ``github/codeql-action/upload-sarif`` fills that in
from its ``category:`` input, but only when the document does not already carry
one. A tool-supplied constant would therefore make every job upload under the
same automation id, and GitHub would read the second job's upload as a
re-analysis of the first -- closing every alert the other one found, on every
push. The category is a property of the CI invocation, not of the scan.

**No ``uriBaseId``.** ``%SRCROOT%`` is a GitHub convention, and SARIF §3.4.4 says
a ``uriBaseId`` names a symbol defined in ``originalUriBaseIds`` -- which would
mean writing the scanner's absolute filesystem layout into the document. Plain
repository-relative URIs resolve correctly for GitHub and are not a token only
one vendor understands.

**One run for the whole scan.** ``report.build`` folds every target into one
findings list, one summary and one coverage block, and a SARIF that described the
same scan differently would make "the format changes what is printed, never what
it means" false. Per-target identity lives in ``result.properties.subject`` and
in which artefact a result points at.

**``ensure_ascii=True``.** A hostile server can put a lone surrogate in a
description -- ``json.loads`` accepts ``\\ud800`` and UTF-8 cannot encode it --
and a scanner that crashes on the input it exists to examine is not a scanner.
The same choice in ``document.serialise`` is what makes the artefact's columns
plain character offsets.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote

from mcpscan import __version__
from mcpscan.analyser import AnalysisResult
from mcpscan.catalogue import rule_catalogue
from mcpscan.document import SurveyArtefact
from mcpscan.engine import RuleMeta, RuleSet
from mcpscan.models import Finding, Location, Severity, Target
from mcpscan.report import TOOL_NAME, coverage_json, sorted_findings, summarise, target_json

SARIF_VERSION: Final = "2.1.0"

#: The schema this document is validated against in the test suite -- the OASIS
#: errata01 copy, which is what `sarif-schema-2.1.0.json` declares as its own
#: `id`. GitHub's documentation names a schemastore mirror of the same schema;
#: either is accepted, and pointing at the copy we actually check against is the
#: one that cannot quietly become a different claim.
SCHEMA_URI: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

INFORMATION_URI: Final = "https://github.com/Kavennesh/mcpscan"

#: GitHub displays the top 5000 of at most 25000 results per run and rejects an
#: upload above that. A scanner that silently exceeds it loses the whole run.
MAX_RESULTS: Final = 25_000

#: `result.level`. SARIF has four; we have five severities, and the two lowest
#: are both advisory.
LEVELS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: `properties.security-severity`, which is what GitHub turns into the severity
#: badge on an alert. Its own thresholds: >9.0 critical, 7.0 high, 4.0 medium,
#: 0.1 low. Emitted as strings because that is what CodeQL emits.
SECURITY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

#: Fields of `Finding.metadata` that identify *what* was found rather than where
#: or when. An allow-list rather than a deny-list: a metadata key added later
#: cannot silently start churning every fingerprint, it just does not
#: participate until someone decides it should.
STABLE_METADATA_KEYS: Final = (
    "argument",
    "condition",
    "declared",
    "drift",
    "field",
    "kind",
    "parameter",
    "pattern",
    "probe",
    "shell",
    "sink",
    "sink_kind",
    "surface",
    "tool",
    "variable",
)

#: Version of the fingerprint recipe. Bumping it re-opens every alert once, on
#: purpose, which is why it is a constant with a comment rather than a literal.
FINGERPRINT_VERSION: Final = "mcpscan/1"


@dataclass(frozen=True, slots=True)
class WrittenSurvey:
    """A survey artefact and the file it was written to."""

    #: Workspace-relative POSIX path, already percent-encoded. The URI a result
    #: points at.
    uri: str
    artefact: SurveyArtefact


# ---------------------------------------------------------------------------
# locations
# ---------------------------------------------------------------------------
def workspace_root(start: Path | None = None) -> Path:
    """The directory a result's URI is relative to: the repository root.

    Not the working directory, which is the obvious choice and is wrong twice
    over. GitHub resolves a result's URI against the root of the checkout, so a
    scan run from a package subdirectory that reported ``s.py`` sends it looking
    for ``/s.py`` -- which finds nothing, or worse finds a *different* file with
    that name and hangs the alert on it. And a scan run from a sibling directory
    would report every committed file as unreachable and fall back to the survey
    artefact, which is a worse place to read an alert than the source.

    Found by walking up for ``.git``, which is a directory in a normal checkout
    and a file in a worktree or submodule -- hence ``exists`` rather than
    ``is_dir``. A path walk, not a subprocess: `git` is not a dependency of this
    project and running one would breach the containment rule that keeps process
    spawning inside ``sandbox.py``. A tree that is not a checkout falls back to
    the working directory, which is the best guess available.
    """
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    return here


def workspace_uri(path: Path, workspace: Path) -> str | None:
    """A repository-relative URI, or nothing if the path is not in the tree.

    ``Path.relative_to(..., walk_up=True)`` would be the obvious call and is
    3.12; the floor here is 3.11. Nothing outside the workspace can be reported
    against the repository anyway -- GitHub drops an alert whose file it cannot
    find -- so "outside" and "no URI" are the same answer.
    """
    try:
        relative = path.resolve().relative_to(workspace.resolve())
    except (OSError, ValueError):
        return None
    return quote(relative.as_posix(), safe="/")


def source_uri(location: Location, target: Target, workspace: Path) -> str | None:
    """Where a source-tree location points, as a repository-relative URI.

    ``Location.path`` is relative to the *scan root*, and ``source.relative_to_root``
    rebases on the containing directory when that root is a file -- so
    ``--path src/server.py`` yields ``server.py``, and joining it back onto
    ``src/server.py`` would produce ``src/server.py/server.py``.
    """
    if location.path is None or target.path is None:
        return None
    root = target.path if target.path.is_dir() else target.path.parent
    return workspace_uri(root / location.path, workspace)


def _region_from_lines(location: Location, evidence: str | None) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": location.start_line or 1}
    if location.end_line is not None and location.end_line >= (location.start_line or 1):
        region["endLine"] = location.end_line
    if evidence:
        region["snippet"] = {"text": evidence}
    return region


def _region_from_survey(location: Location, survey: WrittenSurvey, evidence: str | None
                          ) -> dict[str, Any]:
    anchor = survey.artefact.anchor_for(location.pointer or "#")
    region: dict[str, Any] = {"startLine": anchor.line, "endLine": anchor.line}
    # A span when the rule matched a substring; otherwise the whole value, which
    # is what a probe finding is about. A container anchor has neither, and a
    # region of just a line is the right answer for `#/tools/3`.
    columns = anchor.columns(location.span) if location.span is not None else anchor.whole()
    if columns is not None:
        region["startColumn"], region["endColumn"] = columns
    if evidence:
        region["snippet"] = {"text": evidence}
    return region


def physical_location(
    location: Location,
    *,
    target: Target,
    survey: WrittenSurvey | None,
    workspace: Path,
    evidence: str | None = None,
) -> dict[str, Any] | None:
    """A file and a region, or nothing when neither is available.

    Source first, artefact second. The artefact catches three cases and all
    three are real: a live server, whose metadata has no file at all; a nested
    ``inputSchema`` description, which has a pointer and no line even on a source
    scan; and a source tree outside the workspace, whose file is not in the
    repository the alerts will land on.
    """
    uri = source_uri(location, target, workspace)
    if uri is not None:
        return {
            "artifactLocation": {"uri": uri},
            "region": _region_from_lines(location, evidence),
        }
    if survey is None:
        return None
    return {
        "artifactLocation": {"uri": survey.uri},
        "region": _region_from_survey(location, survey, evidence),
    }


# ---------------------------------------------------------------------------
# fingerprints
# ---------------------------------------------------------------------------
def stable_label(label: str) -> str:
    """A target label with a trailing version stripped.

    ``npx -y @vendor/server@1.2.3`` labels as ``@vendor/server@1.2.3``, so a
    dependency bump would otherwise change every fingerprint for that server and
    close and reopen every one of its alerts on the bump commit. The leading
    ``@`` of a scoped package is not a version and is left alone.
    """
    at = label.rfind("@")
    if at > 0 and "/" not in label[at:]:
        return label[:at]
    return label


def logical_key(finding: Finding, survey: WrittenSurvey | None, uri: str | None) -> str:
    """What the finding is *about*, in a form that survives an edit elsewhere.

    Two normalisations, each for a churn source seen in practice. A tool's index
    becomes its name, because a server is free to reorder its listing and a
    reordering is not nine new problems -- but only when the name is unique in
    that listing, since a name shared by two tools identifies neither. And
    ``#/_transport/7`` becomes ``#/_transport``, because the number is arrival
    order: one extra banner line upstream shifts every anomaly after it.
    """
    pointer = finding.location.pointer
    if pointer is None:
        return uri or str(finding.location.path or "")

    if pointer.startswith("#/_transport/"):
        return "#/_transport"

    parts = pointer.split("/")
    if survey is not None and len(parts) > 2 and parts[1] == "tools" and parts[2].isdigit():
        names = {index: name for name, index in survey.artefact.tool_index.items()}
        name = names.get(int(parts[2]))
        if name is not None:
            parts[2] = name
            return "/".join(parts)
    return pointer


def fingerprint(finding: Finding, survey: WrittenSurvey | None, uri: str | None) -> str:
    """A stable identity for one finding, for tracking it across commits.

    Deliberately built from **nothing positional**. No line number, no byte
    offset, no arrival order, no timestamp -- every one of those moves when an
    unrelated line is inserted above, and an alert that closes and reopens on
    every push is an alert people turn off.

    What is left is the rule, the target, what the finding is about, and the
    evidence. Canary tokens are already out of the evidence by the time a
    finding reaches here (``scanrun._redact_evidence``), which matters: they are
    regenerated every scan, and one in the hash would make the fingerprint
    change every run for no reason a reader could ever work out.

    Two byte-identical findings therefore share a fingerprint and become one
    alert. That is the honest outcome -- nothing distinguishes them except where
    they sit, and where they sit is what this refuses to use.
    """
    discriminator = "|".join(
        f"{key}={finding.metadata[key]!r}"
        for key in STABLE_METADATA_KEYS
        if key in finding.metadata
    )
    material = "\0".join(
        [
            FINGERPRINT_VERSION,
            finding.rule_id,
            stable_label(finding.subject),
            logical_key(finding, survey, uri),
            discriminator,
            finding.evidence or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# the driver
# ---------------------------------------------------------------------------
def _worst_by_rule(findings: Sequence[Finding]) -> dict[str, Severity]:
    worst: dict[str, Severity] = {}
    for finding in findings:
        current = worst.get(finding.rule_id)
        if current is None or finding.severity.rank > current.rank:
            worst[finding.rule_id] = finding.severity
    return worst


def rule_descriptor(meta: RuleMeta, family: str, worst: Severity) -> dict[str, Any]:
    """One ``reportingDescriptor``.

    ``defaultConfiguration.level`` is the rule's declared severity and
    ``security-severity`` is the worst its findings actually reached, which are
    not the same number and must not be. MCP-004 declares MEDIUM and emits
    anything from INFO to MEDIUM; MCP-009 declares HIGH and emits CRITICAL when
    the variable was never declared. GitHub derives the badge on an alert from
    the rule-level number, so taking it from the declared severity would display
    a critical disclosure as a high one.
    """
    return {
        "id": meta.id,
        "name": meta.id.replace("-", ""),
        "shortDescription": {"text": meta.title},
        "fullDescription": {"text": meta.description or meta.title},
        "defaultConfiguration": {"level": LEVELS[meta.severity]},
        "help": {
            "text": meta.remediation,
            "markdown": f"{meta.remediation}\n\n[{meta.id} in the rule docs]({meta.help_uri})",
        },
        "helpUri": meta.help_uri,
        "properties": {
            # `security` is not decoration: GitHub only honours
            # `security-severity` on a rule that carries the tag.
            "tags": ["security", "mcp", family],
            "security-severity": SECURITY_SEVERITY[worst],
            "severity": meta.severity.value,
        },
    }


def driver_rules(rules: RuleSet, findings: Sequence[Finding]) -> list[dict[str, Any]]:
    """Every rule that could fire, not merely every rule that did.

    A driver listing only the rules with results turns "MCP-008 ran and found
    nothing" into "MCP-008 was never mentioned". It is also a hard requirement:
    a ``ruleId`` naming no descriptor gets the whole upload rejected, which is
    how a contributed pack loaded with ``--rules`` would otherwise break a build
    the first time one of its rules matched.
    """
    worst = _worst_by_rule(findings)
    descriptors = [
        rule_descriptor(
            entry.meta, entry.family.value, worst.get(entry.meta.id, entry.meta.severity)
        )
        for entry in rule_catalogue(rules)
    ]

    # Belt and braces for a Finding built outside the rule engine -- a test
    # fixture, a future rule home nobody wired into the catalogue. Rejecting the
    # upload is a worse outcome than a thin descriptor.
    known = {descriptor["id"] for descriptor in descriptors}
    for rule_id in sorted({f.rule_id for f in findings} - known):
        descriptors.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": rule_id},
                "fullDescription": {"text": f"Undocumented rule {rule_id}."},
                "properties": {"tags": ["security", "mcp"]},
            }
        )
    return descriptors


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------
def _properties(finding: Finding, extra_path: str | None) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "subject": finding.subject,
    }
    if finding.help_uri:
        # Per-finding, and often carrying a `#kind` anchor a per-rule
        # `helpUri` cannot hold.
        properties["helpUri"] = finding.help_uri
    if finding.evidence is not None:
        properties["evidence"] = finding.evidence
    if finding.location.pointer is not None:
        properties["pointer"] = finding.location.pointer
    if finding.location.span is not None:
        # Offsets into the field's own text, never into the artifact. Named so
        # here rather than smuggled into `region.byteOffset`, which SARIF defines
        # relative to the file and which these would name arbitrary bytes of.
        properties["span"] = {
            "start": finding.location.span.start,
            "end": finding.location.span.end,
            "byte_start": finding.location.span.byte_start,
            "byte_end": finding.location.span.byte_end,
        }
    if extra_path is not None:
        # A source file outside the workspace. The result points at the artefact
        # so it is not discarded; this is where the real path survives.
        properties["path"] = extra_path
    if finding.metadata:
        properties["metadata"] = finding.metadata
    return properties


def result_json(
    finding: Finding,
    *,
    target: Target,
    survey: WrittenSurvey | None,
    workspace: Path,
    rule_index: Mapping[str, int],
) -> dict[str, Any]:
    uri = source_uri(finding.location, target, workspace)
    outside = (
        str(finding.location.path)
        if uri is None and finding.location.path is not None
        else None
    )

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": LEVELS[finding.severity],
        "message": {"text": finding.message},
        "partialFingerprints": {
            # The key GitHub consumes, and the one `upload-sarif` leaves alone
            # rather than replacing with a hash of the line's contents. The value
            # is deliberately not a line hash -- see `fingerprint` -- and the key
            # name is the price of being the key that gets used.
            "primaryLocationLineHash": fingerprint(finding, survey, uri),
        },
        "properties": _properties(finding, outside),
    }
    if finding.rule_id in rule_index:
        result["ruleIndex"] = rule_index[finding.rule_id]

    location: dict[str, Any] = {}
    physical = physical_location(
        finding.location,
        target=target,
        survey=survey,
        workspace=workspace,
        evidence=finding.evidence,
    )
    if physical is not None:
        location["physicalLocation"] = physical
    if finding.location.pointer is not None:
        location["logicalLocations"] = [{"fullyQualifiedName": finding.location.pointer}]
    if location:
        result["locations"] = [location]

    related: list[dict[str, Any]] = []
    for other in finding.related:
        physical = physical_location(
            other, target=target, survey=survey, workspace=workspace
        )
        if physical is not None:
            related.append({"physicalLocation": physical})
    if related:
        result["relatedLocations"] = related

    return result


# ---------------------------------------------------------------------------
# the document
# ---------------------------------------------------------------------------
def _notifications(coverage: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Coverage as SARIF says it: what the analysis could not do.

    ``toolExecutionNotifications`` rather than ``toolConfigurationNotifications``
    -- nothing about the configuration is wrong when MCP-003 skips a target with
    no source, or when a file will not parse. A rule pack that fails to load is
    a configuration problem, and that path exits 2 before a report exists.
    """
    notifications: list[dict[str, Any]] = []
    for entry in coverage["rules_skipped"]:
        notifications.append(
            {
                "level": "note",
                "message": {"text": f"{entry['rule_id']} did not run: {entry['reason']}"},
                "associatedRule": {"id": entry["rule_id"]},
            }
        )
    for entry in coverage["unparsed"]:
        notifications.append(
            {
                "level": "warning",
                "message": {"text": f"{entry['path']} was not analysed: {entry['reason']}"},
            }
        )
    for entry in coverage["notes"]:
        notifications.append({"level": "note", "message": {"text": entry["detail"]}})
    return notifications


def build(
    results: Sequence[tuple[Target, AnalysisResult]],
    *,
    rules: RuleSet,
    fail_on: Severity,
    surveys: Mapping[str, WrittenSurvey] | None = None,
    workspace: Path | None = None,
    errors: Sequence[str] = (),
    generated_at: str | None = None,
) -> dict[str, Any]:
    """The whole SARIF log as a plain dict."""
    surveys = surveys or {}
    workspace = workspace or Path.cwd()

    findings = sorted_findings(results)
    coverage = coverage_json(results)
    descriptors = driver_rules(rules, findings)
    rule_index = {str(descriptor["id"]): index for index, descriptor in enumerate(descriptors)}
    # `sorted_findings` flattens every target into one worst-first list, which is
    # the order `report.build` uses; walking it keeps the two formats listing one
    # scan's findings identically. The map back to a target is by identity, since
    # two targets can produce equal findings and only one of them owns each.
    owner = {id(finding): target for target, result in results for finding in result.findings}

    entries: list[dict[str, Any]] = []
    for finding in findings:
        target = owner[id(finding)]
        entries.append(
            result_json(
                finding,
                target=target,
                survey=surveys.get(target.label),
                workspace=workspace,
                rule_index=rule_index,
            )
        )

    dropped = 0
    if len(entries) > MAX_RESULTS:
        dropped = len(entries) - MAX_RESULTS
        entries = entries[:MAX_RESULTS]

    invocation: dict[str, Any] = {
        # False when a target could not be scanned at all. A consumer that
        # uploads this anyway is publishing a partial run as if it were whole,
        # which is why the shipped workflow refuses to upload on exit 2.
        "executionSuccessful": not errors,
    }
    if generated_at is not None:
        invocation["endTimeUtc"] = generated_at
    notifications = _notifications(coverage)
    if errors:
        notifications = [
            {"level": "error", "message": {"text": problem}} for problem in errors
        ] + notifications
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    properties: dict[str, Any] = {
        "coverage": coverage,
        "summary": summarise(findings, fail_on),
        "targets": [target_json(target) for target, _ in results],
    }
    if dropped:
        properties["truncated"] = (
            f"{dropped} further result(s) omitted: SARIF uploads are capped at "
            f"{MAX_RESULTS} per run."
        )

    return {
        "$schema": SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": descriptors,
                    }
                },
                "columnKind": "utf16CodeUnits",
                "invocations": [invocation],
                "results": entries,
                "properties": properties,
            }
        ],
    }


def render(
    results: Sequence[tuple[Target, AnalysisResult]],
    *,
    rules: RuleSet,
    fail_on: Severity,
    surveys: Mapping[str, WrittenSurvey] | None = None,
    workspace: Path | None = None,
    errors: Sequence[str] = (),
    generated_at: str | None = None,
) -> str:
    payload = build(
        results,
        rules=rules,
        fail_on=fail_on,
        surveys=surveys,
        workspace=workspace,
        errors=errors,
        generated_at=generated_at,
    )
    return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"
