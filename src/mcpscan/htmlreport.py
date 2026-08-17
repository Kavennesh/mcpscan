"""The HTML report: one self-contained file, safe to open.

The other three formats each have an audience that is not a person reading in a
browser -- a terminal, a script, a code-scanning tab. This is the artefact you
attach to a ticket or hand to whoever owns the server, and being that means two
properties the others never had to have.

**Nothing leaves the page.** No script, no stylesheet link, no font, no image, no
`fetch`. A security tool that phones a third party when its report is opened is
the first thing anyone will point at, and "it was only a font" is not an answer.
The stylesheet is inlined and static; there is no JavaScript at all, so there is
nothing for a reviewer to audit and nothing that can be turned against the reader.

**Escaping is a security property here, not a formatting one.** Every description,
tool name, server-info string and evidence excerpt in a report is text the target
chose. jinja2's ``Environment`` defaults ``autoescape`` to False, so the single
most load-bearing line in this module is the one that turns it on -- and the rule
that keeps it load-bearing is that **no markup is ever constructed in Python**.
Interleaving text with badges is done by handing the template a list of
:class:`Segment` and letting it emit each one, never by building a string and
marking it safe. ``tests/test_html_report.py`` enforces that by grepping this
module and the template for ``Markup`` and ``|safe``.

There is a third problem the other formats do not have, and it is not XSS.
A raw U+202E in an HTML text node does not render as nothing -- it **reorders the
report text around it**. A description carrying one can rearrange how a finding
reads in a browser: swap the severity onto another rule, hide a sentence behind
its neighbour. So every attacker-controlled string is passed through
:func:`segments`, which replaces each invisible or format character with a visible
badge naming it. That is also what makes MCP-001 legible at last, since its
evidence *is* those characters and nothing else.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Final

from jinja2 import Environment, StrictUndefined

from mcpscan import __version__
from mcpscan.analyser import AnalysisResult
from mcpscan.catalogue import rule_catalogue
from mcpscan.document import SurveyArtefact
from mcpscan.engine import RuleSet
from mcpscan.models import Finding, Severity, Target
from mcpscan.predicates import is_legitimate_format_char
from mcpscan.report import TOOL_NAME, coverage_json, now_utc, summarise, target_json

#: Where the template lives, as a package resource so it survives pip install.
TEMPLATE_PACKAGE: Final = "mcpscan.templates"
TEMPLATE_NAME: Final = "report.html.j2"

#: Unicode general categories whose members must never reach the page as
#: themselves. ``Cf`` is the interesting one -- bidi overrides, zero-width
#: spaces, tag characters -- but the rest matter too:
#:
#: * ``Cc`` control characters, which a terminal-shaped payload arrives as;
#: * ``Co``/``Cn`` private-use and unassigned, which render as tofu at best;
#: * ``Cs`` lone surrogates, which ``json.loads`` accepts off the wire and UTF-8
#:   cannot encode. Writing one to the report file raises `UnicodeEncodeError`,
#:   so badging it is not cosmetic -- it is why this format survives an input
#:   that still crashes `--format json`.
INVISIBLE_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cn", "Co", "Cs"})

#: Not a format character by category, but invisible and used the same way.
INVISIBLE_EXTRA: Final = frozenset({"͏"})

#: Only an absolute https URL is ever emitted as a link. `RuleMeta.help_uri` is
#: derived from a rule id the loader constrains, but `Finding.help_uri` is a
#: plain `str` on the model, and a scheme is not something a future rule should
#: be able to choose. Note `targets.from_client_config` does *not* validate the
#: scheme of a config's `url`, so `Target.url` -- and therefore the `detail` in
#: a target header -- can be `javascript:`. It is rendered as text, never a link.
SAFE_LINK_PREFIX: Final = "https://"

#: How much of a field to show around a flagged character, and how far before
#: the first one to start. A server does not get to choose the size of the
#: report -- the same argument as `models.EVIDENCE_CHARS`, one layer out.
CONTEXT_CHARS: Final = 600
CONTEXT_MARGIN: Final = 120

#: A coalesced run can flag hundreds of characters. The table names the first
#: few; the badges in the text already show every one of them in place.
MAX_CHARACTER_ROWS: Final = 40

#: Cap for any single attacker string drawn outside the context window.
MAX_DISPLAY_CHARS: Final = 2000

ELIDED: Final = " […]"


def _clamp(text: str) -> str:
    return text if len(text) <= MAX_DISPLAY_CHARS else text[:MAX_DISPLAY_CHARS] + ELIDED


@dataclass(frozen=True, slots=True)
class Segment:
    """One piece of a display string: readable text, or one named character."""

    text: str = ""
    #: Set when this segment is a single invisible character.
    codepoint: str = ""
    name: str = ""
    category: str = ""
    #: True when a rule named this exact position, as opposed to the character
    #: merely being present. Lets the template distinguish the payload MCP-001
    #: found from a legitimate ZWNJ sitting elsewhere in the same sentence.
    flagged: bool = False

    @property
    def is_char(self) -> bool:
        return bool(self.codepoint)


def is_invisible(char: str) -> bool:
    return unicodedata.category(char) in INVISIBLE_CATEGORIES or char in INVISIBLE_EXTRA


def describe_char(char: str) -> tuple[str, str, str]:
    """Codepoint, name and category for one character.

    ``unicodedata.name`` raises for unassigned and tag characters, which are
    exactly the ones worth naming, so the fallback is not a rare path.
    """
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = "unnamed"
    return f"U+{ord(char):04X}", name, unicodedata.category(char)


def segments(text: str, flagged: frozenset[int] = frozenset()) -> list[Segment]:
    """Split attacker-controlled text into readable runs and named characters.

    ``flagged`` holds offsets *into this string* that a rule called out. Callers
    working from `metadata["characters"]` have to get that right: ``char_offset``
    is absolute within the whole field, so it indexes the field text directly but
    needs ``span.start`` subtracted to index an evidence excerpt.
    """
    out: list[Segment] = []
    run: list[str] = []

    for index, char in enumerate(text):
        # A character the rule named is always badged. One that merely happens
        # to be here is badged unless it is doing the job it exists for -- the
        # same question MCP-001 asks, answered by the same code, so a family
        # emoji stays an emoji and a Persian ZWNJ stays orthography instead of
        # every clean report being shredded into badges.
        if not is_invisible(char) or (
            index not in flagged and is_legitimate_format_char(text, index)
        ):
            run.append(char)
            continue
        if run:
            out.append(Segment(text="".join(run)))
            run = []
        codepoint, name, category = describe_char(char)
        out.append(
            Segment(
                codepoint=codepoint,
                name=name,
                category=category,
                flagged=index in flagged,
            )
        )

    if run:
        out.append(Segment(text="".join(run)))
    return out


@dataclass(frozen=True, slots=True)
class DiffLine:
    marker: str
    segments: list[Segment]


@dataclass(frozen=True, slots=True)
class EvidenceView:
    """How one finding's evidence should be drawn.

    Exactly one of the three is populated. The template branches on ``kind``
    rather than on a rule id, so a contributed rule using the same reporter is
    rendered the same way without naming it anywhere.
    """

    kind: str = "plain"
    #: kind == "plain" or "codepoints": the text, already segmented.
    body: list[Segment] = field(default_factory=list)
    #: kind == "codepoints": the characters a rule named, for the table.
    characters: list[dict[str, Any]] = field(default_factory=list)
    #: kind == "codepoints": True when `body` is the whole field rather than
    #: just the matched run, so the template can say which it is showing.
    in_context: bool = False
    #: kind == "diff".
    lines: list[DiffLine] = field(default_factory=list)


def _diff_view(finding: Finding) -> EvidenceView:
    """The two halves of a rug pull, from metadata rather than from `evidence`.

    Never by splitting the flattened `- old\\n+ new` string. That form is capped
    at `EVIDENCE_CHARS`, so a 300-character description loses the `+` row and the
    diff quietly becomes a one-sided quote; and a server that puts a newline and
    a `+ ` in its own description writes a diff row of its own. Reading the two
    halves as separate values makes both impossible: whatever they contain, they
    are one row each.
    """
    lines: list[DiffLine] = []
    for marker, key in (("-", "before"), ("+", "after")):
        value = finding.metadata.get(key)
        if isinstance(value, str):
            lines.append(DiffLine(marker=marker, segments=segments(_clamp(value))))
    if not lines:
        # A drift with neither half recorded -- an appeared or vanished tool.
        return EvidenceView(kind="plain", body=segments(_clamp(finding.evidence or "")))
    return EvidenceView(kind="diff", lines=lines)


def _codepoint_view(finding: Finding, survey: SurveyArtefact | None) -> EvidenceView:
    """The characters a rule flagged, shown where they sit.

    Prefers the whole field over the matched run, because the run *is* the
    invisible characters -- a payload shown on its own says what was found but
    not what it was hiding inside.
    """
    characters = [c for c in finding.metadata.get("characters", []) if isinstance(c, dict)]
    pointer = finding.location.pointer

    anchor = survey.anchor_for(pointer) if survey is not None and pointer else None
    if anchor is not None and anchor.text is not None and anchor.exact:
        # `char_offset` is absolute within the field, and this text *is* the
        # field, so the offsets index it directly. `exact` is False whenever
        # redaction rewrote the value, which is also the only case where
        # `Anchor.text` -- the pre-redaction original -- would print a canary.
        text, offset = _window(anchor.text, characters)
        flagged = frozenset(
            position - offset
            for entry in characters
            if isinstance(position := entry.get("char_offset"), int)
        )
        return EvidenceView(
            kind="codepoints",
            body=segments(text, flagged),
            characters=characters[:MAX_CHARACTER_ROWS],
            in_context=True,
        )

    # The fallback. Offsets are *not* trusted here: this branch is reached when
    # redaction rewrote the evidence without adjusting them, and a coalesced run
    # can also carry offsets past the 240-character truncation. `segments` finds
    # every invisible character by inspection anyway, so the honest degradation
    # is to badge them all and claim none of them is the one the rule named.
    return EvidenceView(
        kind="codepoints",
        body=segments(_clamp(finding.evidence or "")),
        characters=characters[:MAX_CHARACTER_ROWS],
        in_context=False,
    )


def _window(text: str, characters: Sequence[Mapping[str, Any]]) -> tuple[str, int]:
    """A bounded slice of a field, centred on the characters a rule flagged.

    `Anchor.text` is the original string, uncapped -- up to `jsonrpc`'s line
    limit. Rendering that in full, once per finding, would hand a server the
    size of the report, which `EVIDENCE_CHARS`, `MAX_ARTEFACT_VALUE_CHARS` and
    `FIELD_SAMPLE_CHARS` each already refused it elsewhere. It also composes
    badly with badging: a field of 100k format characters is 100k spans.
    """
    offsets = [
        position
        for entry in characters
        if isinstance(position := entry.get("char_offset"), int)
    ]
    if len(text) <= CONTEXT_CHARS:
        return text, 0
    first = min(offsets) if offsets else 0
    start = max(0, first - CONTEXT_MARGIN)
    return text[start : start + CONTEXT_CHARS], start


def evidence_view(finding: Finding, survey: SurveyArtefact | None = None) -> EvidenceView:
    """Pick how to draw this finding's evidence. Dispatches on metadata."""
    if finding.metadata.get("probe") == "rug_pull":
        return _diff_view(finding)
    if finding.metadata.get("characters"):
        return _codepoint_view(finding, survey)
    return EvidenceView(kind="plain", body=segments(_clamp(finding.evidence or "")))


@dataclass(frozen=True, slots=True)
class RenderedFinding:
    """One finding, reduced to what the template draws."""

    rule_id: str
    title: list[Segment]
    severity: str
    confidence: str
    message: list[Segment]
    path: str
    lines: str
    pointer: str
    evidence: EvidenceView
    remediation: list[Segment]
    help_uri: str
    related: list[str]
    metadata: list[tuple[str, list[Segment]]]

    @property
    def has_link(self) -> bool:
        return self.help_uri.startswith(SAFE_LINK_PREFIX)


def _lines_of(finding: Finding) -> str:
    start = finding.location.start_line
    if start is None:
        return ""
    end = finding.location.end_line
    return f"{start}" if end is None or end == start else f"{start}-{end}"


def _metadata_rows(finding: Finding) -> list[tuple[str, list[Segment]]]:
    """Metadata as label/value pairs, every value segmented.

    `characters` is dropped: the codepoint view already draws it as a table, and
    a raw dump beside it is noise. Everything else is rendered as text, because
    a tool name or a traversal payload in here is as attacker-chosen as anything
    in a description.
    """
    rows: list[tuple[str, list[Segment]]] = []
    for key in sorted(finding.metadata):
        if key == "characters":
            continue
        value = finding.metadata[key]
        shown = ", ".join(str(item) for item in value) if isinstance(value, list) else str(value)
        rows.append((key, segments(shown)))
    return rows


def render_finding(finding: Finding, survey: SurveyArtefact | None) -> RenderedFinding:
    return RenderedFinding(
        rule_id=finding.rule_id,
        title=segments(finding.title),
        severity=finding.severity.value,
        confidence=finding.confidence.value,
        message=segments(finding.message),
        path=str(finding.location.path) if finding.location.path is not None else "",
        lines=_lines_of(finding),
        pointer=finding.location.pointer or "",
        evidence=evidence_view(finding, survey),
        remediation=segments(finding.remediation),
        help_uri=finding.help_uri,
        related=[location.describe() for location in finding.related],
        metadata=_metadata_rows(finding),
    )


@dataclass(frozen=True, slots=True)
class RenderedTarget:
    label: list[Segment]
    kind: str
    detail: list[Segment]
    files_scanned: int
    #: What the server claimed about itself, from the survey. Unverified, and
    #: worth showing precisely because it is unverified.
    server_info: list[tuple[str, list[Segment]]]
    findings: list[RenderedFinding]
    actionable: int


def _server_info(survey: SurveyArtefact | None) -> list[tuple[str, list[Segment]]]:
    if survey is None:
        return []
    rows: list[tuple[str, list[Segment]]] = []
    for key in ("name", "title", "version"):
        anchor = survey.anchor_for(f"#/serverInfo/{key}")
        if anchor.text is not None:
            rows.append((key, segments(anchor.text)))
    return rows


def build(
    results: Sequence[tuple[Target, AnalysisResult]],
    *,
    rules: RuleSet,
    fail_on: Severity,
    surveys: Mapping[str, SurveyArtefact] | None = None,
    errors: Sequence[str] = (),
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Everything the template needs, and nothing it has to reach for."""
    surveys = surveys or {}
    findings = [f for _, result in results for f in result.findings]

    targets: list[RenderedTarget] = []
    for target, result in results:
        survey = surveys.get(target.label)
        detail = target_json(target)
        ordered = sorted(result.findings, key=lambda f: f.sort_key)
        targets.append(
            RenderedTarget(
                label=segments(target.label),
                kind=detail["kind"],
                detail=segments(detail["detail"]),
                files_scanned=result.files_scanned,
                server_info=_server_info(survey),
                findings=[render_finding(f, survey) for f in ordered],
                actionable=len(result.at_or_above(fail_on)),
            )
        )

    fired = {f.rule_id for f in findings}
    coverage = coverage_json(results)
    ran = set(coverage["rules_run"])
    # Why a rule did not run, when the scan knows. A rule that is in neither
    # set was simply not applicable to these targets -- MCP-007 on a --path
    # scan, say -- which is a third state and not the same as being skipped.
    reasons = {entry["rule_id"]: entry["reason"] for entry in coverage["rules_skipped"]}

    catalogue = [
        {
            "id": entry.meta.id,
            "title": entry.meta.title,
            "family": entry.family.value,
            "severity": entry.meta.severity.value,
            "ran": entry.meta.id in ran,
            "reason": reasons.get(entry.meta.id, ""),
            "findings": sum(1 for f in findings if f.rule_id == entry.meta.id),
            # Guarded the same way a finding's link is. A bundled rule's URI is
            # derived from a regex-constrained id and cannot be anything else
            # today; making the template's two href sites behave differently is
            # how that stops being true later.
            "link": (
                entry.meta.help_uri
                if entry.meta.help_uri.startswith(SAFE_LINK_PREFIX)
                else ""
            ),
            "fired": entry.meta.id in fired,
        }
        for entry in rule_catalogue(rules)
    ]

    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated_at": generated_at if generated_at is not None else now_utc(),
        "fail_on": fail_on.value,
        "summary": summarise(findings, fail_on),
        "severities": [severity.value for severity in Severity],
        "coverage": coverage,
        "errors": [segments(problem) for problem in errors],
        "targets": targets,
        "catalogue": catalogue,
    }


def environment() -> Environment:
    """The one place autoescaping is configured.

    ``autoescape=True`` is not a default and is the whole security posture of
    this format. ``StrictUndefined`` so a template typo is a loud failure rather
    than a silently empty finding.
    """
    return Environment(autoescape=True, undefined=StrictUndefined, trim_blocks=True)


def template_text() -> str:
    """The template, from package data. Never `__file__`-relative -- see rules/."""
    return (
        resources.files(TEMPLATE_PACKAGE)
        .joinpath(TEMPLATE_NAME)
        .read_text(encoding="utf-8")
    )


def render(
    results: Sequence[tuple[Target, AnalysisResult]],
    *,
    rules: RuleSet,
    fail_on: Severity,
    surveys: Mapping[str, SurveyArtefact] | None = None,
    errors: Sequence[str] = (),
    generated_at: str | None = None,
) -> str:
    payload = build(
        results,
        rules=rules,
        fail_on=fail_on,
        surveys=surveys,
        errors=errors,
        generated_at=generated_at,
    )
    rendered = environment().from_string(template_text()).render(**payload)
    return rendered if rendered.endswith("\n") else rendered + "\n"
