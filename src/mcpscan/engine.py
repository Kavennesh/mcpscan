"""The pattern-rule engine: matching, the closed hook registries, and the timeout.

Step 4 wrote MCP-001 and MCP-002 as code so this file could be *derived* from two
real rules rather than guessed at. What survived that derivation is here; what did
not is now a YAML file. The two rules shared traversal, field selection, span
arithmetic and location handling -- all of which is :class:`PatternRule` -- and
differed in exactly three ways, each of which is now a named registry entry.

**Contributor regexes are untrusted input**, and the defence is the per-match
timeout, not a static check. ``regex`` supports ``timeout=`` on ``finditer``, so a
catastrophic pattern is interrupted mid-backtrack with no threads and no signals.
On timeout the pattern is *quarantined* for the rest of the scan: retrying it on
every one of thousands of fields would turn a slow rule into the denial of service
the timeout exists to prevent. The scan finishes and says what did not run.

Static nested-quantifier detection is advisory only, and deliberately so. Of five
classic catastrophic patterns tried against this engine, four were optimised away
and one was not -- so a static check would have warned about four harmless
patterns and told the truth about one. That is a linter, not a control.

.. warning::

   ``regex`` raises the **builtin** ``TimeoutError``, which is an ``OSError``
   subclass on Python 3.11+. A broad ``except OSError`` anywhere on the matching
   path silently swallows it and switches the defence off.
   ``tests/test_engine_timeout.py`` pins this.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol

import regex

from mcpscan.document import FieldKind, MetadataDocument, TextField, walk_text
from mcpscan.models import Confidence, Finding, Severity, Span
from mcpscan.predicates import (
    always,
    format_char_is_illegitimate,
    report_codepoints,
    report_nothing,
)

#: Per pattern, per field. Generous for any honest regex over a description and
#: far too short to hang a scan.
RULE_MATCH_TIMEOUT_S: Final = 0.25

Predicate = Callable[[str, int], bool]
Reporter = Callable[[TextField, str, Span, Predicate], "dict[str, Any] | None"]


class MatchMode(StrEnum):
    """How a rule turns matches into findings."""

    #: One finding per match. What MCP-002 does and what a contributed rule wants.
    SPANS = "spans"
    #: Coalesce adjacent matches into runs and let an earlier pattern claim
    #: characters before a later one sees them. What MCP-001 needs: a
    #: 200-character tag payload is one problem, and a bidi control must be
    #: reported once as a bidi control rather than twice, once as a bare `\p{Cf}`.
    COALESCED_RUNS = "coalesced_runs"


#: The closed registries. A rule file may name an entry; it can never define one.
PREDICATES: Final[dict[str, Predicate]] = {
    "none": always,
    "format_char_is_illegitimate": format_char_is_illegitimate,
}

REPORTERS: Final[dict[str, Reporter]] = {
    "none": report_nothing,
    "codepoints": report_codepoints,
}


class RuleError(Exception):
    """A rule could not be loaded. Ours or a contributor's, never a target's."""


@dataclass(frozen=True, slots=True)
class RuleMeta:
    id: str
    title: str
    severity: Severity
    remediation: str

    @property
    def help_uri(self) -> str:
        """Where the rule is documented. By convention, so it cannot rot."""
        return f"docs/rules/{self.id}.md"


@dataclass(frozen=True, slots=True)
class CoverageNote:
    """Something the scan could not do. Never a finding -- see anomalies.py."""

    kind: str
    detail: str


class ScanState:
    """Per-scan mutable state: what got quarantined, and what to tell the user.

    Passed explicitly rather than held on the rule, because a rule object is
    shared across targets and quarantine is a property of one scan.
    """

    __slots__ = ("notes", "quarantined")

    def __init__(self) -> None:
        self.quarantined: set[tuple[str, str]] = set()
        self.notes: list[CoverageNote] = []

    def is_quarantined(self, rule_id: str, pattern_name: str) -> bool:
        return (rule_id, pattern_name) in self.quarantined

    def quarantine(self, rule_id: str, pattern_name: str, where: str) -> None:
        key = (rule_id, pattern_name)
        if key in self.quarantined:
            return
        self.quarantined.add(key)
        self.notes.append(
            CoverageNote(
                kind="pattern_timeout",
                detail=(
                    f"{rule_id}/{pattern_name} exceeded {RULE_MATCH_TIMEOUT_S}s on "
                    f"{where} and was disabled for the rest of this scan; "
                    "results for that pattern are incomplete"
                ),
            )
        )

    def note(self, kind: str, detail: str) -> None:
        self.notes.append(CoverageNote(kind=kind, detail=detail))


@dataclass(frozen=True, slots=True)
class Pattern:
    """One detection, with its own confidence and its own explanation.

    Confidence is per-pattern rather than per-rule because the tiers within a
    rule differ far more than the rules do: ``<IMPORTANT>`` in a description is
    unambiguous, a second-person imperative is a hint. Step 4 called this the
    load-bearing part of the schema, and it survived derivation unchanged.
    """

    name: str
    expression: str
    confidence: Confidence
    message: str
    #: When set, the pattern only applies to these field kinds.
    kinds: frozenset[FieldKind] | None = None
    #: When set, the pattern is skipped for these field kinds. This is what
    #: carries MCP-002's `instructions` exemption -- an imperative in the field
    #: whose whole purpose is to address the model is that field doing its job.
    exclude_kinds: frozenset[FieldKind] = frozenset()

    def applies_to(self, kind: FieldKind) -> bool:
        if kind in self.exclude_kinds:
            return False
        return self.kinds is None or kind in self.kinds


@dataclass(frozen=True, slots=True)
class CompiledPattern:
    """A pattern with its regex compiled once, at load time."""

    spec: Pattern
    compiled: regex.Pattern[str]

    def finditer(self, text: str, timeout: float) -> list[tuple[int, int]] | None:
        """Match spans, or ``None`` if the pattern exceeded its budget.

        ``TimeoutError`` is caught by name. Never widen this to ``OSError``:
        ``TimeoutError`` is a subclass of it, and the broader clause would make
        a catastrophic pattern indistinguishable from a missing file.
        """
        try:
            return [m.span() for m in self.compiled.finditer(text, timeout=timeout)]
        except TimeoutError:
            return None


def compile_pattern(spec: Pattern, *, rule_id: str) -> CompiledPattern:
    try:
        compiled = regex.compile(spec.expression, regex.IGNORECASE | regex.VERSION1)
    except regex.error as exc:
        raise RuleError(f"{rule_id}/{spec.name}: regex does not compile: {exc}") from exc
    return CompiledPattern(spec=spec, compiled=compiled)


class PatternRule:
    """Apply a pattern list to every text field a model can see.

    Instantiated from YAML by :mod:`mcpscan.ruleloader`; there is no subclassing
    front-door any more, so the built-in rules and a contributed one travel the
    same path and the YAML path cannot rot behind a privileged one.
    """

    def __init__(
        self,
        meta: RuleMeta,
        patterns: Sequence[CompiledPattern],
        *,
        match_mode: MatchMode = MatchMode.SPANS,
        predicate: str = "none",
        reporter: str = "none",
    ) -> None:
        self.meta = meta
        self.patterns = tuple(patterns)
        self.match_mode = match_mode
        self.predicate_name = predicate
        self.reporter_name = reporter
        try:
            self.predicate = PREDICATES[predicate]
            self.reporter = REPORTERS[reporter]
        except KeyError as exc:
            raise RuleError(
                f"{meta.id}: unknown hook {exc.args[0]!r}. "
                f"predicates: {sorted(PREDICATES)}; reporters: {sorted(REPORTERS)}"
            ) from exc

    # -- driving --------------------------------------------------------
    def check(
        self, doc: MetadataDocument, state: ScanState | None = None
    ) -> Iterator[Finding]:
        state = state if state is not None else ScanState()
        for field_ in walk_text(doc):
            yield from self.check_field(field_, state)

    def check_field(
        self, field_: TextField, state: ScanState | None = None
    ) -> Iterator[Finding]:
        state = state if state is not None else ScanState()
        if self.match_mode is MatchMode.COALESCED_RUNS:
            yield from self._coalesced(field_, state)
        else:
            yield from self._spans(field_, state)

    def _spans(self, field_: TextField, state: ScanState) -> Iterator[Finding]:
        for pattern in self._applicable(field_, state):
            spans = self._match(pattern, field_, state)
            for start, end in spans:
                if start == end:
                    continue
                finding = self._build(field_, pattern.spec, start, end)
                if finding is not None:
                    yield finding

    def _coalesced(self, field_: TextField, state: ScanState) -> Iterator[Finding]:
        """Earlier patterns claim characters, so the specific one wins.

        Bidi controls are format characters too. Without claiming, a single
        override is reported twice -- once at HIGH as what it is, once at MEDIUM
        as a bare ``\\p{Cf}`` -- and a reader has to work out they are the same
        character.
        """
        claimed: set[int] = set()
        for pattern in self._applicable(field_, state):
            for start, end in self._match(pattern, field_, state):
                if start == end or any(i in claimed for i in range(start, end)):
                    continue
                finding = self._build(field_, pattern.spec, start, end)
                if finding is not None:
                    claimed.update(range(start, end))
                    yield finding

    def _applicable(
        self, field_: TextField, state: ScanState
    ) -> Iterator[CompiledPattern]:
        for pattern in self.patterns:
            if not pattern.spec.applies_to(field_.kind):
                continue
            if state.is_quarantined(self.meta.id, pattern.spec.name):
                continue
            yield pattern

    def _match(
        self, pattern: CompiledPattern, field_: TextField, state: ScanState
    ) -> list[tuple[int, int]]:
        spans = pattern.finditer(field_.text, RULE_MATCH_TIMEOUT_S)
        if spans is None:
            state.quarantine(self.meta.id, pattern.spec.name, field_.pointer)
            return []
        return spans

    def _build(
        self, field_: TextField, pattern: Pattern, start: int, end: int
    ) -> Finding | None:
        span = Span.of(field_.text, start, end)
        extra = self.reporter(field_, pattern.name, span, self.predicate)
        if extra is None:
            return None
        location = field_.locate().model_copy(update={"span": span})
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            confidence=pattern.confidence,
            message=pattern.message,
            location=location,
            evidence=span.excerpt(field_.text),
            remediation=self.meta.remediation,
            help_uri=self.meta.help_uri,
            metadata={"pattern": pattern.name, "field": field_.kind.value, **extra},
        )


class SourceRule(Protocol):
    """A rule that reads the target's code. MCP-003 only, and it stays code."""

    meta: RuleMeta

    def check(self, tree: Any, tools: Sequence[Any]) -> Iterator[Finding]: ...


@dataclass(frozen=True, slots=True)
class RuleSet:
    metadata_rules: tuple[PatternRule, ...] = ()
    source_rules: tuple[SourceRule, ...] = ()

    def ids(self) -> list[str]:
        return [r.meta.id for r in self.metadata_rules] + [
            r.meta.id for r in self.source_rules
        ]

    def by_id(self, rule_id: str) -> PatternRule | SourceRule | None:
        for pattern_rule in self.metadata_rules:
            if pattern_rule.meta.id == rule_id:
                return pattern_rule
        for source_rule in self.source_rules:
            if source_rule.meta.id == rule_id:
                return source_rule
        return None


# --------------------------------------------------------------------------
# advisory lint -- a hint for contributors, never a control
# --------------------------------------------------------------------------
_NESTED_QUANTIFIER = regex.compile(r"\([^)]*[+*]\)[+*]|\(([^|)]+)\|\1\)[+*]")


def lint_expression(expression: str) -> list[str]:
    """Shapes worth a second look before merging. Advisory only.

    Never blocks a load or a scan. This engine optimises away most textbook
    catastrophic patterns and not others, so a static check produces both false
    alarms and false confidence. The timeout is the control; this is a nudge to
    the contributor writing the rule.
    """
    warnings: list[str] = []
    if _NESTED_QUANTIFIER.search(expression):
        warnings.append(
            "nested quantifier -- a quantified group inside another quantifier "
            "can backtrack catastrophically on non-matching input"
        )
    if expression.count("(") > 12:
        warnings.append("more than twelve groups -- consider splitting the pattern")
    return warnings


@dataclass(frozen=True, slots=True)
class RuleCase:
    """One test case from a rule file, with the field it is presented as.

    The field kind is carried rather than assumed: MCP-002's `instructions`
    exemption can only be tested by presenting the same sentence as two different
    kinds and asserting it fires in one and not the other.
    """

    text: str
    kind: FieldKind = FieldKind.TOOL_DESCRIPTION
    expect: str | None = None


@dataclass(frozen=True, slots=True)
class RuleTests:
    """The cases a rule file must carry. A rule without a negative case fails CI."""

    positive: tuple[RuleCase, ...] = ()
    negative: tuple[RuleCase, ...] = ()


@dataclass(frozen=True, slots=True)
class LoadedRule:
    """A rule plus the tests and provenance the CI gate needs."""

    rule: PatternRule
    tests: RuleTests
    source: str = "<builtin>"
