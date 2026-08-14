"""Loading and validating rule files.

The schema here was derived from :class:`~mcpscan.engine.PatternRule`, which
MCP-001 and MCP-002 already shared before either was a file. Everything in it
exists because one of those two rules needed it -- ``exclude_kinds`` carries
MCP-002's ``instructions`` exemption, ``match_mode`` and ``reporter`` carry
MCP-001's run coalescing and codepoint table -- so no field is speculative.

Three properties of the loader do real work:

**Unknown keys are rejected.** ``extra="forbid"`` everywhere, so a rule file with
``confidance: high`` fails at load naming the file and the field, rather than
silently defaulting to something the contributor did not intend and never notices.

**Tests are part of the schema, not a convention.** ``tests.positive`` and
``tests.negative`` are required and must be non-empty. A rule whose author never
wrote down what it must *not* match is a rule nobody can safely change later, and
this is where "a rule PR without a negative case fails the build" is enforced --
one `min_length=1`, checked by the same code path for bundled and third-party
packs alike.

**Third-party rules cannot claim a bundled id.** ``MCP-`` is reserved. A rule pack
that could shadow ``MCP-001`` could silently weaken it.

``yaml.safe_load`` only. A rule file is contributor-supplied data and must not be
able to construct Python objects.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from importlib import resources
from pathlib import Path
from typing import Annotated

import regex
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mcpscan.document import FieldKind
from mcpscan.engine import (
    PREDICATES,
    REPORTERS,
    CompiledPattern,
    LoadedRule,
    MatchMode,
    Pattern,
    PatternRule,
    RuleCase,
    RuleError,
    RuleMeta,
    RuleTests,
    compile_pattern,
)
from mcpscan.models import Confidence, Severity

#: Where the bundled pack lives, as a package resource so it survives pip install.
BUILTIN_PACKAGE = "mcpscan.rules"

#: Reserved for rules shipped with mcpscan.
BUILTIN_PREFIX = "MCP-"

_BUILTIN_ID = regex.compile(r"^MCP-\d{3}$")
_THIRD_PARTY_ID = regex.compile(r"^[A-Z][A-Z0-9]{1,15}-\d{3}$")


class PatternSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1)]
    regex: Annotated[str, Field(min_length=1)]
    confidence: Confidence
    message: Annotated[str, Field(min_length=1)]
    kinds: list[FieldKind] | None = None
    exclude_kinds: list[FieldKind] = Field(default_factory=list)

    def to_pattern(self) -> Pattern:
        return Pattern(
            name=self.name,
            expression=self.regex,
            confidence=self.confidence,
            message=self.message,
            kinds=frozenset(self.kinds) if self.kinds is not None else None,
            exclude_kinds=frozenset(self.exclude_kinds),
        )


class PositiveCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: Annotated[str, Field(min_length=1)]
    #: Which pattern must fire. Optional, but naming it turns "something matched"
    #: into a test that survives someone adding a second pattern.
    expect: str | None = None
    #: Which field kind to present the text as. Defaults to a tool description,
    #: the field these rules exist for.
    kind: FieldKind = FieldKind.TOOL_DESCRIPTION


class NegativeCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: Annotated[str, Field(min_length=1)]
    kind: FieldKind = FieldKind.TOOL_DESCRIPTION


class TestsSpec(BaseModel):
    """Both lists are required and non-empty. This is the CI gate, in one place."""

    model_config = ConfigDict(extra="forbid")

    positive: Annotated[list[PositiveCase], Field(min_length=1)]
    negative: Annotated[list[NegativeCase], Field(min_length=1)]


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: Annotated[str, Field(min_length=1)]
    title: Annotated[str, Field(min_length=1)]
    severity: Severity
    remediation: Annotated[str, Field(min_length=1)]
    patterns: Annotated[list[PatternSpec], Field(min_length=1)]
    tests: TestsSpec
    match_mode: MatchMode = MatchMode.SPANS
    predicate: str = "none"
    reporter: str = "none"

    @field_validator("id")
    @classmethod
    def _well_formed_id(cls, value: str) -> str:
        if _BUILTIN_ID.match(value) or _THIRD_PARTY_ID.match(value):
            return value
        raise ValueError(
            f"{value!r} is not a valid rule id. Bundled rules are MCP-NNN; "
            "third-party rules use another prefix, e.g. ACME-001."
        )

    @field_validator("predicate")
    @classmethod
    def _known_predicate(cls, value: str) -> str:
        if value not in PREDICATES:
            raise ValueError(f"unknown predicate {value!r}; known: {sorted(PREDICATES)}")
        return value

    @field_validator("reporter")
    @classmethod
    def _known_reporter(cls, value: str) -> str:
        if value not in REPORTERS:
            raise ValueError(f"unknown reporter {value!r}; known: {sorted(REPORTERS)}")
        return value

    def pattern_names(self) -> set[str]:
        return {p.name for p in self.patterns}


def _validate_cross_field(spec: RuleSpec, origin: str) -> None:
    """Checks that need more than one field, so pydantic cannot express them."""
    names = [p.name for p in spec.patterns]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise RuleError(f"{origin}: duplicate pattern names {sorted(duplicates)}")

    known = spec.pattern_names()
    for case in spec.tests.positive:
        if case.expect is not None and case.expect not in known:
            raise RuleError(
                f"{origin}: positive case expects pattern {case.expect!r}, "
                f"which this rule does not define. Known: {sorted(known)}"
            )


def parse_rule(data: object, origin: str, *, builtin: bool) -> LoadedRule:
    """Validate one parsed YAML document into a runnable rule."""
    if not isinstance(data, dict):
        raise RuleError(f"{origin}: expected a mapping at the top level")

    try:
        spec = RuleSpec.model_validate(data)
    except ValidationError as exc:
        raise RuleError(f"{origin}: {_render(exc)}") from exc

    if not builtin and spec.id.startswith(BUILTIN_PREFIX):
        raise RuleError(
            f"{origin}: id {spec.id!r} uses the reserved {BUILTIN_PREFIX!r} prefix. "
            "A third-party rule that could shadow a bundled one could silently "
            "weaken it."
        )

    _validate_cross_field(spec, origin)

    compiled: list[CompiledPattern] = [
        compile_pattern(p.to_pattern(), rule_id=spec.id) for p in spec.patterns
    ]

    rule = PatternRule(
        meta=RuleMeta(
            id=spec.id,
            title=spec.title,
            severity=spec.severity,
            remediation=" ".join(spec.remediation.split()),
        ),
        patterns=compiled,
        match_mode=spec.match_mode,
        predicate=spec.predicate,
        reporter=spec.reporter,
    )

    tests = RuleTests(
        positive=tuple(
            RuleCase(text=c.text, kind=c.kind, expect=c.expect) for c in spec.tests.positive
        ),
        negative=tuple(RuleCase(text=c.text, kind=c.kind) for c in spec.tests.negative),
    )
    return LoadedRule(rule=rule, tests=tests, source=origin)


def _render(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        location = ".".join(str(p) for p in error["loc"]) or "<root>"
        parts.append(f"{location}: {error['msg']}")
    return "; ".join(parts)


def load_text(text: str, origin: str, *, builtin: bool = False) -> LoadedRule:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"{origin}: not valid YAML: {exc}") from exc
    return parse_rule(data, origin, builtin=builtin)


def load_directory(path: Path) -> list[LoadedRule]:
    """Load every ``.yaml`` rule in a directory. Third-party by definition."""
    if not path.is_dir():
        raise RuleError(f"rule directory not found: {path}")
    rules = []
    for file in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
        rules.append(load_text(file.read_text(encoding="utf-8"), str(file)))
    return rules


def load_builtin() -> list[LoadedRule]:
    """Load the bundled pack from package data."""
    rules: list[LoadedRule] = []
    for entry in sorted(_builtin_files(), key=lambda item: item[0]):
        name, text = entry
        rules.append(load_text(text, f"{BUILTIN_PACKAGE}/{name}", builtin=True))
    return rules


def _builtin_files() -> Iterator[tuple[str, str]]:
    for item in resources.files(BUILTIN_PACKAGE).iterdir():
        if item.name.endswith((".yaml", ".yml")):
            yield item.name, item.read_text(encoding="utf-8")


def check_unique(rules: Iterable[LoadedRule]) -> None:
    """Two rules with one id makes findings ambiguous and suppression a lottery."""
    seen: dict[str, str] = {}
    for loaded in rules:
        rule_id = loaded.rule.meta.id
        if rule_id in seen:
            raise RuleError(
                f"duplicate rule id {rule_id!r}: {seen[rule_id]} and {loaded.source}"
            )
        seen[rule_id] = loaded.source


def load_all(extra: Path | None = None) -> list[LoadedRule]:
    """The bundled pack, plus an optional third-party directory."""
    rules = load_builtin()
    if extra is not None:
        rules += load_directory(extra)
    check_unique(rules)
    return rules


def lint_all(rules: Iterable[LoadedRule]) -> list[tuple[str, str, str]]:
    """Advisory warnings as ``(rule_id, pattern_name, warning)``. Never blocking."""
    from mcpscan.engine import lint_expression

    found: list[tuple[str, str, str]] = []
    for loaded in rules:
        for pattern in loaded.rule.patterns:
            for warning in lint_expression(pattern.spec.expression):
                found.append((loaded.rule.meta.id, pattern.spec.name, warning))
    return found
