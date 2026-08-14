"""The three rules, written as code so step 5's YAML schema can be derived from them.

What this file is really for, beyond finding things: MCP-001 and MCP-002 turn out
to be the *same* mechanism -- a list of patterns applied to text fields selected
by :class:`~mcpscan.document.FieldKind`, each pattern carrying its own severity,
confidence and message. :class:`PatternRule` is that mechanism, and it is the
shape step 5 should generate rather than invent. MCP-003 does not fit it at all
and is not forced to; recording that mismatch is worth more than a schema that
pretends three rules are one shape.

Precision is the design driver here, not recall. A scanner's real failure mode is
not missing a bug -- it is being switched off, because findings a reviewer learns
to skim are worse than no findings at all. Every false positive spends credibility
the true positives need. Two decisions came directly out of asking what a
*realistic* benign corpus would contain:

**MCP-001 cannot sweep ``\\p{Cf}`` blindly.** ZWJ builds emoji sequences, ZWNJ is
orthographically required in Persian, Arabic and Indic scripts, and LRM/RLM exist
to make mixed-direction text display correctly. A rule that fires on all of them
cannot be pointed at a real server. So each candidate is asked whether it is doing
the job it exists for -- and a ZWJ between two ASCII characters is still reported,
because "that is how emoji work" is only an excuse where there are emoji.

**MCP-002's weakest tier needs a behavioural object.** "You must provide an
absolute path" is documentation and appears everywhere. "You must always call
setup first" is steering. Matching bare second person would make the rule
unusable; requiring an action, an ordering or a prohibition keeps it sharp.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

import regex

from mcpscan.document import MODEL_FACING_KINDS, FieldKind, MetadataDocument, TextField, walk_text
from mcpscan.models import Confidence, Finding, Severity, Span


@dataclass(frozen=True, slots=True)
class RuleMeta:
    id: str
    title: str
    severity: Severity


class MetadataRule(Protocol):
    """A rule that reads what a server advertises."""

    meta: RuleMeta

    def check(self, doc: MetadataDocument) -> Iterator[Finding]: ...


class SourceRule(Protocol):
    """A rule that reads the target's code."""

    meta: RuleMeta

    def check(self, tree: Any, tools: Sequence[Any]) -> Iterator[Finding]: ...


@dataclass(frozen=True, slots=True)
class Pattern:
    """One detection, with its own confidence and its own explanation.

    Confidence is per-pattern rather than per-rule because the tiers within a
    rule differ far more than the rules do: `<IMPORTANT>` in a description is
    unambiguous, a second-person imperative is a hint. This field is the
    load-bearing part of the schema step 5 will generate.
    """

    name: str
    expression: str
    confidence: Confidence
    message: str
    #: When set, the pattern only applies to these field kinds.
    kinds: frozenset[FieldKind] | None = None
    #: When set, the pattern is skipped for these field kinds.
    exclude_kinds: frozenset[FieldKind] = frozenset()

    def compiled(self) -> regex.Pattern[str]:
        return regex.compile(self.expression, regex.IGNORECASE | regex.VERSION1)

    def applies_to(self, kind: FieldKind) -> bool:
        if kind in self.exclude_kinds:
            return False
        return self.kinds is None or kind in self.kinds


class PatternRule:
    """Apply a pattern list to every text field a model can see.

    Shared by MCP-001 and MCP-002. Subclasses override :meth:`describe` to turn a
    match into the metadata their finding needs -- codepoints for one, nothing
    extra for the other -- but the traversal, the field selection, the span
    arithmetic and the location handling are identical, which is the whole point.
    """

    meta: RuleMeta
    patterns: tuple[Pattern, ...] = ()

    def check(self, doc: MetadataDocument) -> Iterator[Finding]:
        for field_ in walk_text(doc):
            yield from self.check_field(field_)

    def check_field(self, field_: TextField) -> Iterator[Finding]:
        for pattern in self.patterns:
            if not pattern.applies_to(field_.kind):
                continue
            for match in pattern.compiled().finditer(field_.text):
                start, end = match.span()
                if start == end:
                    continue
                finding = self.build(field_, pattern, start, end)
                if finding is not None:
                    yield finding

    def build(
        self,
        field_: TextField,
        pattern: Pattern,
        start: int,
        end: int,
    ) -> Finding | None:
        span = Span.of(field_.text, start, end)
        location = field_.locate().model_copy(update={"span": span})
        extra = self.describe(field_, pattern, span)
        if extra is None:
            return None
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            severity=self.meta.severity,
            confidence=pattern.confidence,
            message=pattern.message,
            location=location,
            evidence=span.excerpt(field_.text),
            metadata={"pattern": pattern.name, "field": field_.kind.value, **extra},
        )

    def describe(
        self,
        field_: TextField,
        pattern: Pattern,
        span: Span,
    ) -> dict[str, Any] | None:
        """Rule-specific metadata, or ``None`` to suppress the match."""
        return {}


# --------------------------------------------------------------------------
# MCP-001
# --------------------------------------------------------------------------
#: Bidi overrides and isolates. These reorder displayed text, so what a reviewer
#: reads is not what the model receives -- the entire attack in one character.
BIDI_CONTROLS: Final = "‪-‮⁦-⁩"

#: Invisible, and carry a full ASCII alphabet. Nothing legitimate uses them in a
#: description; a payload can be spelled out entirely in them.
TAG_CHARACTERS: Final = "\U000e0000-\U000e007f"

#: Format characters with a real job in ordinary text. Reported only when the
#: context check below says they are not doing it.
ZWJ: Final = "‍"
ZWNJ: Final = "‌"
BIDI_MARKS: Final = frozenset({"‎", "‏", "؜"})

#: Strong right-to-left text, excluding the directional marks themselves. The
#: exclusion is load-bearing: LRM/RLM/ALM carry a strong bidi class of their own,
#: so a naive search would find the very character being judged and let it
#: justify its own presence -- a lone RLM smuggled into Latin text would suppress
#: itself.
_RTL = regex.compile(
    r"(?![‎‏؜])[\p{Bidi_Class=R}\p{Bidi_Class=AL}]", regex.VERSION1
)
_PICTOGRAPH = regex.compile(r"\p{Extended_Pictographic}", regex.VERSION1)

#: Characters that decorate the one before them rather than standing alone:
#: variation selectors, skin-tone modifiers, combining marks, keycaps. An emoji
#: sequence is routinely `pictograph + VS16 + ZWJ + pictograph` -- 🏳️‍🌈 is
#: exactly that -- so a neighbour check that stops at the first character finds
#: U+FE0F and wrongly concludes the ZWJ is joining nothing.
_MODIFIER = regex.compile(
    r"[︀-️\U0001F3FB-\U0001F3FF⃣\p{Mn}\p{Me}\p{Mc}]", regex.VERSION1
)
_JOINING_SCRIPT = regex.compile(
    r"[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Devanagari}\p{Script=Bengali}"
    r"\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Oriya}\p{Script=Tamil}"
    r"\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}"
    r"\p{Script=Thaana}\p{Script=Syriac}]",
    regex.VERSION1,
)


def codepoint_info(char: str) -> dict[str, Any]:
    """Identify a character the way a report needs to name it."""
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = "<unnamed>"
    return {
        "codepoint": f"U+{ord(char):04X}",
        "name": name,
        "category": unicodedata.category(char),
    }


def _neighbour(text: str, index: int, step: int) -> str:
    """The nearest character either side that is not a modifier of another.

    Walking past variation selectors and combining marks is what makes the emoji
    check work: 🏳️‍🌈 is flag + VS16 + ZWJ + rainbow, so the character
    immediately before the ZWJ is U+FE0F rather than the flag it belongs to.
    """
    position = index + step
    while 0 <= position < len(text) and _MODIFIER.match(text[position]):
        position += step
    if 0 <= position < len(text):
        return text[position]
    return ""


def is_legitimate_format_char(text: str, index: int) -> bool:
    """Whether the format character at ``index`` is doing the job it exists for.

    Four checks, no heuristics beyond them:

    * ZWJ between two pictographs is an emoji sequence -- 👨‍👩‍👧 is three
      pictographs and two ZWJs, and flagging it would fire on any server whose
      descriptions contain a family or a profession emoji.
    * ZWJ or ZWNJ adjacent to a joining script is orthography. Persian ``ملف‌ها``
      needs the ZWNJ; removing it changes the word.
    * LRM/RLM/ALM in a field that contains strong-RTL text is bidi correctness,
      which is the only reason those characters exist.
    * A ``U+FEFF`` at position zero is a byte-order mark -- how a UTF-8 file
      legitimately begins. Anywhere else it is an invisible character with no job.
    """
    char = text[index]

    if char == "﻿":
        return index == 0

    before = _neighbour(text, index, -1)
    after = _neighbour(text, index, 1)

    if char == ZWJ and before and after:
        if _PICTOGRAPH.match(before) and _PICTOGRAPH.match(after):
            return True

    if char in (ZWJ, ZWNJ):
        if (before and _JOINING_SCRIPT.match(before)) or (after and _JOINING_SCRIPT.match(after)):
            return True

    if char in BIDI_MARKS:
        return bool(_RTL.search(text))

    return False


class InvisibleUnicodeRule(PatternRule):
    """MCP-001 -- invisible or deceptive characters in advertised metadata."""

    meta = RuleMeta(
        id="MCP-001",
        title="Invisible or deceptive Unicode in tool metadata",
        severity=Severity.HIGH,
    )

    patterns = (
        Pattern(
            name="bidi-control",
            expression=f"[{BIDI_CONTROLS}]+",
            confidence=Confidence.HIGH,
            message=(
                "Bidirectional override or isolate in metadata. These reorder how "
                "text is displayed, so a reviewer does not read what the model receives."
            ),
        ),
        Pattern(
            name="tag-characters",
            expression=f"[{TAG_CHARACTERS}]+",
            confidence=Confidence.HIGH,
            message=(
                "Unicode tag characters in metadata. They render as nothing in every "
                "client and can spell out an entire hidden instruction in ASCII."
            ),
        ),
        Pattern(
            name="format-character",
            expression=r"\p{Cf}+",
            confidence=Confidence.MEDIUM,
            message=(
                "Invisible format character in metadata with no legitimate role in "
                "this text."
            ),
        ),
        Pattern(
            name="private-use",
            expression=r"\p{Co}+",
            confidence=Confidence.MEDIUM,
            message=(
                "Private use area character in metadata. Its appearance depends "
                "entirely on the font, so what a reviewer sees is not defined."
            ),
        ),
    )

    def check_field(self, field_: TextField) -> Iterator[Finding]:
        """Report one finding per run, and let the specific patterns win.

        A 200-character tag-encoded payload is one problem, not 200, so runs
        coalesce. Where the broad ``\\p{Cf}`` sweep overlaps a specific pattern --
        bidi controls are format characters too -- the specific one is kept, so a
        bidi override is reported once at HIGH rather than twice.
        """
        claimed: set[int] = set()
        for pattern in self.patterns:
            for match in pattern.compiled().finditer(field_.text):
                start, end = match.span()
                if start == end or any(index in claimed for index in range(start, end)):
                    continue
                finding = self.build(field_, pattern, start, end)
                if finding is not None:
                    claimed.update(range(start, end))
                    yield finding

    def describe(
        self,
        field_: TextField,
        pattern: Pattern,
        span: Span,
    ) -> dict[str, Any] | None:
        text = field_.text
        reported: list[dict[str, Any]] = []

        for index in range(span.start, span.end):
            if pattern.name == "format-character" and is_legitimate_format_char(text, index):
                continue
            info = codepoint_info(text[index])
            info["char_offset"] = index
            info["byte_offset"] = len(text[:index].encode("utf-8"))
            reported.append(info)

        if not reported:
            # Every character in the run was doing its job. Emoji, not a payload.
            return None

        return {"characters": reported, "count": len(reported)}


# --------------------------------------------------------------------------
# MCP-002
# --------------------------------------------------------------------------
class ModelDirectedInstructionRule(PatternRule):
    """MCP-002 -- instructions aimed at the model rather than at a human reader.

    A tool description is documentation. When it starts issuing orders, it is not
    describing the tool any more, it is programming whatever reads it -- and what
    reads it is a model with the user's credentials.
    """

    meta = RuleMeta(
        id="MCP-002",
        title="Model-directed instructions in tool metadata",
        severity=Severity.HIGH,
    )

    patterns = (
        Pattern(
            name="instruction-override",
            expression=(
                r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?"
                r"(?:the\s+)?(?:previous|prior|earlier|above|preceding|system)\s+"
                r"(?:instruction|prompt|direction|rule|message)s?"
            ),
            confidence=Confidence.HIGH,
            message="Attempts to override instructions the model was already given.",
        ),
        Pattern(
            name="secrecy-directive",
            expression=(
                r"\b(?:do\s+not|don't|never)\s+(?:ever\s+)?"
                r"(?:mention|tell|inform|reveal|disclose|report|explain|say)\b"
                r"[^.!?]{0,60}?\b(?:user|human|operator|anyone)\b"
                r"|\bwithout\s+(?:telling|informing|notifying|alerting)\s+"
                r"(?:the\s+)?(?:user|human|operator|anyone)\b"
                r"|\b(?:silently|quietly|discreetly)\s+"
                r"(?:send|read|fetch|include|append|forward|copy|transmit)\b"
            ),
            confidence=Confidence.HIGH,
            message="Directs the model to conceal its behaviour from the user.",
        ),
        Pattern(
            name="injection-wrapper",
            expression=(
                r"<\s*/?\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|PROMPT|ADMIN|CRITICAL)\s*>"
                r"|\[\[\s*(?:system|important|instructions?)\s*\]\]"
                r"|^\s*(?:system|assistant)\s*:\s*\S"
            ),
            confidence=Confidence.HIGH,
            message=(
                "Pseudo-markup framing the text as a system instruction rather than "
                "as documentation."
            ),
        ),
        Pattern(
            name="exfiltration-directive",
            expression=(
                r"\b(?:read|open|cat|include|attach|send|upload|forward|exfiltrate)\b"
                r"[^.!?]{0,40}?"
                r"(?:~/\.\w+|\.ssh/|\.aws/|\.env\b|id_rsa|credential|"
                r"private\s+key|api[_\s-]?key|password|secret)"
            ),
            confidence=Confidence.HIGH,
            message="Directs the model at credential material.",
        ),
        Pattern(
            name="tool-use-directive",
            expression=(
                r"\bbefore\s+(?:using|calling|invoking|running)\s+"
                r"(?:this|any|the)\s+tool\b[^.!?]{0,40}?\b(?:always|first|must|you)\b"
                r"|\b(?:always|automatically)\s+(?:call|invoke|run|use)\s+\w+"
                r"\s+(?:before|after|first|instead)"
            ),
            confidence=Confidence.MEDIUM,
            message="Instructs the model how to sequence its tool calls.",
            # `instructions` exists to say this. Saying it there is not a finding.
            exclude_kinds=MODEL_FACING_KINDS,
        ),
        Pattern(
            name="model-address",
            expression=(
                r"\bas\s+an?\s+(?:AI|LLM|language\s+model|assistant|agent)\b"
                r"|\byou\s+are\s+an?\s+(?:AI|LLM|assistant|agent|model|helpful)\b"
                r"|\byour\s+(?:system\s+prompt|instructions|training|guidelines)\b"
            ),
            confidence=Confidence.MEDIUM,
            message="Addresses the reader as a language model rather than as a developer.",
        ),
        Pattern(
            name="behavioural-imperative",
            # Requires an *object* -- an action, an ordering or a prohibition.
            # Bare second person ("you must provide a path") is documentation and
            # is deliberately not matched; matching it would make the rule
            # unusable against real servers.
            expression=(
                r"\byou\s+(?:must|should|need\s+to|have\s+to)\s+"
                r"(?:always|never|first|then|also)\b"
                r"|\b(?:never|do\s+not|don't)\s+"
                r"(?:show|display|output|print|return|reveal)\b"
                r"[^.!?]{0,40}?\bto\s+the\s+(?:user|human)\b"
            ),
            confidence=Confidence.LOW,
            message="Second-person imperative directing behaviour rather than describing input.",
            exclude_kinds=MODEL_FACING_KINDS,
        ),
    )


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class RuleSet:
    metadata_rules: tuple[MetadataRule, ...] = field(default_factory=tuple)
    source_rules: tuple[SourceRule, ...] = field(default_factory=tuple)

    def ids(self) -> list[str]:
        metadata = [rule.meta.id for rule in self.metadata_rules]
        source = [rule.meta.id for rule in self.source_rules]
        return metadata + source
