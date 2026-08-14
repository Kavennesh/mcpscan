"""MCP-001 -- invisible and deceptive Unicode.

The negative half lives in ``test_negative_controls.py``; this is what the rule
must catch, and how precisely it must report it. Two things get asserted harder
than they might elsewhere:

*Byte offsets are checked against text where they genuinely differ from character
offsets.* A test using pure ASCII would pass identically whether the rule
computed byte offsets or forgot to, so every offset assertion here sits behind
multibyte text.

*The context check is tested in both directions.* Showing that a ZWJ inside an
emoji is suppressed proves nothing on its own -- a rule that suppressed
everything would pass. Each suppression is paired with the same character in a
context where it must still fire.
"""

from __future__ import annotations

import pytest

from mcpscan.document import FieldKind, MetadataDocument, TextField
from mcpscan.models import Confidence, Severity
from mcpscan.rules import InvisibleUnicodeRule

RULE = InvisibleUnicodeRule()


def check(text: str, kind: FieldKind = FieldKind.TOOL_DESCRIPTION) -> list:
    return list(RULE.check_field(TextField(pointer="#/tools/0/description", text=text, kind=kind)))


def only(text: str):
    findings = check(text)
    if len(findings) != 1:
        raise AssertionError(f"expected exactly one finding, got {len(findings)}")
    return findings[0]


# --------------------------------------------------------------------------
# categories
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("char", "name"),
    [
        ("‪", "LEFT-TO-RIGHT EMBEDDING"),
        ("‫", "RIGHT-TO-LEFT EMBEDDING"),
        ("‬", "POP DIRECTIONAL FORMATTING"),
        ("‭", "LEFT-TO-RIGHT OVERRIDE"),
        ("‮", "RIGHT-TO-LEFT OVERRIDE"),
        ("⁦", "LEFT-TO-RIGHT ISOLATE"),
        ("⁧", "RIGHT-TO-LEFT ISOLATE"),
        ("⁨", "FIRST STRONG ISOLATE"),
        ("⁩", "POP DIRECTIONAL ISOLATE"),
    ],
)
def test_every_bidi_control_is_high_confidence(char: str, name: str) -> None:
    finding = only(f"Reads a file.{char}payload")
    assert finding.rule_id == "MCP-001"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.metadata["characters"][0]["name"] == name


def test_tag_characters_are_high_confidence() -> None:
    finding = only("Reads a file.\U000e0049\U000e0067\U000e006e")
    assert finding.confidence is Confidence.HIGH
    assert finding.metadata["pattern"] == "tag-characters"
    assert finding.metadata["count"] == 3


def test_zero_width_space_is_reported() -> None:
    finding = only("Reads a file.​hidden")
    assert finding.metadata["pattern"] == "format-character"
    assert finding.metadata["characters"][0]["codepoint"] == "U+200B"


def test_private_use_area_is_reported() -> None:
    finding = only("Reads a file.")
    assert finding.metadata["pattern"] == "private-use"
    assert finding.confidence is Confidence.MEDIUM


def test_soft_hyphen_and_word_joiner_are_reported() -> None:
    assert check("Reads a­file.")
    assert check("Reads a⁠file.")


def test_a_bom_after_position_zero_is_reported() -> None:
    """At position zero it is a byte-order mark; anywhere else it is hiding."""
    assert check("﻿Reads a file.") == []
    assert check("Reads a file.﻿hidden")


# --------------------------------------------------------------------------
# offsets -- the reason the rule exists in this shape
# --------------------------------------------------------------------------
def test_byte_offset_differs_from_char_offset_after_multibyte_text() -> None:
    """The assertion that makes every other offset assertion meaningful.

    "Récupère" is eight characters but ten bytes, so a rule that reported
    character offsets as byte offsets would be caught here and nowhere else.
    """
    text = "Récupère‮payload"
    finding = only(text)
    char = finding.metadata["characters"][0]

    assert char["char_offset"] == 8
    # 'é' and 'è' are two bytes each in UTF-8, so the byte offset runs two ahead.
    assert char["byte_offset"] == 10
    assert finding.location.span.start == 8
    assert finding.location.span.byte_start == 10


def test_offsets_survive_astral_plane_characters() -> None:
    text = "\U0001f600​hidden"
    finding = only(text)
    char = finding.metadata["characters"][0]
    assert char["char_offset"] == 1
    assert char["byte_offset"] == 4  # the emoji is four bytes


def test_the_span_covers_only_the_payload() -> None:
    finding = only("Reads a file.​​​more text here")
    assert finding.location.span.start == 13
    assert finding.location.span.end == 16
    assert finding.evidence == "​​​"


# --------------------------------------------------------------------------
# coalescing and precedence
# --------------------------------------------------------------------------
def test_a_run_is_one_finding_not_one_per_character() -> None:
    """A 200-character tag payload is one problem, not 200."""
    payload = "".join(chr(0xE0000 + 0x41 + index % 26) for index in range(200))
    finding = only(f"Reads a file.{payload}")
    assert finding.metadata["count"] == 200


def test_a_bidi_control_is_reported_once_at_high_not_twice() -> None:
    """Bidi controls are format characters too; the specific pattern must win."""
    findings = check("Reads a file.‮payload")
    assert len(findings) == 1
    assert findings[0].metadata["pattern"] == "bidi-control"


def test_separate_runs_are_separate_findings() -> None:
    findings = check("Reads​a​file")
    assert len(findings) == 2
    assert [f.metadata["characters"][0]["char_offset"] for f in findings] == [5, 7]


# --------------------------------------------------------------------------
# the context check, in both directions
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("suppressed", "reported"),
    [
        # ZWJ: emoji sequence vs ASCII
        ("\U0001f468‍\U0001f469", "file‍name"),
        # ZWJ after a variation selector, as in a flag sequence
        ("\U0001f3f3️‍\U0001f308", "abc️‍def"),
        # ZWNJ: Persian orthography vs ASCII
        ("ملف‌ها", "file‌name"),
        # RLM: present with RTL text vs alone in Latin text
        ("קובץ ‏README", "Reads a file.‏"),
    ],
)
def test_format_characters_are_judged_by_context(suppressed: str, reported: str) -> None:
    """Each suppression paired with the same character where it must still fire.

    Without the pairing, a rule that suppressed everything would pass.
    """
    assert check(suppressed) == [], f"false positive on {suppressed!r}"
    assert check(reported), f"missed payload in {reported!r}"


def test_a_mixed_run_reports_only_the_illegitimate_characters() -> None:
    """An emoji ZWJ and a smuggled ZWSP adjacent to each other."""
    finding = only("\U0001f468‍\U0001f469​hidden")
    codepoints = [c["codepoint"] for c in finding.metadata["characters"]]
    assert codepoints == ["U+200B"]


# --------------------------------------------------------------------------
# traversal
# --------------------------------------------------------------------------
def test_a_payload_nested_in_the_input_schema_is_found() -> None:
    """One level down is what makes a schema description a good hiding place."""
    doc = MetadataDocument(
        tools=[
            {
                "name": "search",
                "description": "Searches.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "The query.‮payload"}
                    },
                },
            }
        ]
    )
    findings = list(RULE.check(doc))
    assert len(findings) == 1
    assert findings[0].location.pointer == (
        "#/tools/0/inputSchema/properties/query/description"
    )


def test_a_payload_in_a_tool_name_is_found() -> None:
    doc = MetadataDocument(tools=[{"name": "read‮file", "description": "Reads."}])
    findings = list(RULE.check(doc))
    assert findings[0].location.pointer == "#/tools/0/name"
    assert findings[0].metadata["field"] == "tool_name"
