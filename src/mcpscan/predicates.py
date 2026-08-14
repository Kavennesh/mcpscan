"""The named hooks a rule file may reference, and nothing else it can reach.

A rule file is contributor-supplied data. It may supply patterns and prose; it
must never be able to supply behaviour. So where a rule needs logic a regex
cannot express, it names an entry in one of the closed registries in
:mod:`mcpscan.engine`, and every entry is implemented here, in reviewed Python.

That is the whole security boundary of the YAML engine. A regex is bounded by the
per-match timeout; a hook name is bounded by existing in the registry or failing
to load. Neither can introduce a code path that was not reviewed.

Two kinds of hook:

``predicate(text, index) -> bool``
    Should the character at ``index`` be reported? This is what lets MCP-001 ask
    whether a format character is doing the job it exists for, which no pattern
    can answer -- the answer depends on the character's neighbours and on the
    script of the surrounding text.

``reporter(field, pattern, span, predicate) -> dict | None``
    Build the finding's ``metadata``, or return ``None`` to suppress the match
    entirely. Suppression lives here rather than in the predicate because a
    reporter sees the whole span: a run of format characters where *every*
    character turned out legitimate is not a finding, and only something looking
    at the run as a whole can say so.

The unicode machinery below moved verbatim from step 4's ``rules.py``. Its
reasoning is unchanged and is load-bearing -- see ``tests/test_negative_controls.py``,
where each suppression is paired with a case that must still fire.
"""

from __future__ import annotations

import unicodedata
from typing import TYPE_CHECKING, Any, Final

import regex

from mcpscan.models import Span

if TYPE_CHECKING:
    from mcpscan.document import TextField

#: Format characters with a real job in ordinary text.
ZWJ: Final = "‍"
ZWNJ: Final = "‌"
BOM: Final = "﻿"
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
#: sequence is routinely `pictograph + VS16 + ZWJ + pictograph` -- the pride flag
#: is exactly that -- so a neighbour check that stops at the first character
#: finds U+FE0F and wrongly concludes the ZWJ is joining nothing.
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
    check work: the pride flag is flag + VS16 + ZWJ + rainbow, so the character
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

    * ZWJ between two pictographs is an emoji sequence. A family emoji is three
      pictographs and two ZWJs, and flagging it would fire on any server whose
      descriptions contain a family or a profession emoji.
    * ZWJ or ZWNJ adjacent to a joining script is orthography. Persian needs the
      ZWNJ; removing it changes the word.
    * LRM/RLM/ALM in a field that contains strong-RTL text is bidi correctness,
      which is the only reason those characters exist.
    * A ``U+FEFF`` at position zero is a byte-order mark -- how a UTF-8 file
      legitimately begins. Anywhere else it is an invisible character with no job.
    """
    char = text[index]

    if char == BOM:
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


# --------------------------------------------------------------------------
# registry implementations
# --------------------------------------------------------------------------
def always(text: str, index: int) -> bool:
    """The default predicate: every matched character is worth reporting."""
    return True


def format_char_is_illegitimate(text: str, index: int) -> bool:
    """Report this character only if it is *not* doing its legitimate job."""
    return not is_legitimate_format_char(text, index)


def report_nothing(
    field_: TextField,
    pattern_name: str,
    span: Span,
    predicate: object,
) -> dict[str, Any] | None:
    """The default reporter: no extra metadata, never suppresses."""
    return {}


def report_codepoints(
    field_: TextField,
    pattern_name: str,
    span: Span,
    predicate: object,
) -> dict[str, Any] | None:
    """Name every reportable character in the span, with both offsets.

    Returns ``None`` when the predicate cleared every character in the run --
    an emoji sequence, not a payload. That is why suppression belongs to the
    reporter rather than the predicate: only something looking at the whole run
    can tell "this run contained one smuggled character" from "this run was
    entirely legitimate".

    Both offsets are reported because they answer different questions. The
    character offset slices the excerpt; the byte offset is what a user greps
    for and what SARIF wants at step 7.
    """
    if not callable(predicate):
        return None

    text = field_.text
    reported: list[dict[str, Any]] = []
    for index in range(span.start, span.end):
        if not predicate(text, index):
            continue
        info = codepoint_info(text[index])
        info["char_offset"] = index
        info["byte_offset"] = len(text[:index].encode("utf-8"))
        reported.append(info)

    if not reported:
        return None
    return {"characters": reported, "count": len(reported)}
