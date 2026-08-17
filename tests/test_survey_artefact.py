"""The survey artefact: the file a live server's findings point at.

A finding from a running server names a field with a JSON pointer and nothing
else, and SARIF results without a file are discarded by the consumer they exist
for. `document.serialise` closes that by writing the metadata out and recording
where every value landed, so a pointer becomes a line and a span becomes a
column.

That makes this module a parser's mirror image, and it takes hostile input for
the same reason `jsonrpc.py` does: everything in a `MetadataDocument` from a
live scan came off the wire. The tests below are mostly about what a server can
do to a writer -- a lone surrogate, an infinity, a tool named `read/file`, a
description longer than the report -- and about the one property everything else
rests on, which is that a pointer the rules produced resolves to the place the
artefact put it.
"""

from __future__ import annotations

import json

from mcpscan.document import (
    MAX_ARTEFACT_VALUE_CHARS,
    Anchor,
    MetadataDocument,
    serialise,
    walk_text,
)
from mcpscan.models import Span

# A document exercising every shape `walk_text` knows how to reach.
MAXIMAL = MetadataDocument(
    instructions="Call tools in order.",
    server_info={"name": "demo", "title": "Demo", "version": "1.0"},
    tools=[
        {
            "name": "search",
            "title": "Search",
            "description": "Search the index.",
            "annotations": {"title": "Search things"},
            "inputSchema": {
                "type": "object",
                "properties": {
                    "q": {"type": "string", "description": "The query.", "enum": ["a", "b"]}
                },
            },
            "outputSchema": {"type": "object", "description": "Results."},
        },
        {"name": "write", "description": "Write a file."},
    ],
    resources=[{"name": "notes", "title": "Notes", "description": "A note.", "uri": "file:///n"}],
    resource_templates=[{"name": "t", "uriTemplate": "file:///{id}"}],
    prompts=[
        {
            "name": "summarise",
            "title": "Summarise",
            "description": "Summarise a thing.",
            "arguments": [{"name": "text", "description": "What to summarise."}],
        }
    ],
)


def line_of(text: str, number: int) -> str:
    return text.splitlines()[number - 1]


# --------------------------------------------------------------------------
# the artefact is the document
# --------------------------------------------------------------------------
def test_the_artefact_parses_back_to_the_document() -> None:
    """It is JSON, and it is the metadata -- not a rendering of it."""
    artefact = serialise(MAXIMAL)
    payload = json.loads(artefact.text)

    assert payload["instructions"] == MAXIMAL.instructions
    assert payload["tools"] == MAXIMAL.tools
    assert payload["resources"] == MAXIMAL.resources
    assert payload["prompts"] == MAXIMAL.prompts


def test_the_top_level_keys_are_the_pointer_tokens_not_the_attribute_names() -> None:
    """`walk_text` says `#/serverInfo`; the dataclass says `server_info`.

    Serialise the attribute names and every finding on the server's own identity
    or on a resource template silently lands on line 1 -- silently, because the
    fallback exists precisely so that nothing is ever dropped.
    """
    payload = json.loads(serialise(MAXIMAL).text)

    assert "serverInfo" in payload and "server_info" not in payload
    assert "resourceTemplates" in payload and "resource_templates" not in payload


def test_the_artefact_is_byte_stable() -> None:
    """No clock, no set iteration. It changes when the server changes."""
    assert serialise(MAXIMAL).text == serialise(MAXIMAL).text


def test_an_empty_document_still_has_a_line_one() -> None:
    """A server that failed its handshake gets one of these, and its anomaly
    findings have nowhere else to point."""
    artefact = serialise(MetadataDocument())
    assert json.loads(artefact.text)["tools"] == []
    assert artefact.anchor_for("#/_transport/3").line == 1


# --------------------------------------------------------------------------
# pointers resolve
# --------------------------------------------------------------------------
def test_every_pointer_the_rules_can_produce_resolves_exactly() -> None:
    """The load-bearing property. If this drifts, findings quietly pile up on
    line 1 and the artefact looks like it is working."""
    artefact = serialise(MAXIMAL)
    walked = list(walk_text(MAXIMAL))
    assert len(walked) > 15, "fixture stopped exercising the walk"

    missing = [field.pointer for field in walked if field.pointer not in artefact.anchors]
    assert not missing, f"pointers with no anchor: {missing}"


def test_an_anchor_points_at_the_text_it_claims_to() -> None:
    artefact = serialise(MAXIMAL)
    for field in walk_text(MAXIMAL):
        anchor = artefact.anchors[field.pointer]
        line = line_of(artefact.text, anchor.line)
        # `column` is 1-based and names the opening quote.
        assert line[anchor.column - 1] == '"', field.pointer
        assert json.dumps(field.text, ensure_ascii=True) in line, field.pointer


def test_a_nested_schema_field_falls_back_to_its_tool() -> None:
    """`#/tools/0/inputSchema/properties/q/description` exists, but a probe
    pointer at a whole tool does not -- and neither should land on line 1."""
    artefact = serialise(MAXIMAL)
    tool = artefact.anchors["#/tools/0"]

    assert artefact.anchor_for("#/tools/0/nonesuch/deeper") == tool
    assert artefact.anchor_for("#/tools/0").line == tool.line


def test_a_probe_pointer_resolves_by_tool_name() -> None:
    """`probes.py` writes `#/_probe/rug-pull/<tool>` for a tool that vanished
    from the later listing. It still names something a reader can look at."""
    artefact = serialise(MAXIMAL)

    assert artefact.anchor_for("#/_probe/rug-pull/write") == artefact.anchors["#/tools/1"]
    assert artefact.anchor_for("#/_probe/scope-escape/search") == artefact.anchors["#/tools/0"]
    # A variable name, not a tool name: nothing to point at but the root.
    assert artefact.anchor_for("#/_probe/env-leak/OPENAI_API_KEY").line == 1


def test_a_probe_pointer_survives_an_unescaped_slash_in_a_tool_name() -> None:
    """`probes.py` interpolates the name without RFC 6901 escaping, so the
    resolver has to treat everything after the second segment as one name."""
    doc = MetadataDocument(tools=[{"name": "read/file", "description": "d"}])
    artefact = serialise(doc)

    assert artefact.anchor_for("#/_probe/rug-pull/read/file") == artefact.anchors["#/tools/0"]


def test_a_duplicate_tool_name_is_not_an_identity() -> None:
    """Two tools called `search` identify neither, so the name resolves to
    nothing rather than to whichever one happened to be first."""
    doc = MetadataDocument(tools=[{"name": "search"}, {"name": "search"}])
    artefact = serialise(doc)

    assert artefact.tool_index == {}
    assert artefact.anchor_for("#/_probe/rug-pull/search").line == 1


def test_a_tool_name_that_is_not_a_string_is_not_indexed() -> None:
    doc = MetadataDocument(tools=[{"name": 42}, {"name": None}, {}, "not-a-dict"])
    artefact = serialise(doc)

    assert artefact.tool_index == {}
    assert json.loads(artefact.text)["tools"][0] == {"name": 42}


def test_rfc_6901_escaping_matches_the_walk() -> None:
    """A property key with a `/` or a `~` in it is escaped the same way in both
    places, or the pointer the rule reported names nothing in the file."""
    doc = MetadataDocument(
        tools=[
            {
                "name": "t",
                "inputSchema": {
                    "properties": {"a/b~c": {"description": "Awkward but legal."}}
                },
            }
        ]
    )
    artefact = serialise(doc)
    pointers = [field.pointer for field in walk_text(doc)]

    assert "#/tools/0/inputSchema/properties/a~1b~0c/description" in pointers
    assert all(pointer in artefact.anchors for pointer in pointers)


# --------------------------------------------------------------------------
# columns
# --------------------------------------------------------------------------
def test_a_span_becomes_the_columns_of_the_text_it_spans() -> None:
    text = "Search the index."
    doc = MetadataDocument(tools=[{"name": "t", "description": text}])
    artefact = serialise(doc)
    anchor = artefact.anchors["#/tools/0/description"]

    span = Span.of(text, 7, 10)  # "the"
    columns = anchor.columns(span)
    assert columns is not None
    start, end = columns
    line = line_of(artefact.text, anchor.line)
    assert line[start - 1 : end - 1] == "the"


def test_columns_survive_an_astral_character_before_the_match() -> None:
    """A Python string index is a code point; a SARIF column is a UTF-16 code
    unit; an emoji is two of the latter. `ensure_ascii=True` makes the artefact
    pure ASCII so the file's own offsets are the only ones that matter -- this
    pins that, because the payloads MCP-001 exists for are exactly these."""
    text = "🙂 hidden here"
    doc = MetadataDocument(tools=[{"name": "t", "description": text}])
    artefact = serialise(doc)
    anchor = artefact.anchors["#/tools/0/description"]

    span = Span.of(text, text.index("hidden"), text.index("hidden") + 6)
    columns = anchor.columns(span)
    assert columns is not None
    start, end = columns
    assert line_of(artefact.text, anchor.line)[start - 1 : end - 1] == "hidden"


def test_a_redacted_value_reports_a_line_and_no_columns() -> None:
    """Redaction changes lengths, so offsets into the original no longer index
    the file. An invented column points at the wrong characters and looks
    authoritative doing it."""
    text = "token sk-canary-1234 here"
    doc = MetadataDocument(tools=[{"name": "t", "description": text}])
    artefact = serialise(doc, redact=lambda s: s.replace("sk-canary-1234", "<env canary KEY>"))
    anchor = artefact.anchors["#/tools/0/description"]

    assert "sk-canary-1234" not in artefact.text
    assert anchor.exact is False
    assert anchor.columns(Span.of(text, 0, 5)) is None
    assert anchor.line >= 1


def test_columns_are_refused_past_the_value_cap() -> None:
    """A span inside the part that was written is still exact; one past the cap
    is not, and saying so beats guessing."""
    text = "x" * (MAX_ARTEFACT_VALUE_CHARS + 500)
    doc = MetadataDocument(tools=[{"name": "t", "description": text}])
    artefact = serialise(doc)
    anchor = artefact.anchors["#/tools/0/description"]

    assert anchor.columns(Span.of(text, 0, 3)) is not None
    assert anchor.columns(Span.of(text, len(text) - 3, len(text))) is None


def test_a_container_anchor_has_no_columns() -> None:
    artefact = serialise(MAXIMAL)
    assert artefact.anchors["#/tools/0"].columns(Span.of("abc", 0, 1)) is None
    assert artefact.anchors["#/tools/0"].whole() is None


def test_a_whole_value_has_columns_without_a_span() -> None:
    """A probe finding is about a whole field -- a rug pull says this text is no
    longer in force -- and has no span to offer. It still gets columns."""
    artefact = serialise(MAXIMAL)
    anchor = artefact.anchors["#/tools/0/description"]

    columns = anchor.whole()
    assert columns is not None
    start, end = columns
    assert line_of(artefact.text, anchor.line)[start - 1 : end - 1] == "Search the index."


def test_whole_value_columns_survive_redaction() -> None:
    """Unlike a span, which indexes the original: the width is measured from
    what was written, so it is right even when the offsets would not be."""
    text = "token sk-canary-1234 here"
    doc = MetadataDocument(tools=[{"name": "t", "description": text}])
    artefact = serialise(doc, redact=lambda s: s.replace("sk-canary-1234", "<canary>"))
    anchor = artefact.anchors["#/tools/0/description"]

    assert anchor.columns(Span.of(text, 0, 5)) is None
    columns = anchor.whole()
    assert columns is not None
    start, end = columns
    assert line_of(artefact.text, anchor.line)[start - 1 : end - 1] == "token <canary> here"


def test_whole_value_columns_survive_truncation() -> None:
    text = "x" * (MAX_ARTEFACT_VALUE_CHARS + 500)
    doc = MetadataDocument(tools=[{"name": "t", "description": text}])
    artefact = serialise(doc)
    anchor = artefact.anchors["#/tools/0/description"]

    columns = anchor.whole()
    assert columns is not None
    start, end = columns
    written = line_of(artefact.text, anchor.line)[start - 1 : end - 1]
    assert written.endswith("truncated]")
    assert len(written) < len(text)


# --------------------------------------------------------------------------
# hostile input
# --------------------------------------------------------------------------
def test_a_lone_surrogate_does_not_crash_the_writer() -> None:
    """`json.loads` accepts `\\ud800` off the wire and UTF-8 cannot encode it.
    A scanner that crashes on the input it exists to examine is not a scanner."""
    doc = MetadataDocument(tools=[{"name": "t", "description": "before \ud800 after"}])
    artefact = serialise(doc)

    assert "\\ud800" in artefact.text
    artefact.text.encode("utf-8")  # the write that would otherwise raise
    assert json.loads(artefact.text)["tools"][0]["description"] == "before \ud800 after"


def test_a_non_finite_number_becomes_null() -> None:
    """`json.loads` accepts `Infinity` and `json.dumps` writes it back, and the
    result is a file no strict parser will read -- including the validator
    checking the SARIF that points at it."""
    doc = MetadataDocument(tools=[{"name": "t", "score": float("inf"), "n": float("nan")}])
    artefact = serialise(doc)

    tool = json.loads(artefact.text)["tools"][0]
    assert tool["score"] is None and tool["n"] is None


def test_a_long_value_is_capped() -> None:
    """A hostile server chooses how long its descriptions are. It does not get
    to choose how large our artefact is."""
    doc = MetadataDocument(tools=[{"name": "t", "description": "x" * 100_000}])
    artefact = serialise(doc)

    assert len(artefact.text) < 20_000
    assert json.loads(artefact.text)["tools"][0]["description"].endswith("truncated]")


def test_deep_nesting_is_truncated_rather_than_recursed_into() -> None:
    deep: dict[str, object] = {"description": "bottom"}
    for _ in range(400):
        deep = {"properties": {"x": deep}}
    doc = MetadataDocument(tools=[{"name": "t", "inputSchema": deep}])

    artefact = serialise(doc)  # must not raise RecursionError
    assert "truncated" in artefact.text


def test_an_unserialisable_value_becomes_null_rather_than_an_exception() -> None:
    doc = MetadataDocument(tools=[{"name": "t", "weird": {1, 2, 3}}])
    assert json.loads(serialise(doc).text)["tools"][0]["weird"] is None


def test_a_key_that_is_not_a_string_is_coerced() -> None:
    doc = MetadataDocument(tools=[{"name": "t", "schema": {1: "one"}}])
    assert json.loads(serialise(doc).text)["tools"][0]["schema"] == {"1": "one"}


def test_the_fallback_anchor_is_never_nothing() -> None:
    """Every path through `anchor_for` ends somewhere, because a result GitHub
    drops is a finding nobody is told about."""
    artefact = serialise(MAXIMAL)
    for pointer in ("#", "#/nope", "#/_transport/9999", "#/_probe/x/y/z", "#/tools/99/name"):
        assert isinstance(artefact.anchor_for(pointer), Anchor)
