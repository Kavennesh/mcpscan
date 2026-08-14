"""The canonical document, its pointers, and the two-way location.

The requirement this file exists to pin: a location must work as a file path plus
line range when source exists, as a JSON pointer when only a live server does,
and as **both when both**. The merge is keyed on tool name rather than on
matching description text -- exact where fuzzy matching would be guesswork, and
it still works on a server that assembles its descriptions at runtime.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscan.document import (
    FieldKind,
    MetadataDocument,
    escape_token,
    pointer,
    walk_text,
)
from mcpscan.source import extract_tools, load_tree
from tests.sourcefixtures import materialise


def kinds_of(doc: MetadataDocument) -> dict[str, FieldKind]:
    return {f.pointer: f.kind for f in walk_text(doc)}


def texts_of(doc: MetadataDocument) -> dict[str, str]:
    return {f.pointer: f.text for f in walk_text(doc)}


# --------------------------------------------------------------------------
# pointers
# --------------------------------------------------------------------------
def test_pointer_uses_the_fragment_form() -> None:
    assert pointer("tools", 3, "description") == "#/tools/3/description"


def test_pointer_escaping_follows_rfc_6901() -> None:
    """`~` first, then `/` -- the other order double-escapes."""
    assert escape_token("a/b") == "a~1b"
    assert escape_token("a~b") == "a~0b"
    assert escape_token("a~/b") == "a~0~1b"
    assert pointer("properties", "a/b") == "#/properties/a~1b"


def test_pointer_survives_a_schema_property_named_with_a_slash() -> None:
    doc = MetadataDocument(
        tools=[
            {
                "name": "t",
                "inputSchema": {"properties": {"a/b": {"description": "Odd name."}}},
            }
        ]
    )
    assert "#/tools/0/inputSchema/properties/a~1b/description" in texts_of(doc)


# --------------------------------------------------------------------------
# the walk
# --------------------------------------------------------------------------
def test_every_model_visible_field_is_walked() -> None:
    doc = MetadataDocument(
        instructions="Server instructions.",
        server_info={"name": "srv", "title": "Server"},
        tools=[
            {
                "name": "search",
                "title": "Search",
                "description": "Searches.",
                "annotations": {"title": "Read only"},
                "inputSchema": {
                    "properties": {"q": {"description": "Query.", "enum": ["a", "b"]}}
                },
            }
        ],
        resources=[
            {"uri": "file:///a", "name": "a", "title": "A", "description": "Res."}
        ],
        resource_templates=[{"uriTemplate": "file:///{p}", "name": "tpl"}],
        prompts=[
            {
                "name": "p",
                "description": "Prompt.",
                "arguments": [{"name": "arg", "description": "An arg."}],
            }
        ],
    )
    kinds = kinds_of(doc)

    assert kinds["#/instructions"] is FieldKind.INSTRUCTIONS
    assert kinds["#/tools/0/name"] is FieldKind.TOOL_NAME
    assert kinds["#/tools/0/description"] is FieldKind.TOOL_DESCRIPTION
    assert kinds["#/tools/0/annotations/title"] is FieldKind.ANNOTATION_TITLE
    assert kinds["#/tools/0/inputSchema/properties/q/description"] is (
        FieldKind.SCHEMA_DESCRIPTION
    )
    assert kinds["#/tools/0/inputSchema/properties/q/enum/0"] is FieldKind.SCHEMA_ENUM
    assert kinds["#/resources/0/description"] is FieldKind.RESOURCE_DESCRIPTION
    assert kinds["#/resources/0/uri"] is FieldKind.RESOURCE_URI
    assert kinds["#/resourceTemplates/0/uriTemplate"] is FieldKind.RESOURCE_URI
    assert kinds["#/prompts/0/arguments/0/description"] is FieldKind.PROMPT_ARGUMENT


def test_nested_schemas_are_walked_recursively() -> None:
    doc = MetadataDocument(
        tools=[
            {
                "name": "t",
                "inputSchema": {
                    "properties": {
                        "outer": {
                            "properties": {"inner": {"description": "Deep payload."}}
                        }
                    }
                },
            }
        ]
    )
    assert (
        "#/tools/0/inputSchema/properties/outer/properties/inner/description"
        in texts_of(doc)
    )


def test_schema_combinators_are_walked() -> None:
    doc = MetadataDocument(
        tools=[
            {
                "name": "t",
                "inputSchema": {"anyOf": [{"description": "One."}, {"description": "Two."}]},
            }
        ]
    )
    texts = texts_of(doc)
    assert texts["#/tools/0/inputSchema/anyOf/0/description"] == "One."
    assert texts["#/tools/0/inputSchema/anyOf/1/description"] == "Two."


def test_schema_recursion_is_depth_capped() -> None:
    """A hostile server can nest forever; the walk must still terminate."""
    schema: dict = {"description": "leaf"}
    for _ in range(200):
        schema = {"properties": {"n": schema}}
    doc = MetadataDocument(tools=[{"name": "t", "inputSchema": schema}])
    assert list(walk_text(doc)) is not None  # terminates at all
    assert len(list(walk_text(doc))) < 200


@pytest.mark.parametrize("value", [None, 42, [], {}, True, ""])
def test_non_string_fields_are_skipped_not_crashed_on(value: object) -> None:
    """Every field is attacker-controlled and may be any JSON type."""
    doc = MetadataDocument(tools=[{"name": value, "description": value}])
    assert list(walk_text(doc)) == []


def test_the_walk_order_is_stable() -> None:
    doc = MetadataDocument(
        instructions="i",
        tools=[{"name": "a", "description": "d"}, {"name": "b"}],
    )
    once = [f.pointer for f in walk_text(doc)]
    twice = [f.pointer for f in walk_text(doc)]
    assert once == twice
    assert once[0] == "#/instructions"


# --------------------------------------------------------------------------
# locations: pointer only, path only, and both
# --------------------------------------------------------------------------
def test_a_live_server_alone_yields_a_pointer_and_no_path() -> None:
    doc = MetadataDocument(tools=[{"name": "t", "description": "Reads."}])
    field = next(f for f in walk_text(doc) if f.kind is FieldKind.TOOL_DESCRIPTION)
    location = field.locate()
    assert location.pointer == "#/tools/0/description"
    assert location.path is None
    assert location.start_line is None


def test_source_alone_yields_a_path_and_lines(tmp_path: Path) -> None:
    root = materialise(tmp_path, "poisoned_metadata")
    tools = extract_tools(load_tree(root))
    doc = MetadataDocument.from_source(tools)

    field = next(
        f
        for f in walk_text(doc)
        if f.kind is FieldKind.TOOL_DESCRIPTION and "IMPORTANT" in f.text
    )
    location = field.locate()
    assert location.path is not None
    assert location.start_line is not None
    # A pointer is still present -- it names the field within the document we
    # built, which is what a report needs to say *which* description this is.
    assert location.pointer == "#/tools/0/description"


def test_both_views_together_yield_both(tmp_path: Path) -> None:
    """The "both when both" requirement, end to end."""
    root = materialise(tmp_path, "poisoned_metadata")
    tools = extract_tools(load_tree(root))

    # A live server's listing: same tool names, independently served.
    served = MetadataDocument(
        tools=[
            {"name": "search", "description": "Searches the index."},
            {"name": "list_files", "description": "Lists files."},
        ]
    )
    merged = served.with_source(tools)

    field = next(f for f in walk_text(merged) if f.pointer == "#/tools/0/description")
    location = field.locate()

    assert location.pointer == "#/tools/0/description"
    assert location.start_line is not None
    # Relative to the scan root: an absolute path would leak the scanner's
    # filesystem layout and match nothing the developer recognises.
    assert location.path == Path("poisoned_metadata.py")
    assert not location.path.is_absolute()


def test_the_merge_keeps_the_served_text_not_the_source_text(tmp_path: Path) -> None:
    """The server's metadata is what a model receives; source only adds locations.

    A server whose source says one thing and whose wire says another is a finding
    for a later step, never a licence to report the source's version.
    """
    root = materialise(tmp_path, "poisoned_metadata")
    tools = extract_tools(load_tree(root))
    served = MetadataDocument(tools=[{"name": "search", "description": "Innocuous."}])

    merged = served.with_source(tools)
    assert merged.tools[0]["description"] == "Innocuous."


def test_a_tool_absent_from_source_simply_has_no_location(tmp_path: Path) -> None:
    root = materialise(tmp_path, "poisoned_metadata")
    tools = extract_tools(load_tree(root))
    served = MetadataDocument(tools=[{"name": "not_in_source", "description": "d"}])

    merged = served.with_source(tools)
    field = next(f for f in walk_text(merged) if f.pointer == "#/tools/0/description")
    assert field.locate().path is None
    assert field.locate().pointer == "#/tools/0/description"
