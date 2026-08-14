"""Reading tool definitions out of source, and pointing at the right line.

The line ranges are the part worth testing hardest. A finding that points at the
``def`` when the payload is in the docstring is a finding a developer has to go
hunting from, and the difference between the two is one AST attribute nobody
notices is wrong until they are staring at the wrong line.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from mcpscan.source import (
    SourceTree,
    extract_by_name,
    extract_tools,
    load_tree,
    python_files,
)
from tests.sourcefixtures import materialise


def tools_from(source: str) -> list:
    module = ast.parse(source)
    tree = SourceTree(root=Path("."), modules={Path("s.py"): module})
    return extract_tools(tree)


# --------------------------------------------------------------------------
# decorator recognition
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "decorator",
    [
        "@mcp.tool()",
        "@mcp.tool",
        "@server.tool()",
        "@app.tool(name='x')",
        "@app.call_tool()",
        "@tool",
        "@tool()",
        "@self.mcp.tool()",
    ],
)
def test_tool_decorator_forms_are_recognised(decorator: str) -> None:
    tools = tools_from(f"{decorator}\ndef search(q: str):\n    'Searches.'\n")
    assert len(tools) == 1, decorator


def test_an_unrelated_decorator_is_not_a_tool() -> None:
    assert tools_from("@app.route('/x')\ndef search(q):\n    'Searches.'\n") == []


def test_an_undecorated_function_is_not_a_tool() -> None:
    assert tools_from("def search(q):\n    'Searches.'\n") == []


def test_async_tools_are_found() -> None:
    tools = tools_from("@mcp.tool()\nasync def search(q: str):\n    'Searches.'\n")
    assert len(tools) == 1


# --------------------------------------------------------------------------
# field resolution
# --------------------------------------------------------------------------
def test_the_docstring_becomes_the_description() -> None:
    tool = tools_from("@mcp.tool()\ndef search(q):\n    'Searches the index.'\n")[0]
    assert tool.name == "search"
    assert tool.description == "Searches the index."


def test_an_explicit_description_wins_over_the_docstring() -> None:
    """Matches how the frameworks resolve it: the keyword is what gets served."""
    tool = tools_from(
        "@mcp.tool(description='Served text.')\ndef search(q):\n    'Docstring text.'\n"
    )[0]
    assert tool.description == "Served text."


def test_an_explicit_name_wins_over_the_function_name() -> None:
    tool = tools_from("@mcp.tool(name='fetch')\ndef fetch_impl(u):\n    'Fetches.'\n")[0]
    assert tool.name == "fetch"


def test_title_and_schema_are_read_when_present() -> None:
    tool = tools_from(
        "@mcp.tool(title='Search', inputSchema={'type': 'object'})\n"
        "def search(q):\n    'Searches.'\n"
    )[0]
    assert tool.title == "Search"
    assert tool.input_schema == {"type": "object"}


def test_a_non_literal_schema_is_simply_unknown() -> None:
    """A schema built at runtime is invisible here, and that is not an error."""
    tool = tools_from(
        "@mcp.tool(inputSchema=build_schema())\ndef search(q):\n    'Searches.'\n"
    )[0]
    assert tool.input_schema is None


def test_a_tool_with_no_docstring_has_no_description() -> None:
    tool = tools_from("@mcp.tool()\ndef search(q):\n    return 1\n")[0]
    assert tool.description is None


# --------------------------------------------------------------------------
# line ranges -- the half that makes a finding actionable
# --------------------------------------------------------------------------
def test_the_description_line_points_at_the_docstring_not_the_def() -> None:
    source = "@mcp.tool()\ndef search(q):\n    'Searches the index.'\n    return 1\n"
    tool = tools_from(source)[0]
    assert tool.func.lineno == 2
    assert tool.field_lines["description"] == (3, 3)


def test_a_multiline_docstring_reports_its_full_range() -> None:
    source = '@mcp.tool()\ndef search(q):\n    """Line one.\n\n    Line three.\n    """\n'
    tool = tools_from(source)[0]
    assert tool.field_lines["description"] == (3, 6)


def test_a_keyword_description_points_at_the_keyword() -> None:
    source = "@mcp.tool(\n    description='Served.',\n)\ndef search(q):\n    'Doc.'\n"
    tool = tools_from(source)[0]
    assert tool.field_lines["description"] == (2, 2)


def test_the_name_line_is_recorded_only_when_explicit() -> None:
    explicit = tools_from("@mcp.tool(name='fetch')\ndef f(u):\n    'F.'\n")[0]
    implicit = tools_from("@mcp.tool()\ndef fetch(u):\n    'F.'\n")[0]
    assert explicit.field_lines["name"] == (1, 1)
    assert "name" not in implicit.field_lines


# --------------------------------------------------------------------------
# parameters -- MCP-003's taint sources
# --------------------------------------------------------------------------
def test_parameters_exclude_self_and_cls() -> None:
    tool = tools_from("@mcp.tool()\ndef search(self, q, *args, **kw):\n    'S.'\n")[0]
    assert tool.parameters == ["q", "args", "kw"]


def test_keyword_only_parameters_are_included() -> None:
    tool = tools_from("@mcp.tool()\ndef search(a, *, b, c=1):\n    'S.'\n")[0]
    assert tool.parameters == ["a", "b", "c"]


# --------------------------------------------------------------------------
# tree loading
# --------------------------------------------------------------------------
def test_vendored_directories_are_skipped(tmp_path: Path) -> None:
    """Findings against a vendored dependency are ones the user cannot act on."""
    root = tmp_path / "target"
    (root / ".venv" / "lib").mkdir(parents=True)
    (root / "node_modules").mkdir(parents=True)
    (root / "src").mkdir(parents=True)
    (root / ".venv" / "lib" / "dep.py").write_text("x = 1\n")
    (root / "node_modules" / "mod.py").write_text("x = 1\n")
    (root / "src" / "server.py").write_text("x = 1\n")

    assert [p.name for p in python_files(root)] == ["server.py"]


def test_an_unparseable_file_is_reported_not_swallowed(tmp_path: Path) -> None:
    """A file we could not read is a coverage gap, and a scan that hides it
    reports "clean" for a tree it never looked at."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "good.py").write_text("@mcp.tool()\ndef a(q):\n    'A.'\n")
    (root / "broken.py").write_text("def (:\n")

    tree = load_tree(root)
    assert tree.file_count == 1
    assert len(tree.unparsed) == 1
    assert tree.unparsed[0][0].name == "broken.py"
    assert "SyntaxError" in tree.unparsed[0][1]


def test_a_single_file_root_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "server.py"
    path.write_text("@mcp.tool()\ndef a(q):\n    'A.'\n")
    assert extract_tools(load_tree(path))[0].name == "a"


def test_extract_by_name_finds_tools_registered_some_other_way() -> None:
    """A server whose registration pattern we do not recognise still has functions,
    and a live survey names them."""
    module = ast.parse("def search(q):\n    'Searches.'\ndef helper(x):\n    pass\n")
    tree = SourceTree(root=Path("."), modules={Path("s.py"): module})

    found = extract_by_name(tree, {"search"})
    assert [t.name for t in found] == ["search"]
    assert found[0].description == "Searches."


# --------------------------------------------------------------------------
# the fixture tree
# --------------------------------------------------------------------------
def test_the_poisoned_fixture_extracts_every_tool(tmp_path: Path) -> None:
    root = materialise(tmp_path, "poisoned_metadata")
    tools = extract_tools(load_tree(root))
    assert {t.name for t in tools} == {
        "search",
        "list_files",
        "summarise",
        "translate",
        "fetch",
    }


def test_the_poisoned_fixture_line_ranges_land_on_the_strings(tmp_path: Path) -> None:
    root = materialise(tmp_path, "poisoned_metadata")
    text = (root / "poisoned_metadata.py").read_text().splitlines()
    tools = {t.name: t for t in extract_tools(load_tree(root))}

    start, _ = tools["search"].field_lines["description"]
    assert "Searches the index" in text[start - 1]

    start, _ = tools["list_files"].field_lines["description"]
    assert "description=" in text[start - 1]
