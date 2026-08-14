"""Reading tool definitions out of Python source with ``ast``.

Two jobs, both feeding the rules rather than doing any judging themselves:

**Finding the tools.** A source tree alone is enough to scan tool metadata -- no
container, no handshake, no target running at all -- which is what makes
``mcpscan scan --path`` worth having and what finally gives ``TargetKind.PATH``
something to do. :func:`extract_tools` recognises the decorator forms MCP servers
actually use and reads the name, title, description and schema out of each.

**Locating them precisely.** Every field carries the line range of the *string
literal* that defines it, not of the function that owns it. A finding that points
at ``server.py:42`` where line 42 is the ``def`` is a finding a developer has to
go hunting from; pointing at the docstring line is the difference between a
report and a chore.

Deliberately not clever. Descriptions are read from decorator keywords and
docstrings, which is how the frameworks work and how humans write them. A
description assembled at import time -- built by a loop, read from a file,
interpolated from config -- is invisible here, and that is exactly why
:meth:`MetadataDocument.with_source` treats a live survey as ground truth and
merely *attaches* these locations to it rather than trusting them as the metadata.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

#: Directories that are never the target's own code. Scanning a vendored
#: dependency tree produces findings against software the user did not write and
#: cannot fix, which is the fastest way to make a scanner's output ignorable.
SKIP_DIRS: Final = frozenset(
    {
        ".git", ".hg", ".svn", ".tox", ".nox", ".venv", "venv", "env",
        "__pycache__", "node_modules", "dist", "build", ".mypy_cache",
        ".pytest_cache", ".ruff_cache", "site-packages", ".eggs",
    }
)

#: Decorator attribute names that register a tool. `@mcp.tool()` is FastMCP;
#: `@app.call_tool()` is the low-level SDK; a bare `@tool` covers hand-rolled
#: registries that follow the same convention.
TOOL_DECORATORS: Final = frozenset({"tool", "call_tool", "add_tool"})
RESOURCE_DECORATORS: Final = frozenset({"resource", "read_resource"})
PROMPT_DECORATORS: Final = frozenset({"prompt", "get_prompt"})

FunctionDef = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class SourceTool:
    """A tool definition found in source, with per-field line ranges."""

    name: str
    path: Path
    func: FunctionDef
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    #: field name -> (start_line, end_line) of the literal that defines it.
    field_lines: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def parameters(self) -> list[str]:
        """Parameter names, excluding ``self`` and ``cls``.

        These are MCP-003's taint sources: everything a caller controls.
        """
        args = self.func.args
        names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
        if args.vararg is not None:
            names.append(args.vararg.arg)
        if args.kwarg is not None:
            names.append(args.kwarg.arg)
        return [name for name in names if name not in ("self", "cls")]


@dataclass(frozen=True, slots=True)
class SourceTree:
    """Every Python module under a root, parsed once.

    ``unparsed`` is reported rather than swallowed. A file we could not read is a
    coverage gap, and a scanner that silently skips it will report "clean" for a
    tree it never looked at -- which is worse than reporting nothing, because the
    user believes it.
    """

    root: Path
    modules: dict[Path, ast.Module] = field(default_factory=dict)
    unparsed: list[tuple[Path, str]] = field(default_factory=list)

    @property
    def file_count(self) -> int:
        return len(self.modules)


def python_files(root: Path) -> Iterator[Path]:
    """Every ``.py`` file under ``root``, skipping vendored and generated trees."""
    if root.is_file():
        if root.suffix == ".py":
            yield root
        return
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        yield path


def load_tree(root: Path) -> SourceTree:
    """Parse every Python file under ``root``. Never raises on bad input."""
    tree = SourceTree(root=root)
    for path in python_files(root):
        # Reported relative, like every other path in a finding: an absolute one
        # leaks the scanner's filesystem layout and matches nothing the
        # developer recognises. The key stays absolute -- that is what reads it.
        shown = relative_to_root(path, root)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            tree.unparsed.append((shown, f"unreadable: {exc}"))
            continue
        try:
            tree.modules[path] = ast.parse(text, filename=str(path))
        except (SyntaxError, ValueError, RecursionError) as exc:
            # A target is free to ship a file that does not parse -- a Python 2
            # leftover, a template, something generated. Not our error to raise.
            tree.unparsed.append((shown, f"{type(exc).__name__}: {exc}"))
    return tree


def dotted_name(node: ast.expr) -> str | None:
    """Render ``a.b.c`` from an attribute chain, or ``None`` if it is not one."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _decorator_call(decorator: ast.expr) -> tuple[str, ast.Call | None] | None:
    """Split a decorator into its final attribute name and its call, if any."""
    if isinstance(decorator, ast.Call):
        name = dotted_name(decorator.func)
        return (name.rsplit(".", 1)[-1], decorator) if name else None
    name = dotted_name(decorator)
    return (name.rsplit(".", 1)[-1], None) if name else None


def _keyword(call: ast.Call | None, name: str) -> ast.expr | None:
    if call is None:
        return None
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _string_of(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _lines_of(node: ast.expr) -> tuple[int, int]:
    return (node.lineno, node.end_lineno or node.lineno)


def _docstring(func: FunctionDef) -> tuple[str, tuple[int, int]] | None:
    """The docstring's text *and* its line range.

    ``ast.get_docstring`` returns the text and throws the position away, and the
    position is half the point: a finding that points at the ``def`` instead of
    the string is one a developer has to go hunting from.
    """
    if not func.body:
        return None
    first = func.body[0]
    if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Constant):
        return None
    value = first.value.value
    if not isinstance(value, str):
        return None
    return value, _lines_of(first.value)


def _literal(node: ast.expr | None) -> Any:
    """Best-effort literal evaluation. A non-literal schema is simply unknown."""
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def relative_to_root(path: Path, root: Path) -> Path:
    """A path as a reader of the target's repository would write it.

    Reports carry these verbatim, so an absolute path would leak the scanner's
    filesystem layout and would not match anything the developer recognises.
    SARIF wants relative URIs for the same reason, which matters at step 7.
    """
    try:
        return path.relative_to(root if root.is_dir() else root.parent)
    except ValueError:
        return path


def extract_tools(tree: SourceTree) -> list[SourceTool]:
    """Find every decorator-registered tool in ``tree``."""
    tools: list[SourceTool] = []
    for path, module in tree.modules.items():
        relative = relative_to_root(path, tree.root)
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                tool = _tool_from(node, relative, TOOL_DECORATORS)
                if tool is not None:
                    tools.append(tool)
    return tools


def extract_by_name(tree: SourceTree, names: set[str]) -> list[SourceTool]:
    """Find functions matching known tool names, however they were registered.

    The companion to :func:`extract_tools`, for when a live server has told us
    what its tools are called. A server whose registration pattern we do not
    recognise still has functions, and the survey names them.
    """
    found: list[SourceTool] = []
    seen: set[tuple[Path, str]] = set()
    for path, module in tree.modules.items():
        relative = relative_to_root(path, tree.root)
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in names or (relative, node.name) in seen:
                continue
            seen.add((relative, node.name))
            found.append(_describe(node, relative, node.name, None))
    return found


def _tool_from(func: FunctionDef, path: Path, decorators: frozenset[str]) -> SourceTool | None:
    for decorator in func.decorator_list:
        split = _decorator_call(decorator)
        if split is None:
            continue
        attr, call = split
        if attr not in decorators:
            continue
        name_node = _keyword(call, "name")
        name = _string_of(name_node) or func.name
        return _describe(func, path, name, call, name_node)
    return None


def _describe(
    func: FunctionDef,
    path: Path,
    name: str,
    call: ast.Call | None,
    name_node: ast.expr | None = None,
) -> SourceTool:
    """Read a tool's fields, recording where each literal lives."""
    lines: dict[str, tuple[int, int]] = {}

    if name_node is not None:
        lines["name"] = _lines_of(name_node)

    title_node = _keyword(call, "title")
    title = _string_of(title_node)
    if title_node is not None and title is not None:
        lines["title"] = _lines_of(title_node)

    # A `description=` keyword wins over the docstring, matching how the
    # frameworks resolve it -- the explicit argument is what gets served.
    description_node = _keyword(call, "description")
    description = _string_of(description_node)
    if description is not None and description_node is not None:
        lines["description"] = _lines_of(description_node)
    else:
        docstring = _docstring(func)
        if docstring is not None:
            description, lines["description"] = docstring

    schema_node = _keyword(call, "inputSchema") or _keyword(call, "input_schema")
    schema = _literal(schema_node)
    if schema_node is not None and isinstance(schema, dict):
        lines["inputSchema"] = _lines_of(schema_node)
    else:
        schema = None

    return SourceTool(
        name=name,
        path=path,
        func=func,
        title=title,
        description=description,
        input_schema=schema,
        field_lines=lines,
    )
