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

#: Decorator attribute names that register a tool. `@mcp.tool()` is FastMCP; a
#: bare `@tool` covers hand-rolled registries that follow the same convention.
#:
#: `call_tool` used to be in here and must never come back. In the low-level SDK
#: `@server.call_tool()` decorates the **dispatcher** -- one function that routes
#: every tool by name -- so treating it as a tool produced exactly one "tool"
#: called `call_tool` for a server with twelve, and, far worse, left
#: `subject.tools` non-empty so MCP-003 reported as having *run*. See
#: `DISPATCHER_DECORATORS`, which is where it went.
TOOL_DECORATORS: Final = frozenset({"tool", "add_tool"})

#: Decorators on the low-level SDK's router. Not a tool: a taint entry point,
#: because its `arguments` parameter is what the caller controls.
DISPATCHER_DECORATORS: Final = frozenset({"call_tool"})

#: Decorators on the low-level SDK's tool *declaration* function, whose body
#: returns `Tool(...)` objects rather than being a tool itself.
LISTER_DECORATORS: Final = frozenset({"list_tools"})

#: The class whose construction declares a tool, matched on the last dotted
#: segment so `Tool(...)` and `types.Tool(...)` both count.
DECLARATION_CLASS: Final = "Tool"

RESOURCE_DECORATORS: Final = frozenset({"resource", "read_resource"})
PROMPT_DECORATORS: Final = frozenset({"prompt", "get_prompt"})

FunctionDef = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class SourceTool:
    """A tool definition found in source, with per-field line ranges."""

    name: str
    path: Path
    #: The function that implements this tool, when there is one. ``None`` for a
    #: tool *declared* as a `Tool(...)` object: the low-level SDK separates the
    #: declaration from the handler, and the handler is reached by name at
    #: runtime through a dispatcher. Such a tool has metadata and no body, which
    #: is exactly what MCP-001 and MCP-002 need and what MCP-003 cannot use.
    func: FunctionDef | None = None
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    #: field name -> (start_line, end_line) of the literal that defines it.
    field_lines: dict[str, tuple[int, int]] = field(default_factory=dict)
    #: False when `name` is the source expression rather than a resolved string,
    #: e.g. `name=self.name`. The tool is still reported -- its description is
    #: the part the metadata rules read -- but nothing should match on the name.
    name_resolved: bool = True

    @property
    def parameters(self) -> list[str]:
        """Parameter names, excluding ``self`` and ``cls``.

        These are MCP-003's taint sources: everything a caller controls.
        """
        if self.func is None:
            return []
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
    #: (kind, detail) for things read but not understood -- a declaration shape
    #: no pattern matched, a language not analysed at all. Beside `unparsed`
    #: rather than inside it because those files parsed fine; what failed was
    #: our recognition, and a scan that cannot say so reports a clean bill of
    #: health for a file it looked straight at.
    notes: list[tuple[str, str]] = field(default_factory=list)

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

    _note_unread_languages(tree, root)
    return tree


#: Extensions an MCP server is commonly written in that this analyser cannot
#: read. Not a promise to support them -- a way to stop claiming a clean scan of
#: a tree nothing ever opened.
UNREAD_SUFFIXES: Final = frozenset({".ts", ".tsx", ".js", ".mjs", ".cjs"})


def _note_unread_languages(tree: SourceTree, root: Path) -> None:
    """Say so when a tree's servers are written in a language we do not read.

    Four of the corpus repositories are TypeScript with no Python at all, and a
    scan of one reported that MCP-001 and MCP-002 ran and found nothing -- which
    reads as a clean bill of health for a directory the analyser never opened.
    The rules genuinely did run; there was simply nothing for them to run on,
    and only this note can tell the two apart.
    """
    if root.is_file() or tree.modules:
        return
    counts: dict[str, int] = {}
    for path in root.rglob("*"):
        if path.suffix not in UNREAD_SUFFIXES or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        counts[path.suffix] = counts.get(path.suffix, 0) + 1
    if not counts:
        return
    listed = ", ".join(f"{count} {suffix}" for suffix, count in sorted(counts.items()))
    tree.notes.append(
        (
            "unread_language",
            f"No Python was found, but this tree holds {listed} file(s). mcpscan "
            "reads Python source only, so nothing here was analysed -- this is "
            "not a clean result.",
        )
    )


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
    """Every tool in ``tree``, however it was registered.

    Two shapes, because MCP has two SDKs. FastMCP decorates a function per tool;
    the low-level SDK declares `Tool(...)` objects in one function and routes to
    handlers by name in another. Both end up as :class:`SourceTool`, the second
    kind without a `func`.

    Notes are recorded on the tree for a third case: a declaration function we
    recognised and could not read. Reporting nothing for it would be the bug
    this whole step exists to fix, one level along.
    """
    tools: list[SourceTool] = []
    for path, module in tree.modules.items():
        relative = relative_to_root(path, tree.root)
        constants = _module_strings(module)
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            decorated = _tool_from(node, relative, TOOL_DECORATORS)
            if decorated is not None:
                tools.append(decorated)

            declared = [
                tool
                for call in _declaration_calls(node)
                if (tool := _declared_tool(call, relative, constants)) is not None
            ]
            tools.extend(declared)

            if not declared and _decorated_with(node, LISTER_DECORATORS):
                tree.notes.append(
                    (
                        "unreadable_tool_shape",
                        f"{relative}:{node.lineno} declares tools in a shape mcpscan "
                        f"cannot read -- {node.name}() returned no literal Tool(...). "
                        "Its tool metadata was not scanned.",
                    )
                )
    return tools


def _decorated_with(func: FunctionDef, decorators: frozenset[str]) -> bool:
    for decorator in func.decorator_list:
        split = _decorator_call(decorator)
        if split is not None and split[0] in decorators:
            return True
    return False


def dispatchers(tree: SourceTree) -> list[SourceTool]:
    """Every low-level SDK router in ``tree``.

    Not tools -- a dispatcher implements all of them and none of them -- but the
    place a caller's arguments enter the program, which makes it MCP-003's other
    entry point. Returned as `SourceTool` only to reuse `parameters`.
    """
    found: list[SourceTool] = []
    for path, module in tree.modules.items():
        relative = relative_to_root(path, tree.root)
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                router = _tool_from(node, relative, DISPATCHER_DECORATORS)
                if router is not None:
                    found.append(router)
    return found


def _own_returns(func: FunctionDef) -> Iterator[ast.Return]:
    """Return statements in this function's own scope.

    ``ast.walk`` is flat, so skipping a nested ``FunctionDef`` node still yields
    its children -- a tool declared in a `list_tools` nested inside `serve()`
    would be attributed to both and counted twice. The subtree has to be pruned,
    which is what `taint._nested_bodies` does for the same reason.
    """

    def walk(body: list[ast.stmt]) -> Iterator[ast.Return]:
        for statement in body:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if isinstance(statement, ast.Return) and statement.value is not None:
                yield statement
            for attribute in ("body", "orelse", "finalbody"):
                yield from walk(getattr(statement, attribute, None) or [])
            for handler in getattr(statement, "handlers", None) or []:
                yield from walk(handler.body)

    yield from walk(func.body)


def _declaration_calls(func: FunctionDef) -> list[ast.Call]:
    """``Tool(...)`` constructions this function returns.

    A return statement rather than any construction anywhere: a function whose
    job is to hand back a tool declaration is saying so, while a `Tool(...)`
    built as a local or in a test helper is not a server's tool surface.
    """
    calls: list[ast.Call] = []
    for statement in _own_returns(func):
        if statement.value is None:  # pragma: no cover - filtered in _own_returns
            continue
        for node in ast.walk(statement.value):
            if not isinstance(node, ast.Call):
                continue
            name = dotted_name(node.func)
            if name is not None and name.rsplit(".", 1)[-1] == DECLARATION_CLASS:
                calls.append(node)
    return calls


def _module_strings(module: ast.Module) -> dict[str, str]:
    """Module-level string constants and ``str``-Enum members, by dotted name.

    Enough to resolve `name=GitTools.STATUS` and `name=TimeTools.X.value`, which
    is how the reference servers name their tools. Measured over the corpus this
    recovers 28 names that would otherwise be unresolved; 275 are already plain
    literals and 33 stay out of reach.
    """
    found: dict[str, str] = {}
    for node in module.body:
        if isinstance(node, ast.Assign):
            text = _string_of(node.value)
            if text is not None:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        found[target.id] = text
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                text = _string_of(item.value)
                if text is None:
                    continue
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        found[f"{node.name}.{target.id}"] = text
    return found


def _resolve_name(node: ast.expr | None, constants: dict[str, str]) -> tuple[str, bool]:
    """A tool's name, and whether we actually resolved it."""
    if node is None:
        return "", False
    text = _string_of(node)
    if text is not None:
        return text, True
    reference = dotted_name(node)
    if reference is None:
        return "", False
    if reference in constants:
        return constants[reference], True
    # `TimeTools.GET_CURRENT_TIME.value` -- an enum member spelt out in full.
    trimmed = reference.removesuffix(".value")
    if trimmed in constants:
        return constants[trimmed], True
    # Keep the tool. Its description is what the metadata rules read, and losing
    # a real tool because we could not name it is the larger error.
    return reference, False


def _declared_tool(
    call: ast.Call, path: Path, constants: dict[str, str]
) -> SourceTool | None:
    """One ``Tool(name=..., description=..., inputSchema=...)`` declaration.

    ``None`` when nothing in it could be read. A comprehension over runtime
    handlers -- `Tool(name=t.name, description=t.description)`, which is how
    `mcp-snowflake-server` builds its list -- yields a shape with no name and no
    description: not a tool anyone can scan, and reporting it as one would put an
    empty row in the document while hiding that we read nothing. The caller
    turns that into a note instead.
    """
    lines: dict[str, tuple[int, int]] = {}

    name_node = _keyword(call, "name")
    name, resolved = _resolve_name(name_node, constants)
    if name_node is not None and resolved and _string_of(name_node) is not None:
        lines["name"] = _lines_of(name_node)

    title_node = _keyword(call, "title")
    title = _string_of(title_node)
    if title_node is not None and title is not None:
        lines["title"] = _lines_of(title_node)

    description_node = _keyword(call, "description")
    description = _string_of(description_node)
    if description_node is not None and description is not None:
        lines["description"] = _lines_of(description_node)

    schema_node = _keyword(call, "inputSchema") or _keyword(call, "input_schema")
    schema = _literal(schema_node)
    if schema_node is not None and isinstance(schema, dict):
        lines["inputSchema"] = _lines_of(schema_node)
    else:
        schema = None

    if not resolved and description is None:
        return None

    return SourceTool(
        name=name,
        path=path,
        func=None,
        title=title,
        description=description,
        input_schema=schema,
        field_lines=lines,
        name_resolved=resolved,
    )


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
