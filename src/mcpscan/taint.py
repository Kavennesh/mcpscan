"""MCP-003 -- tracing a tool's parameters into a dangerous call.

``ast`` only, never a regex. A regex over source finds the string
``subprocess.run(cmd)`` and cannot tell you whether ``cmd`` came from the caller,
from a config file, or from a literal three lines up -- and that difference is the
entire finding. Only a parse knows.

Every parameter of a tool function is attacker-controlled: the model chooses the
arguments, and the model is reading descriptions written by the same server. So
taint starts at the parameters and is followed forward through assignment, string
building and formatting until it either reaches a sink or is killed by a
sanitiser or a rebind.

**A note on how the sinks are named.** ``CLAUDE.md`` constraint 2 says
``subprocess``, ``os.system`` and the rest appear in ``sandbox.py`` and nowhere
else, and ``tests/test_containment.py`` enforces it with an AST walk. This module
has to talk about those functions without ever *being* a way to call them, so
every sink below is a plain string compared against a dotted name recovered from
the target's AST. There is no import and no attribute access here, which is the
same distinction the containment suite already draws in its own
``test_benign_lookalikes_are_not_flagged``.

Limits, stated here rather than discovered from a false negative later:

*Intraprocedural.* A parameter handed to a helper that calls the sink is not
followed. This is the largest gap and the obvious next increment.

*Path-insensitive.* Statements are visited in order with no branch modelling, so
a guard like ``if path not in ALLOWED: raise`` does not clear taint. A correctly
validated parameter can still be reported -- deliberately the safe direction, but
it is why the sanitiser list matters.

*No alias analysis* beyond conservative subscript and attribute propagation:
putting a tainted value into a dict taints the dict, and everything read back out
of it.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from mcpscan.engine import RuleMeta
from mcpscan.models import Confidence, Finding, Location, Severity
from mcpscan.source import SourceTool, SourceTree, dotted_name

#: Dotted names that execute a command. Strings, never attribute access -- see
#: the module docstring.
COMMAND_SINKS: Final = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.spawnl",
        "os.spawnv",
        "os.spawnve",
        "os.posix_spawn",
        "commands.getoutput",
    }
)

#: Dotted names that execute code.
CODE_SINKS: Final = frozenset({"eval", "exec", "compile", "__import__"})

#: Reads or writes a path. Only a finding when the path is not a constant.
PATH_SINKS: Final = frozenset({"open", "io.open", "pathlib.Path", "os.remove", "os.unlink"})

#: Calls that render a value safe for the sinks above. Without these the rule's
#: name is a lie -- "unsanitised" has to be able to be false.
SANITISERS: Final = frozenset(
    {
        "shlex.quote",
        "shlex.split",
        "os.path.basename",
        "posixpath.basename",
        "re.escape",
        "regex.escape",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "html.escape",
        "int",
        "float",
        "bool",
        "len",
    }
)

#: String operations that carry taint from receiver or arguments to the result.
_PROPAGATING_METHODS: Final = frozenset(
    {"format", "join", "replace", "strip", "lstrip", "rstrip", "lower", "upper", "title"}
)

#: Mapping lookups. Their arguments are *keys*, not values, so a tainted key
#: against a clean container yields a clean result -- the parameter selects a
#: value rather than becoming one. This is the allowlist pattern, and it is the
#: main way a careful server makes a caller-supplied name safe, so failing to
#: model it would report every correctly-written tool.
#:
#: Consistent with `ast.Subscript`, where taint already follows the container
#: rather than the key: `ALLOWED[name]` and `ALLOWED.get(name)` are the same
#: operation and now behave the same way.
_LOOKUP_METHODS: Final = frozenset({"get", "setdefault"})


@dataclass(frozen=True, slots=True)
class TaintHit:
    """One tainted value reaching one sink."""

    sink: str
    parameter: str
    node: ast.Call
    shell: bool
    kind: str


class _TaintScope:
    """Forward taint within a single function body."""

    __slots__ = ("hits", "tainted")

    def __init__(self, parameters: Sequence[str]) -> None:
        #: variable name -> the originating parameter, so a finding can say which.
        self.tainted: dict[str, str] = {name: name for name in parameters}
        self.hits: list[TaintHit] = []

    # -- taint of an expression -----------------------------------------
    def origin(self, node: ast.expr | None) -> str | None:
        """Which parameter, if any, this expression carries. ``None`` if clean."""
        if node is None:
            return None

        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)

        if isinstance(node, ast.JoinedStr):  # f"..."
            return self._first(node.values)

        if isinstance(node, ast.FormattedValue):
            return self.origin(node.value)

        if isinstance(node, ast.BinOp):  # a + b, "%s" % a
            return self.origin(node.left) or self.origin(node.right)

        if isinstance(node, (ast.Subscript, ast.Attribute, ast.Starred)):
            return self.origin(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._first(node.elts)

        if isinstance(node, ast.Dict):
            return self._first([v for v in node.values if v is not None])

        if isinstance(node, (ast.IfExp,)):
            return self.origin(node.body) or self.origin(node.orelse)

        if isinstance(node, ast.Call):
            return self._call_origin(node)

        return None

    def _first(self, nodes: Sequence[ast.expr]) -> str | None:
        for node in nodes:
            found = self.origin(node)
            if found is not None:
                return found
        return None

    def _call_origin(self, node: ast.Call) -> str | None:
        """Taint through a call, unless the call is a sanitiser."""
        name = dotted_name(node.func)
        if name is not None:
            tail = name.rsplit(".", 1)[-1]
            if name in SANITISERS or tail in SANITISERS:
                return None
            # A lookup's arguments are keys. Taint follows the container only.
            if tail in _LOOKUP_METHODS and isinstance(node.func, ast.Attribute):
                return self.origin(node.func.value)
            # str(x), "".join(x), x.format(y) -- carry the taint through.
            if name == "str" or tail in _PROPAGATING_METHODS:
                return self._first([*node.args, *(k.value for k in node.keywords)]) or (
                    self.origin(node.func.value) if isinstance(node.func, ast.Attribute) else None
                )
        # An unknown call is not assumed to launder its arguments; a helper that
        # happens to sanitise is a false positive we accept over the alternative.
        if isinstance(node.func, ast.Attribute):
            receiver = self.origin(node.func.value)
            if receiver is not None:
                return receiver
        return self._first([*node.args, *(k.value for k in node.keywords)])

    # -- statement walking ----------------------------------------------
    def visit_body(self, body: Sequence[ast.stmt]) -> None:
        for statement in body:
            self.visit(statement)

    def visit(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            origin = self.origin(node.value)
            for target in node.targets:
                self._bind(target, origin)
        elif isinstance(node, ast.AugAssign):
            origin = self.origin(node.value) or self.origin(node.target)
            self._bind(node.target, origin)
        elif isinstance(node, ast.AnnAssign):
            self._bind(node.target, self.origin(node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind(node.target, self.origin(node.iter))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._check_expr(item.context_expr)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, self.origin(item.context_expr))

        for expression in _expressions_of(node):
            self._check_expr(expression)

        for child in _nested_bodies(node):
            self.visit_body(child)

    def _bind(self, target: ast.expr, origin: str | None) -> None:
        """Assign taint to a target, *killing* it when the value is clean."""
        if isinstance(target, ast.Name):
            if origin is None:
                self.tainted.pop(target.id, None)
            else:
                self.tainted[target.id] = origin
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Conservative: we cannot tell which element went where.
            for element in target.elts:
                self._bind(element, origin)
        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            if origin is not None:
                container = target.value
                if isinstance(container, ast.Name):
                    self.tainted[container.id] = origin

    def _check_expr(self, node: ast.expr) -> None:
        for call in _calls_in(node):
            self._check_call(call)

    def _check_call(self, node: ast.Call) -> None:
        name = dotted_name(node.func)
        if name is None:
            return
        tail = name.rsplit(".", 1)[-1]

        if name in COMMAND_SINKS or (tail in {"system", "popen"} and name.startswith("os.")):
            origin = self._first([*node.args, *(k.value for k in node.keywords)])
            if origin is not None:
                self.hits.append(
                    TaintHit(name, origin, node, shell=_is_shell(node), kind="command")
                )
            return

        if name in CODE_SINKS:
            origin = self._first(node.args)
            if origin is not None:
                self.hits.append(TaintHit(name, origin, node, shell=False, kind="code"))
            return

        if name in PATH_SINKS:
            if not node.args:
                return
            path_arg = node.args[0]
            if isinstance(path_arg, ast.Constant):
                # A constant path is not attacker-controlled, whatever else is.
                return
            origin = self.origin(path_arg)
            if origin is not None:
                self.hits.append(TaintHit(name, origin, node, shell=False, kind="path"))


def _is_shell(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "shell":
            return isinstance(keyword.value, ast.Constant) and keyword.value.value is True
    return False


def _calls_in(node: ast.expr) -> Iterator[ast.Call]:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            yield child


def _expressions_of(node: ast.stmt) -> Iterator[ast.expr]:
    """Every expression directly owned by a statement, each exactly once.

    "Exactly once" is the part worth stating: ``ast.Return`` stores its
    expression in ``.value`` like everything else, so a separate branch for it
    yields the same node twice and every ``return sink(tainted)`` becomes two
    identical findings.
    """
    for name in ("value", "test", "iter", "exc", "cause", "msg"):
        child = getattr(node, name, None)
        if isinstance(child, ast.expr):
            yield child
    for name in ("values", "targets"):
        children = getattr(node, name, None)
        if isinstance(children, list):
            for child in children:
                if isinstance(child, ast.expr):
                    yield child


def _nested_bodies(node: ast.stmt) -> Iterator[list[ast.stmt]]:
    """Bodies to walk in the same scope. Nested functions are their own scope."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    for name in ("body", "orelse", "finalbody"):
        children = getattr(node, name, None)
        if isinstance(children, list) and children and isinstance(children[0], ast.stmt):
            yield children
    handlers = getattr(node, "handlers", None)
    if isinstance(handlers, list):
        for handler in handlers:
            if isinstance(handler, ast.ExceptHandler):
                yield handler.body


def analyse_tool(tool: SourceTool) -> list[TaintHit]:
    """Every tainted parameter reaching a sink inside one tool function."""
    scope = _TaintScope(tool.parameters)
    scope.visit_body(tool.func.body)
    return scope.hits


class UnsanitisedSinkRule:
    """MCP-003 -- a tool parameter reaching a dangerous call unsanitised."""

    meta = RuleMeta(
        id="MCP-003",
        title="Tool parameter reaches a dangerous sink unsanitised",
        severity=Severity.CRITICAL,
        remediation=(
            "Do not pass a tool parameter into a shell, an interpreter, or a "
            "filesystem path without constraining it first. Prefer an allowlist "
            "lookup over interpolation; where a shell is unavoidable, quote with "
            "shlex.quote. The model chooses these arguments, and it is reading "
            "descriptions written by the same server."
        ),
    )

    def check(self, tree: SourceTree, tools: Sequence[SourceTool]) -> Iterator[Finding]:
        for tool in tools:
            for hit in analyse_tool(tool):
                yield self._finding(tree, tool, hit)

    def _finding(self, tree: SourceTree, tool: SourceTool, hit: TaintHit) -> Finding:
        severity, confidence = _rank(hit)
        path = _relative(tool.path, tree.root)
        location = Location(
            path=path,
            start_line=hit.node.lineno,
            end_line=hit.node.end_lineno or hit.node.lineno,
        )
        parameter = Location(
            path=path,
            start_line=tool.func.lineno,
            end_line=tool.func.lineno,
        )

        shell = " with shell=True" if hit.shell else ""
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            severity=severity,
            confidence=confidence,
            message=(
                f"Parameter {hit.parameter!r} of tool {tool.name!r} reaches "
                f"{hit.sink}(){shell} without sanitisation."
            ),
            location=location,
            related=[parameter],
            evidence=_unparse(hit.node),
            remediation=self.meta.remediation,
            help_uri=self.meta.help_uri,
            metadata={
                "sink": hit.sink,
                "parameter": hit.parameter,
                "tool": tool.name,
                "shell": hit.shell,
                "sink_kind": hit.kind,
            },
        )


def _rank(hit: TaintHit) -> tuple[Severity, Confidence]:
    if hit.kind == "command":
        if hit.shell:
            # A tainted string through a shell is command injection outright.
            return Severity.CRITICAL, Confidence.HIGH
        return Severity.HIGH, Confidence.HIGH
    if hit.kind == "code":
        return Severity.CRITICAL, Confidence.HIGH
    # A tool that opens a caller-supplied path is often doing its job; the
    # finding is that nothing constrains it, which is worth less certainty.
    return Severity.MEDIUM, Confidence.MEDIUM


def _relative(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError, RecursionError):
        return "<unrenderable>"
