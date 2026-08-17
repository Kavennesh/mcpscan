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

*One call deep, and only within a module.* The low-level SDK splits a tool in
two -- a dispatcher reads ``arguments["repo_path"]`` and hands it to a handler
that does the work -- so stopping at the dispatcher missed MCP-003 entirely on
every server built that way. A call to a function defined in the same file is
followed once, with the tainted arguments bound to its parameters. A handler that
delegates again is not followed, and neither is one imported from another module:
a finding's path comes from the tool, so a cross-file hop would report the
callee's line against the caller's file. Both limits are judgements about the
shapes servers actually take, not principles.

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
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from mcpscan.engine import RuleMeta
from mcpscan.models import Confidence, Finding, Location, Severity
from mcpscan.source import (
    FunctionDef,
    SourceTool,
    SourceTree,
    dispatchers,
    dotted_name,
    relative_to_root,
)

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


#: How many calls deep taint is followed. One: dispatcher -> handler is the
#: shape the low-level SDK produces, and a handler that delegates again is
#: missed. A judgement, not a principle -- stated here and on the rule page
#: rather than left for a reader to infer from behaviour.
MAX_CALL_DEPTH: Final = 1


@dataclass(frozen=True, slots=True)
class TaintHit:
    """One tainted value reaching one sink."""

    sink: str
    parameter: str
    node: ast.Call
    shell: bool
    kind: str


class _TaintScope:
    """Forward taint within a single function body, and one call beyond it."""

    __slots__ = ("depth", "hits", "callees", "tainted", "visiting")

    def __init__(
        self,
        parameters: Sequence[str],
        callees: Mapping[str, FunctionDef] | None = None,
        depth: int = 0,
        visiting: frozenset[str] = frozenset(),
    ) -> None:
        #: variable name -> the originating parameter, so a finding can say which.
        self.tainted: dict[str, str] = {name: name for name in parameters}
        self.hits: list[TaintHit] = []
        #: Functions defined in the same module, by name. Same module only: a
        #: finding's path comes from the tool, so following a call into another
        #: file would report the callee's line number against the caller's file.
        self.callees: Mapping[str, FunctionDef] = callees or {}
        self.depth = depth
        #: Names already on the stack, so a recursive handler cannot loop.
        self.visiting = visiting

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
            return

        self._follow(name, node)

    def _follow(self, name: str, node: ast.Call) -> None:
        """Step into a same-module callee, once, carrying the taint with us.

        The low-level SDK splits a tool in two: a dispatcher reads
        ``arguments["repo_path"]`` and hands it to a handler that does the work.
        Intraprocedural analysis sees a tainted value go into a call it does not
        recognise as a sink and stops, which is the whole of MCP-003 missing on
        every server built that way.

        One hop, and only within the module. Depth is a judgement rather than a
        principle -- it is the shape the SDK produces -- and the limit is written
        down in the module docstring and on the rule's page rather than implied.
        """
        if self.depth >= MAX_CALL_DEPTH:
            return
        callee = self.callees.get(name.rsplit(".", 1)[-1])
        if callee is None or callee.name in self.visiting:
            return

        bound = self._bindings(callee, node)
        if not bound:
            return

        inner = _TaintScope(
            (),
            callees=self.callees,
            depth=self.depth + 1,
            visiting=self.visiting | {callee.name},
        )
        inner.tainted.update(bound)
        inner.visit_body(callee.body)
        self.hits.extend(inner.hits)

    def _bindings(self, callee: FunctionDef, node: ast.Call) -> dict[str, str]:
        """Which of the callee's parameters receive a tainted argument.

        Positional by position and keyword by name, so the reported parameter
        stays the *caller's* -- a finding that named the handler's local
        parameter would lose the fact that the value came from the wire.
        """
        args = callee.args
        names = [a.arg for a in (*args.posonlyargs, *args.args)]
        bound: dict[str, str] = {}

        for index, argument in enumerate(node.args):
            origin = self.origin(argument)
            if origin is not None and index < len(names):
                bound[names[index]] = origin

        keyword_names = {a.arg for a in args.kwonlyargs} | set(names)
        for keyword in node.keywords:
            if keyword.arg is None or keyword.arg not in keyword_names:
                continue
            origin = self.origin(keyword.value)
            if origin is not None:
                bound[keyword.arg] = origin

        return bound


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


def module_functions(module: ast.Module) -> dict[str, FunctionDef]:
    """Top-level and class-level functions by name, for one-hop call following.

    Names collide across classes; the first definition wins, which is the same
    over-approximation `extract_by_name` already makes. Following the wrong
    same-named function in the same file is a false positive we accept over
    following none of them.
    """
    found: dict[str, FunctionDef] = {}
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.setdefault(node.name, node)
    return found


def analyse_tool(
    tool: SourceTool, callees: Mapping[str, FunctionDef] | None = None
) -> list[TaintHit]:
    """Every tainted parameter reaching a sink inside one tool function."""
    if tool.func is None:
        # A declared `Tool(...)` has metadata and no body. Its handler is reached
        # through the dispatcher, which is analysed as its own entry point.
        return []
    scope = _TaintScope(tool.parameters, callees=callees)
    scope.visit_body(tool.func.body)
    return scope.hits


class UnsanitisedSinkRule:
    """MCP-003 -- a tool parameter reaching a dangerous call unsanitised."""

    meta = RuleMeta(
        id="MCP-003",
        title="Tool parameter reaches a dangerous sink unsanitised",
        severity=Severity.CRITICAL,
        description=(
            "A value the model controls -- a tool's parameter -- flowing into a "
            "shell, an interpreter, a filesystem path or an outbound request "
            "without passing through anything that constrains it. Found by "
            "following assignments, f-strings, concatenation and formatting "
            "through the tool's function in the source tree. The parameter is "
            "chosen by a model that is reading descriptions written by the same "
            "server, so an argument here is attacker-influenced in a way an "
            "ordinary function argument is not."
        ),
        remediation=(
            "Do not pass a tool parameter into a shell, an interpreter, or a "
            "filesystem path without constraining it first. Prefer an allowlist "
            "lookup over interpolation; where a shell is unavoidable, quote with "
            "shlex.quote. The model chooses these arguments, and it is reading "
            "descriptions written by the same server."
        ),
    )

    def check(self, tree: SourceTree, tools: Sequence[SourceTool]) -> Iterator[Finding]:
        # Functions by file, so a call can be followed one hop without leaving
        # the module. Built once per tree rather than per tool.
        index: dict[Path, dict[str, FunctionDef]] = {
            relative_to_root(path, tree.root): module_functions(module)
            for path, module in tree.modules.items()
        }

        # The dispatcher is not a tool, and it is where a caller's arguments
        # enter a low-level SDK server. Analysing only `tools` meant every such
        # server was examined at exactly the wrong function.
        subjects = [*((t, False) for t in tools), *((d, True) for d in dispatchers(tree))]
        for tool, routes in subjects:
            for hit in analyse_tool(tool, index.get(tool.path)):
                yield self._finding(tree, tool, hit, routes=routes)

    def _finding(
        self, tree: SourceTree, tool: SourceTool, hit: TaintHit, *, routes: bool = False
    ) -> Finding:
        severity, confidence = _rank(hit)
        path = _relative(tool.path, tree.root)
        location = Location(
            path=path,
            start_line=hit.node.lineno,
            end_line=hit.node.end_lineno or hit.node.lineno,
        )
        # `func` is never None here: a tool without one produces no hits.
        declared_at = tool.func.lineno if tool.func is not None else hit.node.lineno
        parameter = Location(
            path=path,
            start_line=declared_at,
            end_line=declared_at,
        )

        shell = " with shell=True" if hit.shell else ""
        # Naming the router a "tool" is the exact confusion this rule had to be
        # taught out of: `call_tool` handles every tool and is none of them.
        subject = (
            f"the {tool.name!r} dispatcher" if routes else f"tool {tool.name!r}"
        )
        return Finding(
            rule_id=self.meta.id,
            title=self.meta.title,
            severity=severity,
            confidence=confidence,
            message=(
                f"Parameter {hit.parameter!r} of {subject} reaches "
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
