"""MCP-003 -- tool parameters reaching dangerous sinks.

Most cases are written as source snippets parsed on the fly rather than as files,
because the unit under test is the propagation rule and a snippet states it in
three lines. The ``.py.txt`` fixtures cover the end-to-end path where a whole
tree is walked.

The clean control lives in ``test_negative_controls.py``. What is asserted here
is that the rule follows taint where it genuinely flows, stops where it genuinely
stops, and ranks the difference between a shell and a file open.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from mcpscan.analyser import Subject, analyse, default_rules
from mcpscan.models import Confidence, Severity
from mcpscan.source import SourceTool, SourceTree, extract_tools
from mcpscan.taint import UnsanitisedSinkRule, analyse_tool
from tests.sourcefixtures import materialise

RULE = UnsanitisedSinkRule()


def tool_from(body: str, name: str = "run", params: str = "value: str") -> SourceTool:
    """Parse one decorated tool function out of a snippet."""
    source = f"@mcp.tool()\ndef {name}({params}):\n" + "\n".join(
        f"    {line}" for line in body.strip().splitlines()
    )
    module = ast.parse(source)
    tree = SourceTree(root=Path("."), modules={Path("snippet.py"): module})
    tools = extract_tools(tree)
    if len(tools) != 1:
        raise AssertionError(f"expected one tool, got {len(tools)}")
    return tools[0]


def sinks(body: str, **kwargs: str) -> list[str]:
    return [hit.sink for hit in analyse_tool(tool_from(body, **kwargs))]


def findings(body: str, **kwargs: str) -> list:
    tool = tool_from(body, **kwargs)
    tree = SourceTree(root=Path("."), modules={})
    return list(RULE.check(tree, [tool]))


# --------------------------------------------------------------------------
# propagation
# --------------------------------------------------------------------------
def test_a_parameter_straight_into_a_shell() -> None:
    assert sinks("subprocess.run(value, shell=True)") == ["subprocess.run"]


def test_taint_through_an_fstring() -> None:
    assert sinks('subprocess.run(f"ping {value}", shell=True)') == ["subprocess.run"]


def test_taint_through_concatenation() -> None:
    assert sinks('os.system("rm -rf " + value)') == ["os.system"]


def test_taint_through_percent_formatting() -> None:
    assert sinks('os.system("echo %s" % value)') == ["os.system"]


def test_taint_through_format() -> None:
    assert sinks('os.system("echo {}".format(value))') == ["os.system"]


def test_taint_through_a_local_variable() -> None:
    assert sinks("cmd = value\nos.system(cmd)") == ["os.system"]


def test_taint_through_several_hops() -> None:
    assert sinks(
        'a = value\nb = a.strip()\nc = f"ls {b}"\nsubprocess.run(c, shell=True)'
    ) == ["subprocess.run"]


def test_taint_through_a_list_argument() -> None:
    assert sinks('subprocess.check_output(["tar", "-c", value])') == [
        "subprocess.check_output"
    ]


def test_taint_through_a_dict_value() -> None:
    assert sinks('d = {"k": value}\nos.system(d["k"])') == ["os.system"]


def test_taint_through_tuple_unpacking() -> None:
    assert sinks("a, b = value, 1\nos.system(a)") == ["os.system"]


def test_taint_through_a_loop_variable() -> None:
    assert sinks("for item in value:\n    os.system(item)") == ["os.system"]


def test_taint_inside_a_conditional_branch() -> None:
    assert sinks("if value:\n    os.system(value)") == ["os.system"]


def test_taint_inside_a_try_block() -> None:
    assert sinks("try:\n    os.system(value)\nexcept OSError:\n    pass") == ["os.system"]


def test_keyword_arguments_are_followed() -> None:
    assert sinks("subprocess.run(args=value, shell=True)") == ["subprocess.run"]


# --------------------------------------------------------------------------
# taint that must stop
# --------------------------------------------------------------------------
def test_shlex_quote_kills_taint() -> None:
    assert sinks('subprocess.run(f"ping {shlex.quote(value)}", shell=True)') == []


def test_int_conversion_kills_taint() -> None:
    assert sinks('os.system("sleep " + str(int(value)))') == []


def test_basename_kills_taint() -> None:
    assert sinks('open("/data/" + os.path.basename(value))') == []


def test_an_allowlist_lookup_kills_taint() -> None:
    """The parameter selects a value; it does not become one.

    The main way a careful server makes a caller-supplied name safe, so a rule
    that missed it would report every correctly-written tool.
    """
    assert sinks('path = ALLOWED.get(value)\nopen(path)') == []
    assert sinks('path = ALLOWED[value]\nopen(path)') == []


def test_rebinding_from_a_clean_value_kills_taint() -> None:
    assert sinks('cmd = value\ncmd = "ls -la"\nos.system(cmd)') == []


def test_a_constant_command_is_not_a_finding() -> None:
    assert sinks('subprocess.check_output(["df", "-h"])') == []


def test_a_constant_path_is_not_a_finding() -> None:
    """Tainted parameter in scope, but the path is a literal."""
    assert sinks('open("/etc/config.toml")') == []


def test_a_non_tool_function_is_not_a_source() -> None:
    module = ast.parse('def helper(value):\n    os.system(value)\n')
    tree = SourceTree(root=Path("."), modules={Path("s.py"): module})
    assert extract_tools(tree) == []


# --------------------------------------------------------------------------
# severity and confidence
# --------------------------------------------------------------------------
def test_shell_true_is_critical() -> None:
    finding = findings('subprocess.run(value, shell=True)')[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.HIGH
    assert finding.metadata["shell"] is True


def test_list_form_subprocess_is_high_not_critical() -> None:
    finding = findings('subprocess.run(["ls", value])')[0]
    assert finding.severity is Severity.HIGH
    assert finding.metadata["shell"] is False


def test_eval_is_critical() -> None:
    assert findings("eval(value)")[0].severity is Severity.CRITICAL


def test_a_tainted_open_is_medium() -> None:
    """Often a tool doing its job; the finding is that nothing constrains it."""
    finding = findings("open(value)")[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.MEDIUM


# --------------------------------------------------------------------------
# what a finding says
# --------------------------------------------------------------------------
def test_a_finding_names_the_parameter_the_sink_and_the_tool() -> None:
    finding = findings('subprocess.run(f"ping {host}", shell=True)', params="host: str")[0]
    assert finding.metadata["parameter"] == "host"
    assert finding.metadata["sink"] == "subprocess.run"
    assert finding.metadata["tool"] == "run"
    assert "host" in finding.message
    assert "subprocess.run" in finding.message


def test_a_finding_points_at_the_sink_and_relates_the_parameter() -> None:
    """Two-place by nature: the sink is where, the parameter is why."""
    # 1 @mcp.tool()  2 def run(...)  3 x = 1  4 y = 2  5 os.system(value)
    finding = findings("x = 1\ny = 2\nos.system(value)")[0]
    assert finding.location.start_line == 5
    assert finding.related
    assert finding.related[0].start_line == 2


def test_evidence_is_the_call_not_the_function() -> None:
    finding = findings('subprocess.run(value, shell=True)')[0]
    assert finding.evidence == "subprocess.run(value, shell=True)"


def test_self_is_not_a_taint_source() -> None:
    assert sinks("os.system(self)", params="self, value: str") == []


def test_a_sink_in_a_return_statement_is_reported_once() -> None:
    """Regression: `ast.Return` stores its expression in `.value` like every
    other statement, so a separate branch for it visited the same call twice and
    every `return sink(tainted)` produced two identical findings."""
    assert sinks("return os.system(value)") == ["os.system"]
    assert len(findings("return os.system(value)")) == 1


def test_no_finding_is_duplicated_across_a_whole_tree(tmp_path: Path) -> None:
    root = materialise(tmp_path, "vulnerable_server")
    result = analyse(Subject.from_path(root), default_rules())
    seen = [
        (f.rule_id, f.location.describe(), f.metadata.get("parameter"))
        for f in result.findings
    ]
    assert len(seen) == len(set(seen)), "duplicate findings in the report"


# --------------------------------------------------------------------------
# end to end over a real tree
# --------------------------------------------------------------------------
def test_the_vulnerable_fixture_reports_every_shape(tmp_path: Path) -> None:
    root = materialise(tmp_path, "vulnerable_server")
    result = analyse(Subject.from_path(root), default_rules())
    taint = [f for f in result.findings if f.rule_id == "MCP-003"]

    tools = {f.metadata["tool"] for f in taint}
    assert tools == {
        "ping",
        "find_files",
        "archive",
        "evaluate",
        "fetch_document",
        "render",
        "cleanup",
    }, tools


def test_findings_are_sorted_worst_first(tmp_path: Path) -> None:
    root = materialise(tmp_path, "vulnerable_server")
    result = analyse(Subject.from_path(root), default_rules())
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_paths_are_relative_to_the_scan_root(tmp_path: Path) -> None:
    root = materialise(tmp_path, "vulnerable_server")
    result = analyse(Subject.from_path(root), default_rules())
    for finding in result.findings:
        if finding.location.path is not None:
            assert not finding.location.path.is_absolute()


@pytest.mark.parametrize("fixture", ["clean_server", "vulnerable_server"])
def test_fixtures_parse(tmp_path: Path, fixture: str) -> None:
    """A fixture that does not parse would silently prove nothing."""
    root = materialise(tmp_path, fixture)
    result = analyse(Subject.from_path(root), default_rules())
    assert result.unparsed == []
    assert result.files_scanned == 1


# --------------------------------------------------------------------------
# the low-level SDK: taint crossing the dispatcher
# --------------------------------------------------------------------------
def dispatcher_tree(source: str) -> SourceTree:
    return SourceTree(root=Path("."), modules={Path("s.py"): ast.parse(source)})


CROSSING = """
import subprocess

def archive(directory):
    return subprocess.check_output(f"tar -cf out.tar {directory}", shell=True)

@server.call_tool()
async def call_tool(name, arguments):
    return archive(arguments["directory"])
"""


def test_taint_crosses_the_dispatcher() -> None:
    """The whole point of step 9.

    The low-level SDK splits a tool in two: the dispatcher reads the caller's
    arguments, a handler does the work. Stopping at the dispatcher meant MCP-003
    found nothing on any server built that way, while reporting that it ran.
    """
    findings = list(RULE.check(dispatcher_tree(CROSSING), []))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].metadata["sink"] == "subprocess.check_output"
    assert "subprocess.check_output" in (findings[0].evidence or "")


def test_the_finding_points_at_the_sink_and_back_at_the_dispatcher() -> None:
    """Still two-place: the sink is where the bug is, the entry point is why."""
    finding = list(RULE.check(dispatcher_tree(CROSSING), []))[0]
    assert finding.location.start_line == 5      # the subprocess call
    assert finding.related[0].start_line == 8    # the dispatcher's def


def test_a_dispatcher_finding_does_not_call_the_router_a_tool() -> None:
    """`call_tool` handles every tool and is none of them; naming it one is the
    confusion this step exists to remove."""
    finding = list(RULE.check(dispatcher_tree(CROSSING), []))[0]
    assert "dispatcher" in finding.message
    assert "of tool" not in finding.message


def test_an_allowlist_in_the_handler_still_clears_taint() -> None:
    """The control that proves the crossing is not simply firing on everything."""
    source = """
ALLOWED = {"a": "first"}

def lookup(record_id):
    return ALLOWED.get(record_id, "unknown")

@server.call_tool()
async def call_tool(name, arguments):
    return lookup(arguments["record_id"])
"""
    assert list(RULE.check(dispatcher_tree(source), [])) == []


def test_a_clean_handler_reports_nothing() -> None:
    source = """
import subprocess

def status(repo):
    return subprocess.check_output(["git", "status"], cwd=repo)

@server.call_tool()
async def call_tool(name, arguments):
    return status("/srv/repo")
"""
    assert list(RULE.check(dispatcher_tree(source), [])) == []


def test_only_one_hop_is_followed() -> None:
    """Depth is a judgement about the shape servers take, not a principle, and
    it is stated in the module docstring and on the rule page rather than left
    to be discovered from a false negative."""
    source = """
import subprocess

def inner(value):
    return subprocess.check_output(value, shell=True)

def outer(value):
    return inner(value)

@server.call_tool()
async def call_tool(name, arguments):
    return outer(arguments["cmd"])
"""
    assert list(RULE.check(dispatcher_tree(source), [])) == []


def test_a_recursive_handler_terminates() -> None:
    source = """
import subprocess

def recurse(value):
    if value:
        return recurse(value)
    return subprocess.check_output(value, shell=True)

@server.call_tool()
async def call_tool(name, arguments):
    return recurse(arguments["cmd"])
"""
    list(RULE.check(dispatcher_tree(source), []))  # must not hang or recurse away


def test_a_declared_tool_has_nothing_to_analyse() -> None:
    """It has metadata and no body; its handler is reached through the router."""
    tool = SourceTool(name="declared", path=Path("s.py"), func=None)
    assert analyse_tool(tool) == []


def test_the_dispatcher_fixture_reports_exactly_one_command_injection(
    tmp_path: Path,
) -> None:
    root = materialise(tmp_path, "dispatcher_server")
    result = analyse(Subject.from_path(root, label="fx"), default_rules())

    injections = [f for f in result.findings if f.rule_id == "MCP-003"]
    assert len(injections) == 1
    assert injections[0].severity is Severity.CRITICAL
    assert "MCP-003" in result.ran, "the rule must report that it actually ran"


def test_the_dispatcher_fixture_exposes_its_declared_tools(tmp_path: Path) -> None:
    """Before step 9 this tree yielded one "tool" called `call_tool`."""
    root = materialise(tmp_path, "dispatcher_server")
    subject = Subject.from_path(root, label="fx")
    assert {t.name for t in subject.tools} == {"archive_directory", "lookup_record"}
    assert all(t.description for t in subject.tools)
