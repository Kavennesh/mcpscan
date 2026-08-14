"""The CLI's exit codes, which are a CI contract: 0 clean, 1 findings, 2 error.

Conflating 1 and 2 is the failure that matters here. A pipeline that treats "the
scanner crashed" as "the scanner found something" will be fixed by someone
silencing the rule; a pipeline that treats it as "clean" ships the vulnerability.
Both are worse than a loud failure, so every path below asserts the code.

``test_scan_refuses_without_sandbox`` used to live here and asserted that ``scan``
always exited 2. It has been replaced now that step 4 gives the CLI something to
report -- but its intent survives as
``test_stdio_targets_are_refused_until_probing_exists``: the paths that still
cannot run must refuse loudly rather than quietly reporting nothing.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mcpscan.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app
from tests.sourcefixtures import materialise

runner = CliRunner()


def scan(*args: str) -> object:
    return runner.invoke(app, ["scan", *args, "--yes-i-am-authorised"])


# --------------------------------------------------------------------------
# argument handling -- exit 2
# --------------------------------------------------------------------------
def test_no_target_is_error() -> None:
    assert runner.invoke(app, ["scan"]).exit_code == EXIT_ERROR


def test_two_targets_is_error() -> None:
    result = runner.invoke(app, ["scan", "--stdio", "npx foo", "--url", "https://x/mcp"])
    assert result.exit_code == EXIT_ERROR


def test_a_missing_path_is_an_error_not_a_clean_scan(tmp_path: Path) -> None:
    result = scan("--path", str(tmp_path / "nope"))
    assert result.exit_code == EXIT_ERROR


def test_stdio_targets_are_refused_until_probing_exists() -> None:
    """The successor to test_scan_refuses_without_sandbox.

    The sandbox has existed since step 2 and the client since step 3, but
    nothing drives them through a scan yet. Refusing is correct; reporting
    "no findings" for a server we never contacted would not be.
    """
    result = scan("--stdio", "npx -y @vendor/server")
    assert result.exit_code == EXIT_ERROR
    assert "not implemented" in result.output.lower()
    assert "dynamic probing" in result.output.lower()


def test_url_targets_are_refused_too() -> None:
    assert scan("--url", "https://example.com/mcp").exit_code == EXIT_ERROR


# --------------------------------------------------------------------------
# path scans -- exit 0 and 1
# --------------------------------------------------------------------------
def test_a_clean_tree_exits_zero(tmp_path: Path) -> None:
    root = materialise(tmp_path, "clean_server")
    result = scan("--path", str(root))
    assert result.exit_code == EXIT_OK, result.output
    assert "no findings" in result.output


def test_a_vulnerable_tree_exits_one(tmp_path: Path) -> None:
    root = materialise(tmp_path, "vulnerable_server")
    result = scan("--path", str(root))
    assert result.exit_code == EXIT_FINDINGS, result.output
    assert "MCP-003" in result.output


def test_a_poisoned_tree_reports_the_metadata_rules(tmp_path: Path) -> None:
    root = materialise(tmp_path, "poisoned_metadata")
    result = scan("--path", str(root))
    assert result.exit_code == EXIT_FINDINGS
    assert "MCP-001" in result.output
    assert "MCP-002" in result.output


# --------------------------------------------------------------------------
# --fail-on
# --------------------------------------------------------------------------
def test_fail_on_critical_ignores_a_medium_only_tree(tmp_path: Path) -> None:
    """`fetch_document` opens a caller-supplied path: MEDIUM, and below the bar."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "s.py").write_text(
        "@mcp.tool()\ndef fetch(path: str):\n    'Fetches.'\n"
        "    return open(path).read()\n"
    )
    assert scan("--path", str(root), "--fail-on", "critical").exit_code == EXIT_OK
    assert scan("--path", str(root), "--fail-on", "medium").exit_code == EXIT_FINDINGS


def test_findings_below_the_threshold_are_still_printed(tmp_path: Path) -> None:
    """Exit 0 means "nothing actionable", not "nothing to see"."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "s.py").write_text(
        "@mcp.tool()\ndef fetch(path: str):\n    'Fetches.'\n"
        "    return open(path).read()\n"
    )
    result = scan("--path", str(root), "--fail-on", "critical")
    assert result.exit_code == EXIT_OK
    assert "MCP-003" in result.output
    assert "0 at or above critical" in result.output


# --------------------------------------------------------------------------
# coverage is reported, not implied
# --------------------------------------------------------------------------
def test_a_skipped_rule_is_named_in_the_output(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    (root / "util.py").write_text("def helper(x):\n    return x\n")

    result = scan("--path", str(root))
    assert result.exit_code == EXIT_OK
    assert "MCP-003 did not run" in result.output


def test_an_unparseable_file_is_named_in_the_output(tmp_path: Path) -> None:
    """A clean report for a tree we could not read would be a lie."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "broken.py").write_text("def (:\n")

    result = scan("--path", str(root))
    assert "was not analysed" in result.output
    assert "broken.py" in result.output


def test_configs_command_still_works() -> None:
    assert runner.invoke(app, ["configs"]).exit_code == EXIT_OK
