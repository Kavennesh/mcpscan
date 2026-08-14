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

import json
from importlib.metadata import version as metadata_version
from pathlib import Path

from typer.testing import CliRunner

from mcpscan import __version__, report
from mcpscan.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app
from tests.sourcefixtures import materialise

runner = CliRunner()


def scan(*args: str) -> object:
    return runner.invoke(app, ["scan", *args, "--yes-i-am-authorised"])


# --------------------------------------------------------------------------
# --version
# --------------------------------------------------------------------------
def test_version_flag_prints_the_version_and_exits_zero() -> None:
    """Found by installing the wheel into a clean venv: the option did not exist.

    Nothing in the suite invoked the app without a subcommand, so `mcpscan
    --version` failing with "No such option" was invisible until someone tried
    the first thing anyone tries.
    """
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == EXIT_OK
    assert result.stdout.strip() == __version__


def test_the_version_comes_from_installed_metadata() -> None:
    """One source of truth. It was previously a literal in three places."""
    assert __version__ == metadata_version("mcpscan")
    assert report.TOOL_VERSION == __version__


def test_version_is_eager_and_needs_no_target() -> None:
    """Checking which build you have should not require supplying a target."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == EXIT_OK
    assert "target" not in result.stdout.lower()


def test_the_json_report_names_the_installed_version(tmp_path: Path) -> None:
    root = materialise(tmp_path, "clean_server")
    result = CliRunner().invoke(
        app,
        ["scan", "--path", str(root), "--format", "json", "--yes-i-am-authorised"],
    )
    assert json.loads(result.stdout)["tool"]["version"] == __version__


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


# --------------------------------------------------------------------------
# report formats
# --------------------------------------------------------------------------
def test_json_output_is_parseable_with_nothing_else_on_stdout(tmp_path: Path) -> None:
    """`mcpscan scan --format json > report.json` must produce a valid file.

    Progress chatter belongs on stderr. A "resolved 1 target(s)" line in front
    of the opening brace makes the document unparseable, and it is the kind of
    regression that only shows up in someone's pipeline.
    """
    root = materialise(tmp_path, "vulnerable_server")
    result = CliRunner().invoke(
        app,
        ["scan", "--path", str(root), "--format", "json", "--yes-i-am-authorised"],
    )
    assert result.exit_code == EXIT_FINDINGS
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["findings"]


def test_json_output_carries_coverage_even_when_clean(tmp_path: Path) -> None:
    root = materialise(tmp_path, "clean_server")
    result = CliRunner().invoke(
        app,
        ["scan", "--path", str(root), "--format", "json", "--yes-i-am-authorised"],
    )
    assert result.exit_code == EXIT_OK
    payload = json.loads(result.stdout)
    assert payload["findings"] == []
    assert payload["coverage"]["files_scanned"] == 1
    assert payload["coverage"]["rules_run"]


def test_output_flag_writes_a_file(tmp_path: Path) -> None:
    root = materialise(tmp_path, "vulnerable_server")
    destination = tmp_path / "report.json"
    result = CliRunner().invoke(
        app,
        [
            "scan", "--path", str(root),
            "--format", "json", "--output", str(destination),
            "--yes-i-am-authorised",
        ],
    )
    assert result.exit_code == EXIT_FINDINGS
    assert json.loads(destination.read_text())["schema_version"] == 1


def test_exit_codes_are_identical_across_formats(tmp_path: Path) -> None:
    """The format changes what is printed, never what the exit code means."""
    for fixture, expected in [("clean_server", EXIT_OK), ("vulnerable_server", EXIT_FINDINGS)]:
        root = materialise(tmp_path / fixture, fixture)
        for fmt in ("text", "json"):
            result = CliRunner().invoke(
                app,
                ["scan", "--path", str(root), "--format", fmt, "--yes-i-am-authorised"],
            )
            assert result.exit_code == expected, f"{fixture}/{fmt}"


# --------------------------------------------------------------------------
# the rules subcommands
# --------------------------------------------------------------------------
def test_rules_list_shows_the_bundled_pack() -> None:
    result = CliRunner().invoke(app, ["rules", "list"])
    assert result.exit_code == EXIT_OK
    assert "MCP-001" in result.output
    assert "MCP-002" in result.output
    assert "MCP-003" in result.output  # named as code, not YAML


def test_rules_lint_never_fails_the_build() -> None:
    """Advisory means advisory. The timeout is the control, not this."""
    result = CliRunner().invoke(app, ["rules", "lint"])
    assert result.exit_code == EXIT_OK


def test_a_broken_rule_directory_is_a_scanner_error(tmp_path: Path) -> None:
    """Exit 2, not 1: a rule that will not load is our problem, not a finding."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yaml").write_text("id: NOPE\ntitle: x\n")

    target_dir = materialise(tmp_path, "clean_server")
    result = CliRunner().invoke(
        app,
        ["scan", "--path", str(target_dir), "--rules", str(rules), "--yes-i-am-authorised"],
    )
    assert result.exit_code == EXIT_ERROR
