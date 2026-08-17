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
import os
from collections.abc import Iterator
from contextlib import contextmanager
from importlib.metadata import version as metadata_version
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpscan import __version__, report
from mcpscan.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app
from tests.sourcefixtures import fixture_text, materialise

runner = CliRunner()


def scan(*args: str) -> object:
    return runner.invoke(app, ["scan", *args, "--yes-i-am-authorised"])


@contextmanager
def working_directory(path: Path) -> Iterator[Path]:
    """`--format sarif` writes its artefacts relative to the working directory,
    so a test that checks where they land has to control it."""
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield path
    finally:
        os.chdir(previous)


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


def test_url_targets_are_refused_with_an_accurate_reason() -> None:
    """The last survivor of `test_scan_refuses_without_sandbox`.

    That test asserted `scan` always exited 2; step 4 replaced it with a refusal
    for every dynamic target, and step 6 narrows it again to just `--url`. What
    carries through all three is the intent: a path that cannot run must refuse
    loudly and name the missing piece, never quietly report "no findings" for a
    server it never contacted.

    When the Streamable HTTP bridge lands, this test narrows once more rather
    than disappearing -- something is always unbuilt, and this is how a user
    finds out which thing.
    """
    result = scan("--url", "https://example.com/mcp")
    assert result.exit_code == EXIT_ERROR
    assert "bridge" in result.output.lower()
    assert "not built yet" in result.output.lower()


def test_a_stdio_target_needs_a_daemon_rather_than_degrading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No Docker means no scan. There is no reduced mode that skips the sandbox.

    Falling back to "static rules only" would report a clean bill of health for a
    server nothing ever launched, which is the failure this project is built to
    avoid.
    """
    from mcpscan import cli as cli_module

    monkeypatch.setattr(cli_module.SandboxHandle, "available", staticmethod(lambda: False))
    result = scan("--stdio", "node ./server.js")
    assert result.exit_code == EXIT_ERROR
    assert "docker" in result.output.lower()


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
        for fmt in ("text", "json", "sarif"):
            # Inside tmp_path: a SARIF run writes its artefacts relative to the
            # working directory, and a test suite should not litter the repo.
            with working_directory(tmp_path):
                result = CliRunner().invoke(
                    app,
                    ["scan", "--path", str(root), "--format", fmt, "--yes-i-am-authorised"],
                )
            assert result.exit_code == expected, f"{fixture}/{fmt}"


def test_sarif_output_is_parseable_with_nothing_else_on_stdout(tmp_path: Path) -> None:
    """Same contract as JSON: `--format sarif > out.sarif` has to upload."""
    root = materialise(tmp_path, "vulnerable_server")
    with working_directory(tmp_path):
        result = CliRunner().invoke(
            app,
            ["scan", "--path", str(root), "--format", "sarif", "--yes-i-am-authorised"],
        )
    assert result.exit_code == EXIT_FINDINGS
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]
    assert payload["runs"][0]["tool"]["driver"]["rules"]


def test_sarif_writes_the_artefact_its_results_point_at(tmp_path: Path) -> None:
    """A finding on a nested `inputSchema` description has a pointer and no
    line even here, so a source scan can still need a file to point at -- and
    the artefact has to land in the workspace the URIs are relative to.
    """
    root = materialise(tmp_path, "poisoned_metadata")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with working_directory(workspace) as here:
        result = CliRunner().invoke(
            app,
            ["scan", "--path", str(root), "--format", "sarif", "--yes-i-am-authorised"],
        )
        assert result.exit_code == EXIT_FINDINGS, result.output
        payload = json.loads(result.stdout)
        written = sorted(p.name for p in (here / ".mcpscan").glob("*.survey.json"))

    assert written, "results with no file need an artefact written for them"
    for entry in payload["runs"][0]["results"]:
        assert entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_a_clean_sarif_scan_leaves_no_artefacts_behind(tmp_path: Path) -> None:
    root = materialise(tmp_path, "clean_server")
    with working_directory(tmp_path) as here:
        result = CliRunner().invoke(
            app,
            ["scan", "--path", str(root), "--format", "sarif", "--yes-i-am-authorised"],
        )
        assert result.exit_code == EXIT_OK
        assert not (here / ".mcpscan").exists()


def test_sarif_output_flag_writes_a_file(tmp_path: Path) -> None:
    root = materialise(tmp_path, "vulnerable_server")
    destination = tmp_path / "report.sarif"
    with working_directory(tmp_path):
        result = CliRunner().invoke(
            app,
            [
                "scan", "--path", str(root),
                "--format", "sarif", "--output", str(destination),
                "--yes-i-am-authorised",
            ],
        )
    assert result.exit_code == EXIT_FINDINGS
    assert json.loads(destination.read_text())["version"] == "2.1.0"


def test_uris_are_relative_to_the_repository_not_the_working_directory(
    tmp_path: Path,
) -> None:
    """A monorepo package scanning itself must not report a bare `s.py`.

    GitHub resolves a result's URI against the checkout root, so `s.py` sends it
    looking for a file at the top of the repository -- which finds nothing, or
    finds a *different* file with that name and hangs the alert on it. Three
    invocations of the same committed file have to agree on where it is.
    """
    (tmp_path / ".git").mkdir()
    package = tmp_path / "packages" / "server"
    package.mkdir(parents=True)
    (tmp_path / "tools").mkdir()
    (package / "s.py").write_text(fixture_text("poisoned_metadata"), encoding="utf-8")

    def uris(cwd: Path, target: str) -> set[str]:
        with working_directory(cwd):
            result = CliRunner().invoke(
                app,
                ["scan", "--path", target, "--format", "sarif", "--yes-i-am-authorised"],
            )
        assert result.exit_code == EXIT_FINDINGS, result.output
        return {
            entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for entry in json.loads(result.stdout)["runs"][0]["results"]
        }

    expected = {"packages/server/s.py"}
    assert uris(package, ".") == expected
    assert uris(tmp_path, "packages/server") == expected
    # From a sibling directory the file used to be unreachable and every result
    # fell back to the survey artefact, which is a worse place to read an alert.
    assert uris(tmp_path / "tools", "../packages/server") == expected


def test_the_artefact_follows_the_workspace_not_the_output_flag(tmp_path: Path) -> None:
    """URIs inside a SARIF document are resolved from the repository root, so
    the artefact they name has to be there -- wherever the report itself was
    asked to go.
    """
    root = materialise(tmp_path, "poisoned_metadata")
    workspace = tmp_path / "workspace"
    elsewhere = tmp_path / "elsewhere"
    workspace.mkdir()
    elsewhere.mkdir()

    with working_directory(workspace) as here:
        result = CliRunner().invoke(
            app,
            [
                "scan", "--path", str(root),
                "--format", "sarif",
                "--output", str(elsewhere / "report.sarif"),
                "--yes-i-am-authorised",
            ],
        )
        assert result.exit_code == EXIT_FINDINGS, result.output
        assert (here / ".mcpscan").is_dir()

    assert not (elsewhere / ".mcpscan").exists()
    payload = json.loads((elsewhere / "report.sarif").read_text())
    uris = {
        e["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for e in payload["runs"][0]["results"]
    }
    assert any(uri.startswith(".mcpscan/") for uri in uris)


def test_a_url_target_still_refuses_in_sarif(tmp_path: Path) -> None:
    """Exit 2 and a document that parses. A consumer reading the exit code has
    to be able to tell a partial run from a clean one -- which is why the run
    says it was not successful, and why the shipped workflow will not upload it.
    """
    result = CliRunner().invoke(
        app,
        [
            "scan", "--url", "https://example.test/mcp",
            "--format", "sarif", "--yes-i-am-authorised",
        ],
    )
    assert result.exit_code == EXIT_ERROR
    payload = json.loads(result.stdout)
    assert payload["runs"][0]["results"] == []
    assert payload["runs"][0]["invocations"][0]["executionSuccessful"] is False


def test_verify_has_no_sarif_format() -> None:
    """`verify` reports drift, not findings. Accepting the flag and printing
    text instead would be the worst of the three options.
    """
    result = CliRunner().invoke(app, ["verify", "--format", "sarif"])
    assert result.exit_code == EXIT_ERROR
    assert "sarif" in result.output


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
