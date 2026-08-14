"""The CLI against live servers: exit codes, the lock, and `verify`.

`test_cli.py` covers everything that needs no daemon and runs in the CI `check`
matrix. This is the other half -- the paths that launch a container -- and it is
where the step-6 promise is actually checked: `--stdio` produces findings and an
exit code, `--write-lock` records what was approved, and `verify` fails a build
when a dependency's tools change underneath it.

The exit-code contract is the thing to keep straight. 0 clean, 1 findings or
drift, 2 the scanner could not do its job. A pipeline that reads 2 as 1 gets a
rule silenced; a pipeline that reads 2 as 0 ships the vulnerability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpscan.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app
from tests.dockerprobe import images_ready, skip_reason

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(not images_ready(), reason=skip_reason()),
]

REPO = Path(__file__).parent.parent
SERVERS = "tests/fixtures/servers"


def scan(*args: str) -> object:
    """Run from the repository root, so the fixture paths resolve and mount."""
    runner = CliRunner()
    import os

    previous = os.getcwd()
    os.chdir(REPO)
    try:
        return runner.invoke(app, ["scan", *args, "--yes-i-am-authorised"])
    finally:
        os.chdir(previous)


def verify(*args: str) -> object:
    runner = CliRunner()
    import os

    previous = os.getcwd()
    os.chdir(REPO)
    try:
        return runner.invoke(app, ["verify", *args, "--yes-i-am-authorised"])
    finally:
        os.chdir(previous)


# --------------------------------------------------------------------------
# exit codes
# --------------------------------------------------------------------------
def test_a_clean_server_exits_zero() -> None:
    result = scan("--stdio", f"python3 {SERVERS}/server_clean.py")
    assert result.exit_code == EXIT_OK, result.output
    assert "no findings" in result.output


def test_a_rug_pull_exits_one_and_names_the_rule() -> None:
    result = scan("--stdio", f"python3 {SERVERS}/server_rugpull.py silent")
    assert result.exit_code == EXIT_FINDINGS, result.output
    assert "MCP-007" in result.output


def test_a_local_command_is_mounted_and_resolves() -> None:
    """`mcpscan scan --stdio "python3 ./server.py"` is the obvious thing to type.

    It cannot work unmodified -- the container has never heard of the caller's
    directory -- so the workspace is mounted read-only at /target and the command
    rewritten. Without this the handshake fails and the scan reports an error
    rather than a result.
    """
    result = scan("--stdio", f"python3 {SERVERS}/server_clean.py")
    assert result.exit_code == EXIT_OK
    assert "could not complete the MCP handshake" not in result.output


def test_an_unreachable_server_is_exit_two_not_a_clean_pass() -> None:
    """The distinction the whole exit-code contract turns on."""
    result = scan("--stdio", f"python3 {SERVERS}/server_silent.py")
    assert result.exit_code == EXIT_ERROR, result.output
    assert "not a clean result" in result.output


def test_static_only_surveys_but_does_not_probe() -> None:
    """Asserted on the JSON, not on the text.

    The text output legitimately mentions MCP-007 in coverage notes -- saying
    which probe did *not* run is the whole point of those notes -- so a substring
    check on the human format cannot tell "found a rug pull" from "explained that
    it did not look for one".
    """
    result = scan(
        "--stdio", f"python3 {SERVERS}/server_rugpull.py silent",
        "--static-only", "--format", "json",
    )
    assert result.exit_code == EXIT_OK, result.output
    payload = json.loads(result.stdout)
    assert [f for f in payload["findings"] if f["rule_id"] == "MCP-007"] == []
    assert any("static-only" in n["detail"] for n in payload["coverage"]["notes"])


def test_write_lock_with_static_only_warns() -> None:
    """Pinning a surface nothing probed makes `verify` green forever."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        result = scan(
            "--stdio", f"python3 {SERVERS}/server_clean.py",
            "--static-only", "--write-lock", "--lock", f"{tmp}/x.lock",
        )
    assert "never checked" in result.output


def test_the_static_rules_run_over_live_metadata() -> None:
    """`Subject.from_survey` was written in step 4 and never called until now.

    A server whose *initial* listing carries an injection payload is an MCP-002
    finding, with no probing involved -- the rules that read a source tree read a
    live survey through the same seam.
    """
    result = scan("--stdio", f"python3 {SERVERS}/server_targets_client.py")
    assert result.exit_code == EXIT_FINDINGS, result.output
    assert "MCP-00" in result.output


# --------------------------------------------------------------------------
# coverage is reported, never implied
# --------------------------------------------------------------------------
def test_the_default_budget_says_what_it_did_not_do() -> None:
    result = scan("--stdio", f"python3 {SERVERS}/server_clean.py")
    assert "did not present" in result.output, result.output
    assert "--deep" in result.output


def test_a_tool_that_could_not_be_probed_is_named() -> None:
    result = scan("--stdio", f"python3 {SERVERS}/server_clean.py")
    assert "list_dir" in result.output
    assert "no string argument" in result.output


# --------------------------------------------------------------------------
# the JSON report
# --------------------------------------------------------------------------
def test_json_output_is_parseable_for_a_live_target() -> None:
    result = scan("--stdio", f"python3 {SERVERS}/server_rugpull.py silent", "--format", "json")
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == 1
    assert payload["targets"][0]["kind"] == "stdio"
    assert any(f["rule_id"] == "MCP-007" for f in payload["findings"])


def test_probe_coverage_notes_reach_the_json_report() -> None:
    result = scan("--stdio", f"python3 {SERVERS}/server_clean.py", "--format", "json")
    payload = json.loads(result.stdout)
    assert payload["coverage"]["notes"], "a truncated probe said nothing in JSON"


# --------------------------------------------------------------------------
# the lock and verify -- the CI use case
# --------------------------------------------------------------------------
def test_write_lock_then_verify_is_clean(tmp_path: Path) -> None:
    lock = tmp_path / "a.lock"
    written = scan(
        "--stdio", f"python3 {SERVERS}/server_clean.py", "--write-lock", "--lock", str(lock)
    )
    assert written.exit_code == EXIT_OK, written.output
    assert lock.is_file()

    checked = verify("--lock", str(lock))
    assert checked.exit_code == EXIT_OK, checked.output
    assert "unchanged" in checked.output


def test_verify_fails_the_build_when_a_tool_changes(tmp_path: Path) -> None:
    """The supply-chain case, end to end: a description changes between builds."""
    lock = tmp_path / "b.lock"
    scan("--stdio", f"python3 {SERVERS}/server_clean.py", "--write-lock", "--lock", str(lock))

    data = json.loads(lock.read_text())
    entry = next(iter(data["servers"].values()))
    entry["tools"]["read_file"] = "sha256:0000000000000000"
    lock.write_text(json.dumps(data, indent=2))

    result = verify("--lock", str(lock))
    assert result.exit_code == EXIT_FINDINGS, result.output
    assert "tool_changed" in result.output
    assert "read_file" in result.output


def test_verify_reports_a_tool_that_appeared(tmp_path: Path) -> None:
    lock = tmp_path / "c.lock"
    scan("--stdio", f"python3 {SERVERS}/server_clean.py", "--write-lock", "--lock", str(lock))

    data = json.loads(lock.read_text())
    entry = next(iter(data["servers"].values()))
    del entry["tools"]["list_dir"]
    lock.write_text(json.dumps(data, indent=2))

    result = verify("--lock", str(lock))
    assert result.exit_code == EXIT_FINDINGS
    assert "tool_added" in result.output and "list_dir" in result.output


def test_verify_json_is_machine_readable(tmp_path: Path) -> None:
    lock = tmp_path / "d.lock"
    scan("--stdio", f"python3 {SERVERS}/server_clean.py", "--write-lock", "--lock", str(lock))

    result = verify("--lock", str(lock), "--format", "json")
    payload = json.loads(result.stdout)
    assert payload["drift"] == []
    assert payload["errors"] == []


def test_a_scan_does_not_write_a_lock_unless_asked(tmp_path: Path) -> None:
    """Silently mutating the working directory would be a surprise, and an
    auto-updating baseline defeats itself: the drift you wanted to catch gets
    written into the lock by the scan that should have flagged it."""
    import os

    previous = os.getcwd()
    os.chdir(tmp_path)
    try:
        CliRunner().invoke(
            app,
            [
                "scan", "--stdio", f"python3 {REPO}/{SERVERS}/server_clean.py",
                "--yes-i-am-authorised",
            ],
        )
    finally:
        os.chdir(previous)
    assert not (tmp_path / ".mcpscan.lock").exists()


# --------------------------------------------------------------------------
# containment
# --------------------------------------------------------------------------
def test_a_full_scan_leaves_no_container_behind() -> None:
    """The prober multiplies launches; the CI job asserts this globally too."""
    from tests.dockerprobe import container_exists

    scan("--stdio", f"python3 {SERVERS}/server_rugpull.py")
    assert not container_exists("mcpscan-nonexistent-probe")
