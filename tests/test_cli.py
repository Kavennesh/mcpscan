from typer.testing import CliRunner

from mcpscan.cli import app

runner = CliRunner()


def test_no_target_is_error() -> None:
    assert runner.invoke(app, ["scan"]).exit_code == 2


def test_two_targets_is_error() -> None:
    result = runner.invoke(app, ["scan", "--stdio", "npx foo", "--url", "https://x/mcp"])
    assert result.exit_code == 2


def test_scan_refuses_without_sandbox() -> None:
    """Until the sandbox lands, scan must refuse rather than silently no-op."""
    result = runner.invoke(app, ["scan", "--stdio", "npx -y foo", "--yes-i-am-authorised"])
    assert result.exit_code == 2
    assert "sandbox" in result.output.lower()
