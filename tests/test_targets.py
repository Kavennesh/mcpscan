import json
from pathlib import Path

import pytest

from mcpscan import targets as tgt
from mcpscan.models import TargetKind


def test_config_import_never_captures_secret_values(tmp_path: Path) -> None:
    secret = "ghp_thisMustNeverAppearInATarget"
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "gh": {
                "command": "uvx",
                "args": ["mcp-server-git"],
                "env": {"GITHUB_TOKEN": secret},
            }
        }
    }))

    targets = tgt.from_client_config(cfg)

    assert len(targets) == 1
    assert targets[0].env_keys == ["GITHUB_TOKEN"]
    assert secret not in targets[0].model_dump_json()


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("npx -y @vendor/server", "@vendor/server"),
        ("npx -y @modelcontextprotocol/server-filesystem /tmp",
         "@modelcontextprotocol/server-filesystem"),
        ("uvx mcp-server-git --repository /repo", "mcp-server-git"),
        ("uv run python server.py", "python"),
        ("./my-server", "./my-server"),
    ],
)
def test_label_derivation(command: str, expected: str) -> None:
    assert tgt.from_stdio(command).label == expected


def test_shell_metacharacters_stay_literal() -> None:
    """argv is exec-form; a ';' must never become a second command."""
    target = tgt.from_stdio("npx -y foo ; rm -rf /")
    assert target.command is not None
    assert ";" in target.command


def test_empty_command_rejected() -> None:
    with pytest.raises(tgt.TargetError):
        tgt.from_stdio("   ")


def test_non_http_url_rejected() -> None:
    with pytest.raises(tgt.TargetError, match="http"):
        tgt.from_url("ftp://example.com/mcp")


def test_missing_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(tgt.TargetError, match="does not exist"):
        tgt.from_path(tmp_path / "nope")


def test_malformed_config_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.json"
    cfg.write_text("{not json")
    with pytest.raises(tgt.TargetError, match="invalid JSON"):
        tgt.from_client_config(cfg)


def test_vscode_servers_key_supported(tmp_path: Path) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"servers": {"remote": {"url": "https://example.com/mcp"}}}))
    targets = tgt.from_client_config(cfg)
    assert targets[0].kind is TargetKind.HTTP
