from __future__ import annotations

import json
import shlex
from pathlib import Path

from mcpscan.models import Target, TargetKind

# Where the common MCP clients keep their server config.
KNOWN_CONFIGS = [
    Path.home() / ".config/Claude/claude_desktop_config.json",
    Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
    Path.home() / ".cursor/mcp.json",
    Path.home() / ".vscode/mcp.json",
    Path.home() / ".codeium/windsurf/mcp_config.json",
]


class TargetError(Exception):
    pass


def from_stdio(command: str, label: str | None = None) -> Target:
    argv = shlex.split(command)
    if not argv:
        raise TargetError("empty stdio command")
    return Target(
        kind=TargetKind.STDIO,
        label=label or argv[-1],
        command=argv,
        origin="cli:--stdio",
    )


def from_url(url: str, label: str | None = None) -> Target:
    if not url.startswith(("http://", "https://")):
        raise TargetError(f"url must be http(s): {url!r}")
    return Target(
        kind=TargetKind.HTTP,
        label=label or url,
        url=url,
        origin="cli:--url",
    )


def from_path(path: Path, label: str | None = None) -> Target:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise TargetError(f"path does not exist: {resolved}")
    return Target(
        kind=TargetKind.PATH,
        label=label or resolved.name,
        path=resolved,
        origin="cli:--path",
    )


def from_client_config(config_path: Path) -> list[Target]:
    """Parse an MCP client config. Handles the Claude/Cursor and VS Code shapes."""
    resolved = config_path.expanduser().resolve()
    try:
        raw = json.loads(resolved.read_text())
    except json.JSONDecodeError as exc:
        raise TargetError(f"{resolved}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise TargetError(f"{resolved}: {exc}") from exc

    servers = raw.get("mcpServers") or raw.get("servers") or {}
    if not isinstance(servers, dict):
        raise TargetError(f"{resolved}: no mcpServers/servers object found")

    targets: list[Target] = []
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        # Values are deliberately discarded — key names only.
        env_keys = sorted((entry.get("env") or {}).keys())
        origin = f"config:{resolved}"

        if url := entry.get("url"):
            targets.append(
                Target(kind=TargetKind.HTTP, label=name, url=url,
                       env_keys=env_keys, origin=origin)
            )
        elif command := entry.get("command"):
            argv = [command, *(entry.get("args") or [])]
            targets.append(
                Target(kind=TargetKind.STDIO, label=name, command=argv,
                       env_keys=env_keys, origin=origin)
            )
    return targets


def discover_client_configs() -> list[Path]:
    return [p for p in KNOWN_CONFIGS if p.is_file()]
