from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from mcpscan import targets as tgt
from mcpscan.consent import ensure_consent
from mcpscan.models import Severity, Target

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

app = typer.Typer(
    add_completion=False,
    help="Security scanner for Model Context Protocol servers.",
)


@app.command()
def scan(
    stdio: Annotated[
        str | None,
        typer.Option(help="Command to launch, e.g. 'npx -y @vendor/server'"),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option(help="Streamable HTTP endpoint"),
    ] = None,
    path: Annotated[
        Path | None,
        typer.Option(help="Local source tree"),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(help="MCP client config to import"),
    ] = None,
    static_only: Annotated[
        bool,
        typer.Option(help="Skip all dynamic probing"),
    ] = False,
    fail_on: Annotated[
        Severity,
        typer.Option(help="Exit 1 at or above this severity"),
    ] = Severity.HIGH,
    yes_i_am_authorised: Annotated[
        bool,
        typer.Option("--yes-i-am-authorised", help="Skip the consent prompt (CI)"),
    ] = False,
) -> None:
    """Scan one or more MCP servers."""
    selected = [bool(stdio), bool(url), bool(path), bool(config)]
    if sum(selected) != 1:
        typer.echo("error: pass exactly one of --stdio, --url, --path, --config", err=True)
        raise typer.Exit(EXIT_ERROR)

    try:
        resolved: list[Target]
        if stdio:
            resolved = [tgt.from_stdio(stdio)]
        elif url:
            resolved = [tgt.from_url(url)]
        elif path:
            resolved = [tgt.from_path(path)]
        else:
            if config is None:  # unreachable; satisfies the type checker
                raise typer.Exit(EXIT_ERROR)
            resolved = tgt.from_client_config(config)
    except tgt.TargetError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    if not resolved:
        typer.echo("error: no targets resolved", err=True)
        raise typer.Exit(EXIT_ERROR)

    ensure_consent(assume_yes=yes_i_am_authorised)

    typer.echo(f"resolved {len(resolved)} target(s):")
    for t in resolved:
        typer.echo("  " + t.describe().replace("\n", "\n  "))

    typer.echo("\nnot implemented: the sandbox is not built yet.", err=True)
    typer.echo("no analysis will run until sandbox escape tests pass.", err=True)
    raise typer.Exit(EXIT_ERROR)


@app.command()
def configs() -> None:
    """List MCP client configs found on this machine."""
    found = tgt.discover_client_configs()
    if not found:
        typer.echo("no known MCP client configs found")
        return
    for p in found:
        typer.echo(str(p))


def main() -> None:
    app()
