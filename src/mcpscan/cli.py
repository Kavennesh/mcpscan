from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from mcpscan import targets as tgt
from mcpscan.analyser import AnalysisResult, Subject, analyse
from mcpscan.consent import ensure_consent
from mcpscan.models import Severity, Target, TargetKind

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

    dynamic = [t for t in resolved if t.kind is not TargetKind.PATH]
    if dynamic:
        # The transport and client exist (step 3), but nothing yet drives them
        # through a scan. Naming the missing piece beats a stale message about
        # the sandbox, which has been built for two steps.
        typer.echo(
            f"\nnot implemented: {len(dynamic)} target(s) need dynamic probing, "
            "which is not wired up yet.",
            err=True,
        )
        typer.echo("only --path targets can be scanned today.", err=True)
        raise typer.Exit(EXIT_ERROR)

    worst = EXIT_OK
    for target in resolved:
        if target.path is None:  # unreachable; satisfies the type checker
            continue
        try:
            result = analyse(Subject.from_path(target.path, label=target.label))
        except OSError as exc:
            typer.echo(f"error: could not scan {target.label}: {exc}", err=True)
            raise typer.Exit(EXIT_ERROR) from exc
        if _report(target.label, result, fail_on) is EXIT_FINDINGS:
            worst = EXIT_FINDINGS

    raise typer.Exit(worst)


def _report(label: str, result: AnalysisResult, fail_on: Severity) -> int:
    """Print one target's result. Deliberately minimal -- JSON is step 5."""
    typer.echo(f"\n{label}: {result.files_scanned} file(s) scanned")

    for finding in result.findings:
        typer.echo("")
        typer.echo(
            f"  {finding.severity.value.upper():8} {finding.rule_id}  "
            f"({finding.confidence.value} confidence)"
        )
        typer.echo(f"    {finding.message}")
        typer.echo(f"    at {finding.location.describe()}")
        for related in finding.related:
            typer.echo(f"    from {related.describe()}")
        if finding.evidence:
            typer.echo(f"    | {finding.evidence}")

    # Printed whether or not anything was found. "No findings" and "no analysis"
    # look identical in a report that lists only findings, and a user who trusts
    # a clean result for a scan that never ran is worse off than one who ran
    # nothing at all.
    for rule_id, why in result.skipped:
        typer.echo(f"\n  note: {rule_id} did not run -- {why}")
    for path, why in result.unparsed:
        typer.echo(f"  note: {path} was not analysed -- {why}")

    actionable = result.at_or_above(fail_on)
    if not result.findings:
        typer.echo("\n  no findings")
    else:
        typer.echo(
            f"\n  {len(result.findings)} finding(s), "
            f"{len(actionable)} at or above {fail_on.value}"
        )
    return EXIT_FINDINGS if actionable else EXIT_OK


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
