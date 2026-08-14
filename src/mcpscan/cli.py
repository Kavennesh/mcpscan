from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from mcpscan import __version__, report
from mcpscan import targets as tgt
from mcpscan.analyser import AnalysisResult, Subject, analyse, default_rules
from mcpscan.consent import ensure_consent
from mcpscan.engine import RuleError
from mcpscan.models import Severity, Target, TargetKind
from mcpscan.ruleloader import lint_all, load_all

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class ReportFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


app = typer.Typer(
    add_completion=False,
    help="Security scanner for Model Context Protocol servers.",
)

rules_app = typer.Typer(help="Inspect and check the rule pack.")
app.add_typer(rules_app, name="rules")


def _show_version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit(EXIT_OK)


@app.callback()
def main_options(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_show_version,
            is_eager=True,
            help="Show the installed version and exit.",
        ),
    ] = False,
) -> None:
    """Security scanner for Model Context Protocol servers.

    ``--version`` is eager so it answers before argument validation: someone
    checking which build they have should not first have to supply a target.
    """


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
    format: Annotated[
        ReportFormat,
        typer.Option("--format", help="Output format"),
    ] = ReportFormat.TEXT,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write the report here instead of stdout"),
    ] = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", help="Directory of additional YAML rules"),
    ] = None,
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

    # Progress goes to stderr so that stdout carries the report and nothing else.
    # `mcpscan scan --format json > report.json` has to produce a parseable file,
    # and a preamble on stdout would put a line of prose in front of the `{`.
    typer.echo(f"resolved {len(resolved)} target(s):", err=True)
    for t in resolved:
        typer.echo("  " + t.describe().replace("\n", "\n  "), err=True)

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

    try:
        ruleset = default_rules(rules)
    except RuleError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    collected: list[tuple[Target, AnalysisResult]] = []
    worst = EXIT_OK
    for target in resolved:
        if target.path is None:  # unreachable; satisfies the type checker
            continue
        try:
            result = analyse(Subject.from_path(target.path, label=target.label), ruleset)
        except OSError as exc:
            typer.echo(f"error: could not scan {target.label}: {exc}", err=True)
            raise typer.Exit(EXIT_ERROR) from exc
        collected.append((target, result))
        if result.at_or_above(fail_on):
            worst = EXIT_FINDINGS

    rendered = (
        report.render(collected, fail_on=fail_on)
        if format is ReportFormat.JSON
        else _text(collected, fail_on)
    )
    if output is not None:
        output.write_text(rendered, encoding="utf-8")
    else:
        typer.echo(rendered, nl=False)

    raise typer.Exit(worst)


def _text(results: list[tuple[Target, AnalysisResult]], fail_on: Severity) -> str:
    """The human format. Deliberately plain -- JSON is what machines read."""
    lines: list[str] = []
    for target, result in results:
        lines.append(f"\n{target.label}: {result.files_scanned} file(s) scanned")

        for finding in result.findings:
            lines.append("")
            lines.append(
                f"  {finding.severity.value.upper():8} {finding.rule_id}  "
                f"({finding.confidence.value} confidence)"
            )
            lines.append(f"    {finding.message}")
            lines.append(f"    at {finding.location.describe()}")
            for related in finding.related:
                lines.append(f"    from {related.describe()}")
            if finding.evidence:
                lines.append(f"    | {finding.evidence}")
            if finding.help_uri:
                lines.append(f"    see {finding.help_uri}")

        # Printed whether or not anything was found. "No findings" and "no
        # analysis" look identical in a report that lists only findings, and a
        # user who trusts a clean result for a scan that never ran is worse off
        # than one who ran nothing at all.
        for rule_id, why in result.skipped:
            lines.append(f"\n  note: {rule_id} did not run -- {why}")
        for path, why in result.unparsed:
            lines.append(f"  note: {path} was not analysed -- {why}")
        for note in result.notes:
            lines.append(f"  note: {note.detail}")

        actionable = result.at_or_above(fail_on)
        if not result.findings:
            lines.append("\n  no findings")
        else:
            lines.append(
                f"\n  {len(result.findings)} finding(s), "
                f"{len(actionable)} at or above {fail_on.value}"
            )
    return "\n".join(lines) + "\n"


@rules_app.command("list")
def rules_list(
    rules: Annotated[
        Path | None, typer.Option("--rules", help="Directory of additional YAML rules")
    ] = None,
) -> None:
    """Show every rule that would run."""
    try:
        loaded = load_all(rules)
    except RuleError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    for item in loaded:
        meta = item.rule.meta
        typer.echo(f"{meta.id}  {meta.severity.value:8}  {meta.title}")
        typer.echo(
            f"          {len(item.rule.patterns)} pattern(s), "
            f"{len(item.tests.positive)} positive / {len(item.tests.negative)} "
            f"negative case(s)   [{item.source}]"
        )
    typer.echo("\nMCP-003 is implemented in code: taint analysis is not pattern matching.")


@rules_app.command("lint")
def rules_lint(
    rules: Annotated[
        Path | None, typer.Option("--rules", help="Directory of additional YAML rules")
    ] = None,
) -> None:
    """Warn about regex shapes worth a second look. Advisory only.

    Never fails. This engine optimises away most textbook catastrophic patterns
    and not others, so a static check produces both false alarms and false
    confidence. The per-match timeout is the control; this is a nudge to whoever
    is writing the rule.
    """
    try:
        loaded = load_all(rules)
    except RuleError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    warnings = lint_all(loaded)
    for rule_id, pattern_name, warning in warnings:
        typer.echo(f"{rule_id}/{pattern_name}: {warning}")

    if not warnings:
        typer.echo(f"{len(loaded)} rule(s) checked, nothing to flag")
    else:
        typer.echo(
            f"\n{len(warnings)} advisory warning(s). These do not fail a build: "
            "a catastrophic pattern is stopped at scan time by the per-match "
            "timeout, not by this check."
        )
    raise typer.Exit(EXIT_OK)


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
