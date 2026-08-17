from __future__ import annotations

import asyncio
import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final

import typer

from mcpscan import __version__, htmlreport, report, sarif
from mcpscan import targets as tgt
from mcpscan.analyser import AnalysisResult, default_rules
from mcpscan.consent import ensure_consent
from mcpscan.engine import RuleError, RuleSet
from mcpscan.lockfile import Lock, LockError
from mcpscan.models import Severity, Target, TargetKind
from mcpscan.prober import ProbeBudget
from mcpscan.ruleloader import lint_all, load_all
from mcpscan.sandbox import SandboxHandle
from mcpscan.scanrun import ScanOptions, ScanRun, lock_path_for, run_scan, run_verify

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

#: Where a SARIF run puts the artefacts its results point at. Beside the lock
#: file rather than beside `--output`, because the URIs inside the document are
#: repository-relative and a reader resolves them from the workspace root --
#: wherever the report itself was asked to go.
ARTEFACT_DIR: Final = Path(".mcpscan")


class ReportFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"


class VerifyFormat(StrEnum):
    """`verify` reports drift, not findings, and drift has no SARIF shape.

    Its own enum rather than a shared one so `verify --format sarif` is a usage
    error naming the two formats that exist, instead of falling through to the
    text branch and printing something the caller did not ask for.
    """

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
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Probe harder: more conditions, more payloads, longer"),
    ] = False,
    write_lock: Annotated[
        bool,
        typer.Option("--write-lock", help="Record per-tool hashes to .mcpscan.lock"),
    ] = False,
    lock: Annotated[
        Path | None,
        typer.Option("--lock", help="Lock file path (default .mcpscan.lock)"),
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

    try:
        ruleset = default_rules(rules)
    except RuleError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    if any(t.kind is TargetKind.STDIO for t in resolved) and not SandboxHandle.available():
        # Refuse rather than fall back. There is no path that runs a target
        # outside Docker, and a scan that silently skipped the live half would
        # report "clean" for a server it never contacted.
        typer.echo(
            "error: no reachable Docker daemon, and a stdio target can only be "
            "probed inside the sandbox. Start Docker, or use --path.",
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)

    options = ScanOptions(
        rules=ruleset,
        budget=ProbeBudget.deep() if deep else ProbeBudget(),
        static_only=static_only,
    )
    # One event loop for the whole scan, not one per target: sandbox.py holds a
    # module-level asyncio.Lock for container reaping, and handing it a second
    # loop is a bug waiting for a Python version that stops tolerating it.
    run = asyncio.run(run_scan(resolved, options))

    for problem in run.errors:
        typer.echo(f"error: {problem}", err=True)
    for note in run.notes:
        typer.echo(f"warning: {note}", err=True)

    if write_lock and static_only:
        # Pinning a server you did not check for drift is the one combination
        # that quietly defeats the point: `verify` then goes green forever
        # against a baseline nothing ever probed.
        typer.echo(
            "warning: --write-lock with --static-only records a surface that "
            "MCP-007 never checked. Drop --static-only to pin a probed server.",
            err=True,
        )

    if write_lock and run.locks:
        destination = lock_path_for(lock)
        try:
            Lock(servers=run.locks).write(destination)
        except OSError as exc:
            typer.echo(f"error: could not write {destination}: {exc}", err=True)
            raise typer.Exit(EXIT_ERROR) from exc
        typer.echo(f"wrote {destination} ({len(run.locks)} server(s))", err=True)

    try:
        rendered = _render(run, format, fail_on=fail_on, rules=ruleset)
        if output is not None:
            output.write_text(rendered, encoding="utf-8")
        else:
            typer.echo(rendered, nl=False)
    except (OSError, UnicodeError) as exc:
        # A SARIF run writes the artefacts its results point at. Failing to write
        # part of the output that was asked for is a scanner error, exactly as an
        # unwritable --output is.
        #
        # The write is *inside* the try, which it was not: an unwritable
        # --output raised straight out of the command and exited 1, which a
        # pipeline reads as "findings at or above --fail-on". `UnicodeError` is
        # here for the same reason -- a hostile server can put a lone surrogate
        # in a description, and `--format json` still cannot encode one.
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    if run.errors:
        # A target that could not be scanned is a scanner error, never a finding.
        raise typer.Exit(EXIT_ERROR)
    worst = EXIT_FINDINGS if any(r.at_or_above(fail_on) for _, r in run.results) else EXIT_OK
    raise typer.Exit(worst)


def _render(run: ScanRun, format: ReportFormat, *, fail_on: Severity, rules: RuleSet) -> str:
    if format is ReportFormat.JSON:
        return report.render(run.results, fail_on=fail_on)
    if format is ReportFormat.HTML:
        return htmlreport.render(
            run.results,
            rules=rules,
            fail_on=fail_on,
            surveys=run.surveys,
            # Errors go to stderr for every other format, which is fine when the
            # report is one of two streams a caller is watching. Here the file is
            # the whole artefact: a server that failed its handshake yields a
            # target with no findings and nothing skipped, and without this the
            # page would say "no findings" about a server nothing ever examined.
            errors=run.errors,
        )
    if format is ReportFormat.SARIF:
        # The repository root, not the working directory -- see `workspace_root`.
        workspace = sarif.workspace_root()
        return sarif.render(
            run.results,
            rules=rules,
            fail_on=fail_on,
            surveys=_write_artefacts(run, workspace),
            workspace=workspace,
            errors=run.errors,
        )
    return _text(run.results, fail_on)


def _slug(label: str) -> str:
    """A filename from a target label.

    Labels can hold anything -- a path, a scoped npm package, a config key
    someone typed -- so the readable part is reduced to something a filesystem
    accepts and a short digest of the original is appended. Two labels that
    reduce to the same string are still two files, which matters because they
    are two targets and a result points at one of them.
    """
    safe = "".join(char if char.isalnum() or char in "-_." else "-" for char in label)
    safe = safe.strip("-.") or "target"
    digest = hashlib.sha256(label.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"{safe[:60]}-{digest}"


def _write_artefacts(run: ScanRun, workspace: Path) -> dict[str, sarif.WrittenSurvey]:
    """Write one survey file per target that has a finding needing a file.

    "Needing one" is any finding this workspace cannot place in a source file:
    everything from a live server, the nested `inputSchema` fields of a source
    scan, and a tree scanned from outside the repository the report will be read
    in. Targets with nothing to anchor get no file, so a clean scan leaves no
    directory behind.
    """
    artefacts: dict[str, sarif.WrittenSurvey] = {}
    for target, result in run.results:
        survey = run.surveys.get(target.label)
        if survey is None:
            continue
        placeable = (
            sarif.source_uri(finding.location, target, workspace) is not None
            for finding in result.findings
        )
        if all(placeable):
            continue
        destination = ARTEFACT_DIR / f"{_slug(target.label)}.survey.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(survey.text, encoding="utf-8")
        typer.echo(f"wrote {destination} (metadata surveyed from {target.label})", err=True)
        # Written beside the caller, addressed from the repository root: those
        # differ the moment a scan runs from a subdirectory, and the URI in the
        # document is the one that has to resolve for whoever reads the report.
        artefacts[target.label] = sarif.WrittenSurvey(
            uri=sarif.workspace_uri(destination, workspace) or destination.as_posix(),
            artefact=survey,
        )
    return artefacts


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


@app.command()
def verify(
    lock: Annotated[
        Path | None,
        typer.Option("--lock", help="Lock file path (default .mcpscan.lock)"),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option("--target", help="Verify only this server from the lock"),
    ] = None,
    format: Annotated[
        VerifyFormat,
        typer.Option("--format", help="Output format"),
    ] = VerifyFormat.TEXT,
    yes_i_am_authorised: Annotated[
        bool,
        typer.Option("--yes-i-am-authorised", help="Skip the consent prompt (CI)"),
    ] = False,
) -> None:
    """Check locked servers still serve what they served when the lock was written.

    Exit 0 unchanged, 1 drift, 2 error -- the same contract as `scan`. This is the
    piece meant to run on every build: a dependency whose tool descriptions change
    between two builds is the supply-chain half of the rug-pull problem, and a
    hash comparison catches it in seconds.
    """
    path = lock_path_for(lock)
    try:
        loaded = Lock.read(path)
    except LockError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc

    if target is not None:
        if target not in loaded.servers:
            typer.echo(
                f"error: {target!r} is not in {path}. It holds: "
                f"{', '.join(sorted(loaded.servers)) or '(nothing)'}",
                err=True,
            )
            raise typer.Exit(EXIT_ERROR)
        loaded = Lock(servers={target: loaded.servers[target]})

    if not loaded.servers:
        typer.echo(f"error: {path} locks no servers; nothing to verify", err=True)
        raise typer.Exit(EXIT_ERROR)

    ensure_consent(assume_yes=yes_i_am_authorised)

    if not SandboxHandle.available():
        typer.echo(
            "error: no reachable Docker daemon, and verifying means launching the "
            "server in the sandbox. Drift is unknown, which is not the same as none.",
            err=True,
        )
        raise typer.Exit(EXIT_ERROR)

    typer.echo(f"verifying {len(loaded.servers)} server(s) against {path}", err=True)
    result = asyncio.run(run_verify(loaded, {}, budget=ProbeBudget()))

    if format is VerifyFormat.JSON:
        import json

        typer.echo(json.dumps(result.to_json(), indent=2) + "\n", nl=False)
    else:
        typer.echo(result.render(), nl=False)

    if result.errors:
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(EXIT_FINDINGS if result.drifts else EXIT_OK)


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
