"""Running a scan across targets of mixed kind, and folding the results together.

Lives apart from ``cli.py`` because it is the async half and ``cli.py`` is a sync
Typer app. There is exactly **one** ``asyncio.run`` for a whole scan, in
``cli.py``, calling into here — not one per target. A loop per target would work
today, but ``sandbox.py`` holds a module-level ``asyncio.Lock`` for container
reaping, and a lock that meets a second event loop is a bug waiting for whichever
Python version stops tolerating it.

Three sources of findings meet here and all three go into one ``AnalysisResult``:

* the **static rules**, run over the live survey through ``Subject.from_survey`` —
  the seam step 4 built and never used, so a live server gets MCP-001/002 on its
  advertised metadata exactly as a source tree does;
* the **protocol anomalies** the transport recorded, through ``anomalies.to_findings``;
* the **probe findings**, MCP-007/008/009.

Keeping them in one result is what lets ``--fail-on``, the JSON report and the
exit code work identically whether a target was a directory or a running server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcpscan.analyser import AnalysisResult, Subject, analyse
from mcpscan.canary import CanarySet
from mcpscan.engine import CoverageNote, RuleSet
from mcpscan.fetch import FetchError, fetch
from mcpscan.lockfile import Drift, Lock, ServerLock, VerifyResult, compare
from mcpscan.models import Target, TargetKind
from mcpscan.prober import ProbeBudget, probe
from mcpscan.sandbox import Mount, SandboxError


@dataclass(frozen=True, slots=True)
class ScanOptions:
    rules: RuleSet
    budget: ProbeBudget = field(default_factory=ProbeBudget)
    static_only: bool = False


@dataclass(slots=True)
class ScanRun:
    """Everything one `mcpscan scan` produced."""

    results: list[tuple[Target, AnalysisResult]] = field(default_factory=list)
    locks: dict[str, ServerLock] = field(default_factory=dict)
    #: Targets that could not be scanned at all. Exit 2, never exit 1.
    errors: list[str] = field(default_factory=list)
    #: Things worth saying that are neither a finding nor a failure.
    notes: list[str] = field(default_factory=list)


async def run_scan(targets: list[Target], options: ScanOptions) -> ScanRun:
    """Scan every target, dispatching on kind."""
    run = ScanRun()
    for target in targets:
        if target.kind is TargetKind.PATH:
            run.results.append((target, _scan_path(target, options)))
        elif target.kind is TargetKind.STDIO:
            await _scan_stdio(target, options, run)
        else:
            reason = (
                "--url needs the Streamable HTTP bridge, which is not built yet. "
                "Only --stdio and --path can be scanned today."
            )
            run.errors.append(f"{target.label}: {reason}")
            # Still put the target in the report. A target that silently vanishes
            # from a --config scan is one the reader never learns was skipped.
            run.results.append(
                (
                    target,
                    AnalysisResult(
                        skipped=[(rule, reason) for rule in ("MCP-001", "MCP-002", "MCP-003")]
                    ),
                )
            )
    return run


def _scan_path(target: Target, options: ScanOptions) -> AnalysisResult:
    if target.path is None:  # unreachable; satisfies the type checker
        return AnalysisResult()
    return analyse(Subject.from_path(target.path, label=target.label), options.rules)


async def _scan_stdio(target: Target, options: ScanOptions, run: ScanRun) -> None:
    """Probe a live server, then run the static rules over what it served."""
    canaries = CanarySet.create(target.env_keys)
    fetched = None
    try:
        # A registry spec has to be downloaded before the runner -- which has no
        # network -- can execute it. A local command needs none of this.
        try:
            fetched = await fetch(target.command or [])
        except FetchError as exc:
            run.errors.append(f"{target.label}: {exc}")
            return

        # The target keeps its original command -- that is what goes in the
        # report and the lock. Only the *launch* uses the rewritten argv.
        probed = target
        mounts: tuple[Mount, ...] = ()
        env: dict[str, str] = {}
        if fetched is not None:
            probed = target.model_copy(update={"command": fetched.command})
            mounts = (fetched.mount(),)
            env = fetched.env

        outcome = await probe(
            probed,
            canaries=canaries,
            budget=options.budget,
            static_only=options.static_only,
            extra_mounts=mounts,
            extra_env=env or None,
        )
    except SandboxError as exc:
        # The sandbox failing at its own job is a scanner error, not a finding.
        run.errors.append(f"{target.label}: {exc}")
        return
    finally:
        canaries.cleanup()
        if fetched is not None:
            fetched.cleanup()

    if outcome.survey is None:
        run.errors.append(
            f"{target.label}: could not complete the MCP handshake, so nothing "
            "was examined. This is not a clean result."
        )
        # Still surface whatever the transport managed to record on the way down.
        run.results.append((target, _merge(target, outcome, options, static=AnalysisResult())))
        return

    static = analyse(
        Subject.from_survey(outcome.survey, label=target.label), options.rules
    )
    run.results.append((target, _merge(target, outcome, options, static=static)))
    # Redact before hashing. A server that echoes a canary into a description
    # would otherwise hash a fresh random token every run, and `verify` would be
    # permanently red for a reason nobody could work out from the diff.
    run.locks[target.label] = ServerLock.from_survey(
        outcome.survey, target.command, redact=canaries.redact
    )


def _merge(
    target: Target, outcome: Any, options: ScanOptions, *, static: AnalysisResult
) -> AnalysisResult:
    """One result per target, whatever produced the findings inside it."""
    findings = [*static.findings, *outcome.findings]
    for finding in findings:
        if not finding.subject:
            finding.subject = target.label
    findings.sort(key=lambda f: f.sort_key)

    ran = [*static.ran, *outcome.ran]
    skipped = list(static.skipped)
    if outcome.unreachable:
        skipped.extend(
            (rule_id, "the server was unreachable")
            for rule_id in ("MCP-007", "MCP-008", "MCP-009")
        )

    return AnalysisResult(
        findings=findings,
        files_scanned=static.files_scanned,
        unparsed=static.unparsed,
        ran=ran,
        skipped=skipped,
        notes=[*static.notes, *outcome.notes],
    )


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------
async def run_verify(
    lock: Lock, targets: dict[str, Target], *, budget: ProbeBudget
) -> VerifyResult:
    """Survey every locked server once and diff it against the lock.

    Survey-only by design. A full probe would catch behavioural drift a hash
    cannot, and would also take minutes -- and this is meant to run on every
    build, where a check nobody can afford is a check nobody runs.
    """
    checked: list[str] = []
    drifts: list[Drift] = []
    errors: list[str] = []

    for name in sorted(lock.servers):
        locked = lock.servers[name]
        target = targets.get(name) or _target_from_lock(name, locked)
        if target is None:
            errors.append(
                f"{name}: in the lock but no command recorded, so it cannot be "
                "re-checked. Regenerate the lock with --write-lock."
            )
            continue

        canaries = CanarySet.create(target.env_keys)
        try:
            outcome = await probe(target, canaries=canaries, budget=budget, static_only=True)
        except SandboxError as exc:
            errors.append(f"{name}: {exc}")
            continue
        finally:
            canaries.cleanup()

        if outcome.survey is None:
            # "I could not check" is never "unchanged".
            errors.append(f"{name}: could not be reached, so drift is unknown")
            continue

        checked.append(name)
        drifts.extend(compare(name, locked, ServerLock.from_survey(outcome.survey, target.command)))

    return VerifyResult(checked=checked, drifts=drifts, errors=errors)


def _target_from_lock(name: str, locked: ServerLock) -> Target | None:
    if not locked.command:
        return None
    return Target(kind=TargetKind.STDIO, label=name, command=list(locked.command), origin="lock")


def note_lines(notes: list[CoverageNote]) -> list[str]:
    return [f"  note: {note.detail}" for note in notes]


def lock_path_for(path: Path | None) -> Path:
    from mcpscan.lockfile import DEFAULT_LOCK_PATH

    return path if path is not None else DEFAULT_LOCK_PATH
