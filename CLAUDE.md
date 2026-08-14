# mcpscan

Security scanner for Model Context Protocol servers. Static analysis plus
sandboxed dynamic probing.

## Non-negotiable constraints

1. **The sandbox is never bypassable.** There is no flag, env var, or code path
   that runs a target outside Docker. Do not add one, even for testing.
2. **`subprocess`, `os.exec*`, `os.system`, and `asyncio.create_subprocess_*`
   appear in `src/mcpscan/sandbox.py` and nowhere else.** A CI test enforces
   this. If another module needs to run something, it goes through
   `SandboxHandle`.
3. **Never handle real credentials.** `Target.env_keys` holds variable *names*
   only. Values are replaced with generated canaries at launch. There is a test
   proving a real token cannot survive a round trip into a `Target`.
4. **No new runtime dependencies without asking.** The project must stay
   installable and auditable. Dev dependencies are fine.

## Verify changes with

    make check      # ruff + mypy strict + pytest
    make images     # rebuild sandbox containers

All three must pass before any commit. mypy runs in strict mode; do not add
`# type: ignore` to silence it, fix the type.

## Layout

- `src/mcpscan/cli.py` -- Typer entry point. Exit codes are a CI contract:
  0 clean, 1 findings at/above `--fail-on`, 2 scanner error. Never conflate 1 and 2.
- `src/mcpscan/models.py` -- pydantic models. `Finding` is the single shape all
  report formats serialise from.
- `src/mcpscan/targets.py` -- parses npx commands, URLs, paths, client configs.
- `src/mcpscan/consent.py` -- one-time authorisation gate.
- `src/mcpscan/sandbox.py` -- Docker isolation. The only module permitted to
  spawn processes. `run()` is batch; `session()` is the long-lived duplex form
  the stdio transport needs. Same flags, same teardown, plus `-i`. Never `--tty`.
- `src/mcpscan/jsonrpc.py` -- JSON-RPC framing. Pure: no I/O, no clock, no
  Docker. Every hostile-input decision lives here so CI can test it.
- `src/mcpscan/transport.py` -- stdio transport. Takes a `SandboxSession` and
  nothing else; there is no path to a channel the sandbox did not create.
- `src/mcpscan/client.py` -- MCP client, revision 2025-11-25.
- `src/mcpscan/document.py` -- one metadata shape for both a live survey and a
  source tree, plus `walk_text`, the traversal every metadata rule runs on.
  JSON pointers are RFC 6901 in fragment form: `#/tools/3/description`.
- `src/mcpscan/source.py` -- `ast` extraction of tool definitions. Per-field line
  ranges point at the *string literal*, not the `def`. Paths are relative to the
  scan root.
- `src/mcpscan/engine.py` -- the pattern-rule engine. `PatternRule`, the three
  closed hook registries, and the per-match regex timeout. **Never widen
  `except TimeoutError` to `except OSError`** -- `TimeoutError` is a subclass of
  it, so the broad clause silently disables the backtracking defence.
- `src/mcpscan/predicates.py` -- the only hooks YAML may name. Adding one is a
  reviewed code change; a rule file can reference but never define behaviour.
- `src/mcpscan/ruleloader.py` -- YAML schema (pydantic, `extra="forbid"`,
  `safe_load` only). `tests.negative` is required by the schema, which is where
  "a rule PR without a negative case fails the build" actually lives.
- `src/mcpscan/rules/*.yaml` -- the bundled pack. MCP-001 and MCP-002.
- `src/mcpscan/taint.py` -- MCP-003, in code. Taint analysis is not pattern
  matching; do not push it into YAML. Sinks are named as **strings** so
  constraint 2 holds; no import and no attribute access here.
- `src/mcpscan/anomalies.py` -- `AnomalyKind` -> `Finding`. Fifteen kinds map to
  MCP-004/005/006; four are coverage notes, never findings.
- `src/mcpscan/report.py` -- JSON, `schema_version: 1`. The only clock outside
  `sandbox.py`. Stdout carries the report and nothing else.
- `src/mcpscan/analyser.py` -- runs the rules and reports what it could not run.
- `docs/rules/<ID>.md` -- one page per rule, by convention. CI checks both
  directions, so neither a rule nor a page can be added without the other.

## Build order -- do not skip ahead

`mcpscan scan --path` now runs end to end and exits 0/1. `--stdio` and `--url`
still exit 2: the transport and client exist, but nothing drives them through a
scan until step 6. `tests/test_cli.py::test_stdio_targets_are_refused_until_probing_exists`
is the successor to the old `test_scan_refuses_without_sandbox` and keeps that
refusal honest. Do not "fix" it either.

`ProtocolAnomaly` now maps to `Finding` in `anomalies.py`, but the CLI cannot yet
*produce* those findings: nothing drives the client through a scan until step 6.
The mapping is exercised by `test_anomaly_mapping.py` and by the Docker-gated
client suite, which provokes fourteen of the fifteen reportable kinds.

**Precision is not negotiable in the rules.** `tests/test_negative_controls.py`
holds the fixtures that must report *zero*: `server_clean.py`'s metadata, ~50
realistic benign descriptions, legitimate Unicode (emoji ZWJ sequences, Persian
ZWNJ, Hebrew RLM, a leading BOM), and a safe source tree. Each is paired with an
injection test proving the control is not vacuous. **Those corpora gate every
rule, bundled or contributed** -- see `test_rule_files.py`. A rule change that
needs one of those fixtures relaxed is the wrong change: a scanner whose findings
get skimmed is worse than no scanner.

**Adding a rule** means a YAML file in `src/mcpscan/rules/`, positive *and*
negative cases inside it, a `remediation`, and `docs/rules/<ID>.md`. All four are
enforced; the negative cases are enforced by the schema itself.

1. [x] CLI and target loader
2. [x] Sandbox + escape test suite
3. [x] stdio transport, MCP client
4. [x] Static analyser, 3 rules
5. [x] YAML rule engine, JSON report
6. [ ] Dynamic prober, rug pull detection   <- current
7. [ ] SARIF output
8. [ ] HTML report

## Style

- Python 3.11 floor. Do not use 3.12+ syntax; CI tests against 3.11.
- Type annotations everywhere, `from __future__ import annotations` at top.
- Prefer explicit narrowing over `assert` in `src/` (ruff S101).
- Regexes use the `regex` module, not `re`, for unicode property support.

## Ask before

- Changing anything in `sandbox.py` or the Dockerfiles.
- Adding a dependency.
- Modifying `.github/workflows/`.
