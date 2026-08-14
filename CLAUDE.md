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

## Build order -- do not skip ahead

Analysis code does not get written until the sandbox passes its escape tests.
It does now, and steps 2 and 3 are done -- but `cli.py` is still unwired, and
`tests/test_cli.py::test_scan_refuses_without_sandbox` still asserts that
`scan` exits 2. That test is intentional. Do not "fix" it; it comes out when
step 4 gives the CLI something to report.

Step 3 records what a target did wrong as `ProtocolAnomaly`, not `Finding`.
Mapping anomalies to findings is step 4/5 work, once the rule engine and the
report formats exist to constrain the shape.

1. [x] CLI and target loader
2. [x] Sandbox + escape test suite
3. [x] stdio transport, MCP client
4. [ ] Static analyser, 3 rules   <- current
5. [ ] YAML rule engine, JSON report
6. [ ] Dynamic prober, rug pull detection
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
