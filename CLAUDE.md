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
  JSON pointers are RFC 6901 in fragment form: `#/tools/3/description`. Also
  `serialise`, which writes the survey artefact SARIF anchors its results in.
  That lives here and not in `sarif.py` so the file's pointers and the rules'
  pointers are built beside each other; `ensure_ascii=True` throughout, which is
  what survives a lone surrogate off the wire and makes a column an offset.
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
  `sandbox.py`. Stdout carries the report and nothing else. Holds the SARIF
  mapping as a comment; `coverage_json` and `sorted_findings` are shared so both
  formats describe one scan the same way.
- `src/mcpscan/catalogue.py` -- every rule that can appear in a finding, from all
  four homes. SARIF's driver must declare rules that did *not* fire, and a
  `ruleId` naming no descriptor gets the whole upload rejected.
- `src/mcpscan/sarif.py` -- SARIF 2.1.0. Pure. Four things in it are not
  arbitrary: no `automationDetails` (the CI `category:` owns it, and a
  tool-supplied one makes two jobs close each other's alerts), fingerprints built
  from **nothing positional** (a line number in one reopens every alert on every
  push), the span reported as a property rather than as `region.byteOffset`,
  which SARIF defines relative to the file, and URIs relative to the
  **repository root** rather than the working directory -- `workspace_root`
  walks up for `.git`, because a scan run from a package subdirectory that
  reported `s.py` sends GitHub looking for a file at the top of the repo.
  A finding with a `path` anchors at its source file; the artefact is only ever
  the fallback, since an alert reads better on a committed file.
- `src/mcpscan/analyser.py` -- runs the rules and reports what it could not run.
- `src/mcpscan/canary.py` -- planted secrets. Decoy files mounted read-only at
  `/home/canary`, env values generated per scan from `Target.env_keys`. Detection
  is exact substring match on a token made seconds earlier, which is why MCP-008
  and MCP-009 report HIGH confidence with no benign corpus behind them.
- `src/mcpscan/prober.py` -- drives a live server. `Connector` opens sessions;
  `ProbeBudget` allowances are **per probe, never a shared pool** -- one pool lets
  the rug pull drain it before the other probes run.
- `src/mcpscan/probes.py` -- MCP-007/008/009. Concealment raises confidence: a
  silent mutation outranks an announced one. MCP-007 locates the **field** that
  drifted (`#/tools/3/description`) because it is a claim about that field's
  text; MCP-008 and MCP-009 locate the tool object, because they are claims
  about what a tool *did* when called. All three index the **baseline** listing,
  which is the survey the report's artefact is written from -- an index from a
  later listing names a different tool the moment a server reorders, and a
  server that reorders is what MCP-007 is for.
- `src/mcpscan/fetch.py` -- fetcher downloads with network, runner executes
  offline from a read-only mount. Nothing installs in the runner's 64 MB tmpfs.
- `src/mcpscan/lockfile.py` -- `.mcpscan.lock` and drift. Absence is never success.
- `src/mcpscan/scanrun.py` -- the async half of a scan. **One `asyncio.run` per
  scan, never one per target**: `sandbox.py` holds a module-level `asyncio.Lock`.
  Serialises each target's survey and redacts canaries out of every finding's
  evidence, because this is the last place that still holds the canaries. It
  never *writes* the artefact -- the CLI does, so `--format` changes what is
  printed and not what a scan does.
- `docs/rules/<ID>.md` -- one page per rule, by convention. CI checks both
  directions, so neither a rule nor a page can be added without the other.
- `tests/schemas/` -- the vendored OASIS SARIF schema, with its provenance and
  checksum. Never fetched at test time: that would assert a network is reachable
  rather than that the output is valid.

## Build order -- do not skip ahead

`--path` and `--stdio` both run end to end, including registry specs:
`npx -y @modelcontextprotocol/server-filesystem /tmp` scans in about 20 seconds.
`--url` still exits 2 -- the Streamable HTTP bridge is the one piece not built --
and `test_cli.py::test_url_targets_are_refused_with_an_accurate_reason` keeps that
refusal honest. It is the last descendant of `test_scan_refuses_without_sandbox`;
narrow it when the bridge lands rather than deleting it.

**Two measurements decided the fetch design, and are worth not re-deriving.**
`npm pack` retrieves one tarball and no dependencies, so an offline install of it
fails with `ENOTCACHED`. And a typical server's tree is 31 MB, which peaks the
runner's 64 MB tmpfs at 93% if you install it there. Hence: resolve into a host
directory in the fetcher, mount it read-only, install nothing in the runner.
`fetch.py` uses `npm install --ignore-scripts`, which departs from the letter of
`Dockerfile.fetcher` ("fetching uses npm pack") while keeping its stated reason;
that is a deliberate call, documented in the module, and worth re-reviewing.

**A SARIF result without a `physicalLocation` is silently discarded**, and the
upload still reports success. Every finding from a live server carries a JSON
pointer and no file, so `--format sarif` writes `.mcpscan/<slug>.survey.json` --
the metadata the rules walked, canaries redacted, deterministic so it diffs
cleanly -- and anchors those results at lines in it. A source finding the
workspace cannot place lands there too, for the same reason: a `file://` URI
outside the repository is dropped exactly as thoroughly as no location at all.

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
enforced; the negative cases are enforced by the schema itself. Rules that are not
pattern rules (MCP-003, MCP-004/005/006, MCP-007/008/009) live in code but still
owe a docs page -- `test_rule_files.py` checks both directions across all four
homes.

**Probing calls the target's tools with hostile arguments.** That is only
reasonable because the container has no network, a read-only root, no
capabilities and a hard wall clock. There is no flag to probe outside it.

1. [x] CLI and target loader
2. [x] Sandbox + escape test suite
3. [x] stdio transport, MCP client
4. [x] Static analyser, 3 rules
5. [x] YAML rule engine, JSON report
6. [x] Dynamic prober, rug pull detection   (--url bridge outstanding)
7. [x] SARIF output, validated against the OASIS schema
8. [ ] HTML report   <- current

## Style

- Python 3.11 floor. Do not use 3.12+ syntax; CI tests against 3.11.
- Type annotations everywhere, `from __future__ import annotations` at top.
- Prefer explicit narrowing over `assert` in `src/` (ruff S101).
- Regexes use the `regex` module, not `re`, for unicode property support.

## Ask before

- Changing anything in `sandbox.py` or the Dockerfiles.
- Adding a dependency.
- Modifying `.github/workflows/`.
