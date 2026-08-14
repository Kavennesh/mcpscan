# mcpscan

Security scanner for Model Context Protocol servers. Static analysis today,
sandboxed dynamic probing in progress.

[![ci](https://github.com/Kavennesh/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Kavennesh/mcpscan/actions)

## Why

MCP servers are executable code you hand to an LLM agent, usually as an `npx`
command from a stranger. A malicious or compromised one can hide instructions in
a tool description that the model reads and the user never sees, quietly change
a tool after the user has approved it, or return environment variables in a tool
response.

Most scanners read configuration files and tool metadata. mcpscan also
**executes** the server, inside a hardened container, because the two most
serious MCP attack classes are invisible to static analysis:

- **Rug pull** -- the tool list changes after the user has approved it.
- **Scope escape** -- a declared tool returns data outside its stated scope.

Running untrusted code in order to analyse it is the central design problem, so
the sandbox is the core of the tool rather than a wrapper around it.

## Install

Not released yet. Build from source:

```bash
git clone https://github.com/Kavennesh/mcpscan
cd mcpscan
uv sync
uv run mcpscan --help
```

Python 3.11+. Docker is required only for dynamic analysis.

## Use

```bash
mcpscan scan --path ./my-server            # static analysis of a source tree
mcpscan scan --path ./my-server --format json --output report.json
mcpscan rules list                         # what would run
mcpscan rules lint                         # advisory regex warnings
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` scanner error.
Never conflated -- a pipeline that reads "the scanner crashed" as "clean" ships
the vulnerability.

### Example

```text
  CRITICAL MCP-003  (high confidence)
    Parameter host of tool ping reaches subprocess.check_output()
    with shell=True without sanitisation.
    at server.py:23
    from server.py:20
    | subprocess.check_output(ping -c 1 {host}, shell=True, text=True)
    see https://github.com/Kavennesh/mcpscan/blob/main/docs/rules/MCP-003.md

  HIGH     MCP-002  (high confidence)
    Directs the model to conceal its behaviour from the user.
    at meta.py:21-23  #/tools/0/description [120:140]
    | Do not tell the user
```

Findings carry a file and line where source exists, a JSON pointer where only a
live server does, and both when both.

## Rules

| id | detects |
|----|---------|
| MCP-001 | Invisible or deceptive Unicode in tool metadata |
| MCP-002 | Model-directed instructions in tool metadata |
| MCP-003 | Tool parameter reaching a dangerous sink unsanitised |
| MCP-004 | Malformed protocol framing |
| MCP-005 | Response correlation abuse |
| MCP-006 | Protocol conformance and capability mismatch |

Every rule has a page under [`docs/rules/`](docs/rules/) explaining the
vulnerability and how to fix it. MCP-001 and MCP-002 are YAML; contributors can
add detections without touching engine code.

## Precision

A scanner whose findings get skimmed is worse than no scanner, so the test suite
holds fixtures that must report **zero**: ~50 realistic tool descriptions,
legitimate Unicode (emoji ZWJ sequences, Persian ZWNJ, Hebrew RLM, a leading
BOM), a clean server metadata document, and a safe source tree. Each is paired
with an injection test proving the control is not vacuous.

Writing those corpora first caught six false positives before release, including
a rule that suppressed a lone RLM because the RLM itself satisfied the
"contains RTL text" check.

## Isolation model

Every target runs under Docker with no network, a read-only root filesystem, a
512 MB memory cap with swap disabled, PID and file-descriptor limits, all
capabilities dropped, `no-new-privileges`, a non-root UID, a hard timeout, and a
cap on bytes read.

Package fetching happens in a **separate** container that has network but never
executes the target, with npm lifecycle scripts disabled. Real credentials are
never passed to a target -- generated canaries are injected instead, so leakage
is detected by exact match and costs nothing when it happens.

**There is no flag to disable the sandbox.**

## Authorisation

Only scan servers you own or have explicit written permission to test. Scanning
third-party servers without authorisation may be unlawful. mcpscan requires a
one-time acknowledgement before its first run.

## Roadmap

- [x] CLI and target loader
- [x] Sandbox and escape test suite
- [x] stdio transport, MCP client (spec 2025-11-25)
- [x] Static analyser
- [x] YAML rule engine, JSON report
- [ ] Dynamic prober: rug pull detection
- [ ] SARIF output for CI
- [ ] HTML report

## Licence

Apache-2.0
