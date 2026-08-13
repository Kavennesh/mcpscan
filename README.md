# mcpscan

Static and dynamic security analysis for Model Context Protocol servers.

> **Status: alpha.** The CLI and target loader work. The sandbox is under
> construction, and no analysis runs until it passes its escape tests.

## Why

MCP servers are executable code you hand to an LLM agent. A malicious or
compromised server can hide instructions in a tool description that the model
reads and the user never sees, quietly change a tool's behaviour after the user
has approved it, or return environment variables in a tool response.

Existing scanners read configuration files and tool metadata. mcpscan also
**executes** the server, inside a hardened container, because the two most
serious MCP attack classes are invisible to static analysis:

- **Rug pull** -- the tool list changes after the user has approved it.
- **Scope escape** -- a declared tool returns data outside its stated scope.

Running untrusted code in order to analyse it is the central design problem, so
the sandbox is the core of the tool rather than a wrapper around it.

## Isolation model

Every target runs under Docker with:

- no network (`--network none`)
- read-only root filesystem, 64 MB `noexec` tmpfs for scratch
- 512 MB memory cap with swap disabled
- PID, file-descriptor, file-size and CPU limits
- all capabilities dropped, `no-new-privileges`, non-root UID
- a hard wall-clock timeout and a cap on bytes read from the target

Package fetching happens in a **separate** container that has network access but
never executes the target, with npm lifecycle scripts disabled.

Real credentials are never passed to a target. mcpscan injects freshly generated
canary values instead, so credential leakage is detected by exact match and
costs nothing when it happens.

**There is no flag to disable the sandbox.** If Docker is unavailable, dynamic
analysis refuses to run.

## Install

Requires Python 3.11+ and Docker.

```bash
git clone https://github.com/Kavennesh/mcpscan
cd mcpscan
make install images
```

## Use

```bash
mcpscan scan --stdio "npx -y @vendor/server"
mcpscan scan --url https://example.com/mcp
mcpscan scan --path ./my-server
mcpscan scan --config ~/.config/Claude/claude_desktop_config.json
mcpscan configs
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` scanner error.

## Authorisation

Only scan servers you own or have explicit written permission to test. Scanning
third-party servers without authorisation may be unlawful. mcpscan requires a
one-time acknowledgement before its first run.

## Roadmap

- [x] CLI and target loader
- [ ] Sandbox and escape test suite
- [ ] stdio transport, MCP client
- [ ] Static analyser and YAML rule engine
- [ ] JSON report
- [ ] Dynamic prober: rug pull detection
- [ ] SARIF output for CI
- [ ] Streamable HTTP transport
- [ ] HTML report

## Licence

Apache-2.0
