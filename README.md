# MCP Firewall

A lightweight Python policy-enforcing proxy for Model Context Protocol (MCP)
servers using stdio transport, with PowerShell scripts for Windows setup and
operations.

**Maintainer:** Gareth Sheldon  
**Version:** 0.1.0  
**Status:** Alpha / proof of concept

## Why I built it

MCP creates a useful connection between AI clients and external tools, but that
connection also creates a trust boundary. A client may be able to discover and
invoke tools that read files, change data, execute actions, or reach internal
services.

I built MCP Firewall to put a small, inspectable policy layer between an MCP
client and the upstream server. The goal is straightforward: make tool access
explicit, check every tool invocation, and keep a useful audit trail without
writing argument values to disk.

## What it does

- Runs as a stdio proxy and starts the upstream MCP server as a child process.
- Filters `tools/list` so tools outside the configured policy are not shown to
  the client.
- Independently checks every `tools/call` request before forwarding it.
- Uses default-deny mode and deny-rule precedence.
- Supports wildcard tool rules such as `read_*` and `*delete*`.
- Enforces message size, argument size, and argument nesting limits.
- Can block configured argument key names and regular-expression matches.
- Writes rotating JSONL audit events without argument values.
- Includes PowerShell setup, validation, test, and launch scripts.
- Uses only the Python standard library at runtime.

## What it does not do

This is not a network firewall or a complete MCP security gateway. It only
controls traffic that passes through this stdio proxy. It does not sandbox the
upstream process, stop a server from making its own network connections, or
fully detect prompt injection. See [Threat model](docs/THREAT_MODEL.md) before
using it outside a local test environment.

## Repository layout

```text
mcp-firewall/
|-- config/
|   |-- firewall.example.json
|   `-- firewall.json
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- THREAT_MODEL.md
|   `-- WINDOWS_CLIENTS.md
|-- examples/
|   `-- echo_server.py
|-- scripts/
|   |-- Initialize-MCPFirewall.ps1
|   |-- Start-MCPFirewall.ps1
|   `-- Test-MCPFirewall.ps1
|-- src/mcp_firewall/
|   |-- __init__.py
|   |-- __main__.py
|   |-- audit.py
|   |-- config.py
|   |-- policy.py
|   `-- proxy.py
|-- tests/
|   |-- test_policy.py
|   `-- test_proxy.py
|-- .github/workflows/tests.yml
|-- LICENSE
|-- pyproject.toml
`-- README.md
```

## Requirements

- Python 3.11 or newer.
- Windows PowerShell 5.1 or PowerShell 7 for the included Windows scripts.
- An MCP client and an upstream MCP server that communicate over stdio.

There are no third-party Python runtime dependencies.

## Quick start on Windows

Open PowerShell in the repository folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Initialize-MCPFirewall.ps1
.\scripts\Test-MCPFirewall.ps1
```

Run the local demo proxy:

```powershell
.\scripts\Start-MCPFirewall.ps1
```

The demo server exposes `echo`, `get_status`, and `delete_everything`. The
policy allows the first two and hides/blocks the delete tool.

## Quick start on Linux or macOS

From the repository root:

```bash
python3.11 -m venv .venv
PYTHONPATH=src .venv/bin/python -m mcp_firewall --config config/firewall.json --check-config
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
PYTHONPATH=src .venv/bin/python -m mcp_firewall --config config/firewall.json
```

The proxy uses stdin/stdout for MCP protocol messages. Logs are written to
stderr and the audit file. Do not add normal diagnostic output to stdout in an
upstream server.

## Policy example

```json
{
  "policy": {
    "default_action": "deny",
    "allow_tools": ["read_file", "list_directory"],
    "deny_tools": ["*delete*", "*execute*", "*shell*"],
    "max_message_bytes": 1048576,
    "max_argument_bytes": 65536,
    "max_argument_depth": 12,
    "blocked_argument_keys": ["password", "api_key", "access_token"],
    "blocked_string_patterns": []
  }
}
```

Replace the sample tool names with the exact names exposed by your upstream
server. Deny rules are evaluated first. With `default_action` set to `deny`,
anything not explicitly allowed is blocked.

## Example MCP client launch settings

The MCP client must start the firewall, not the upstream server. The firewall
starts the upstream process itself. Example settings are in
[Windows client integration](docs/WINDOWS_CLIENTS.md).

## Audit events

The default audit file is `logs/mcp-firewall.jsonl`. Example event:

```json
{"timestamp":"2026-11-20T18:00:00+00:00","event":"tool_call","decision":"deny","reason":"tool_matches_deny_rule","tool":"delete_everything","request_id":"12","argument_bytes":2,"argument_keys":[]}
```

Argument values are not recorded. Tool names and argument key names may still
contain operational metadata, so protect the audit directory and apply a
suitable retention policy.

## Current limitations

- Only stdio transport is implemented. HTTP/SSE transport is not included.
- The enforcement points in this release are `tools/list` and `tools/call`.
- Batch JSON-RPC messages are rejected by this proxy.
- Wildcard matching is case-sensitive.
- Regex checks are basic filters, not a reliable method for detecting malicious
  commands or prompt injection.
- The project is alpha software and has not received an independent security
  audit.

## Roadmap

- [ ] Add a policy test harness with replayable MCP request fixtures.
- [ ] Add optional per-tool argument schema constraints.
- [ ] Add configurable rate limits per tool.
- [ ] Add output size controls and response auditing with configurable redaction.
- [ ] Evaluate HTTP transport support with the same policy engine.
- [ ] Add integration tests against maintained MCP SDK servers.
- [ ] Add signed policy bundles and policy change history.

## Security

Read [SECURITY.md](SECURITY.md) and the [threat model](docs/THREAT_MODEL.md).
For a first deployment, run the upstream server with least privilege, restrict
its network egress independently, and allow only the smallest set of tools
required for the workflow.

## License

MIT. See [LICENSE](LICENSE).
