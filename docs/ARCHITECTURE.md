# Architecture

## Request path

```text
MCP client
   |
   | JSON-RPC over stdio
   v
MCP Firewall (Python)
   |-- Parse message and enforce size limits
   |-- tools/list: hide tools outside the configured allow policy
   |-- tools/call: evaluate name and arguments again
   |-- Write value-free audit events
   |
   | JSON-RPC over stdio
   v
Upstream MCP server
```

The firewall starts the upstream process itself. It does not accept arbitrary
shell command strings from MCP messages. The configured `upstream.command` is
passed directly to `asyncio.create_subprocess_exec`; no shell is involved.

## Enforcement points

1. `tools/list` is filtered to reduce accidental tool exposure in the client UI.
2. Every `tools/call` request is checked independently. Hiding a tool is not
   treated as an authorization control.
3. Deny patterns take precedence over allow patterns.
4. The default policy is deny. A tool is available only when a matching allow
   rule exists and no deny rule matches.
5. Argument size, nesting depth, configured key names, and optional regular
   expression rules are checked before forwarding.

## Windows integration

PowerShell scripts create a local virtual environment, validate configuration,
run unit tests, and launch the proxy. PowerShell is used as an operational
control plane; the enforcement engine remains Python.
