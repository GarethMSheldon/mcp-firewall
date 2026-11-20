# Threat model and security boundaries

## Intended protections

MCP Firewall is designed to reduce the risk of an MCP client invoking tools
that have not been explicitly approved. It provides:

- Explicit tool allowlisting with deny-rule precedence.
- A default-deny policy mode.
- A second authorization check at invocation time.
- Basic argument size and nesting limits.
- Optional blocked argument-key and regular-expression checks.
- Structured audit events that omit argument values.

## Out of scope

This release is a stdio proxy, not a host firewall, endpoint agent, sandbox, or
complete MCP security gateway. It does not:

- Inspect network traffic that bypasses this proxy.
- Prevent a permitted MCP server from accessing files, processes, or networks
  using its own operating-system permissions.
- Guarantee detection of prompt injection or malicious instructions in tool
  descriptions, resources, or returned content.
- Sanitize every tool result or enforce a complete schema for every tool.
- Filter every MCP feature or every possible server-to-client request. The
  current authorization boundary is specifically `tools/list` and
  `tools/call`.
- Replace operating-system controls, application sandboxing, egress filtering,
  endpoint protection, or least-privilege service accounts.

## Assumptions and deployment guidance

- The MCP client is configured to start this proxy instead of starting the
  upstream server directly.
- Users cannot start an unmanaged copy of the upstream server and bypass the
  proxy where enforcement is required.
- The proxy process and its configuration file are protected from untrusted
  modification.
- The upstream process runs with a least-privilege OS identity.
- Sensitive tool servers are isolated and have only the file and network access
  they need.

## Known limitations

- Tool name patterns use case-sensitive shell-style wildcard matching.
- Regular-expression argument checks are simple text filters. They can produce
  false positives and can be bypassed by encoding or alternate representations.
  They must not be treated as a substitute for allowlisting or server-side
  validation.
- The audit log records tool names, decision reasons, argument byte counts,
  and top-level argument keys. It intentionally does not record argument
  values. Tool names and key names can still reveal operational metadata.
- The initial release has not undergone an independent security audit.

## Safe rollout

Start with `default_action: deny`, explicitly allow only low-risk tools, test
against a non-production MCP server, and review audit events. Add tools one at
a time. Run the MCP server under a restricted OS identity and restrict its
network egress independently of this proxy.
