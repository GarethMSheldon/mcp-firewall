# Contributing

Contributions are welcome. Please keep changes focused and include tests for
policy or protocol behaviour.

## Development checks

```powershell
.\scripts\Initialize-MCPFirewall.ps1
.\scripts\Test-MCPFirewall.ps1
```

Or with Python directly:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m mcp_firewall --config config/firewall.json --check-config
```

Please do not add argument values, credentials, access tokens, or other secrets
to audit logs, test fixtures, screenshots, or issue reports.
