# Windows client integration

The PowerShell scripts are intended for Windows 10/11 and Windows Server with
PowerShell 5.1 or PowerShell 7 and Python 3.11 or newer.

## 1. Initialize

From the project root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Initialize-MCPFirewall.ps1
```

The script creates `.venv` and validates the sample config. The project has no
third-party Python runtime dependencies.

## 2. Test

```powershell
.\scripts\Test-MCPFirewall.ps1
```

## 3. Configure an MCP client

An MCP client using stdio should launch the firewall as the server process.
The firewall then launches the configured upstream server from
`config/firewall.json`.

Example client configuration (replace the paths with the actual absolute path
on the machine):

```json
{
  "mcpServers": {
    "local-demo-through-firewall": {
      "command": "C:\\Path\\To\\mcp-firewall\\.venv\\Scripts\\python.exe",
      "args": [
        "-m",
        "mcp_firewall",
        "--config",
        "C:\\Path\\To\\mcp-firewall\\config\\firewall.json"
      ],
      "env": {
        "PYTHONPATH": "C:\\Path\\To\\mcp-firewall\\src"
      }
    }
  }
}
```

Client configuration formats differ. Keep the same launch command and adapt
the surrounding JSON to the client you use.

## 4. Configure the upstream server

Edit `upstream.command`, `upstream.cwd`, and `upstream.env` in the firewall JSON
file. Use an argument array rather than a shell command string. Relative paths
for `cwd` and the audit log are resolved relative to the configuration file.

## 5. Configure the policy

Add the exact upstream tool names to `policy.allow_tools`. Keep
`default_action` set to `deny`. Deny rules override allow rules.
