# GitHub repository setup

## Suggested repository details

**Repository name:** `mcp-firewall`

**Description:** Python stdio MCP firewall with default-deny tool policies,
argument guardrails, rotating audit logs, and PowerShell-based Windows operations.

**Suggested topics:**

`mcp`, `model-context-protocol`, `python`, `powershell`, `ai-security`,
`agent-security`, `tool-security`, `cybersecurity`, `security-engineering`

## Upload through the GitHub website

1. Create a new repository named `mcp-firewall`.
2. Keep it empty when creating it. Do not generate a README, license, or gitignore
   because those files are already included here.
3. Extract the project archive on your computer.
4. Open the new repository and use **Add file > Upload files**.
5. Upload the contents of the extracted `mcp-firewall` folder, including the
   hidden `.github` folder.
6. Commit the upload to the `main` branch.

## Or push from a terminal

From the extracted project folder, replace `<your-username>` with your GitHub
username:

```bash
git init -b main
git add .
git commit -m "Initial release: MCP Firewall 0.1.0"
git remote add origin https://github.com/<your-username>/mcp-firewall.git
git push -u origin main
```

The GitHub Actions workflow runs the unit tests on Python 3.11, 3.12, and 3.13.
