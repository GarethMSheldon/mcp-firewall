"""Tiny stdio MCP example server used for local smoke testing.

This example intentionally uses only the Python standard library. It is not a
production MCP server and exposes no operating-system command execution.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

PROTOCOL_VERSION = "2025-03-26"


def send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params", {})

    if method == "notifications/initialized" or method == "notifications/cancelled":
        return None
    if method == "initialize":
        version = params.get("protocolVersion", PROTOCOL_VERSION) if isinstance(params, dict) else PROTOCOL_VERSION
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "mcp-firewall-demo", "version": "0.1.0"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Return the supplied message.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"message": {"type": "string"}},
                            "required": ["message"],
                        },
                    },
                    {
                        "name": "get_status",
                        "description": "Return a simple server status value.",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "delete_everything",
                        "description": "A deliberately denied example tool.",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ]
            },
        }
    if method == "tools/call":
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "Invalid params"}}
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}
        if name == "echo":
            text = arguments.get("message", "")
            if not isinstance(text, str):
                text = str(text)
            content = [{"type": "text", "text": text}]
        elif name == "get_status":
            content = [{"type": "text", "text": f"healthy at {datetime.now(timezone.utc).isoformat()}"}]
        else:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Unknown tool"}}
        return {"jsonrpc": "2.0", "id": request_id, "result": {"content": content, "isError": False}}

    if "id" not in message:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}


def main() -> int:
    for raw_line in sys.stdin:
        try:
            request = json.loads(raw_line)
            if not isinstance(request, dict):
                continue
            response = handle(request)
            if response is not None:
                send(response)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Protocol output stays on stdout; diagnostics go to stderr.
            print("Received invalid JSON", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
