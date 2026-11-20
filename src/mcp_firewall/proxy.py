"""Async JSON-RPC stdio proxy with MCP tool-call enforcement."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
from typing import Any

from .audit import AuditLog
from .config import AppConfig
from .policy import PolicyEngine

LOG = logging.getLogger("mcp_firewall")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _error_response(request_id: Any, code: int, message: str, data: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message, "data": data},
    }


def evaluate_client_message(
    message: Any,
    policy: PolicyEngine,
    audit: AuditLog | None = None,
) -> tuple[bool, dict[str, Any] | None]:
    """Return (forward_upstream, immediate_response) for a client message."""
    if not isinstance(message, dict):
        return False, _error_response(None, -32600, "Invalid Request", "message_must_be_an_object")

    if message.get("method") != "tools/call":
        return True, None

    params = message.get("params")
    decision = policy.check_tool_call(params)
    request_id = message.get("id")
    tool_name = params.get("name") if isinstance(params, dict) else None

    if audit is not None:
        audit.record(
            "tool_call",
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            tool=tool_name if isinstance(tool_name, str) else None,
            request_id=str(request_id) if "id" in message else None,
            argument_bytes=decision.argument_bytes,
            argument_keys=list(decision.argument_keys),
        )

    if decision.allowed:
        return True, None

    # JSON-RPC notifications do not receive a response.
    if "id" not in message:
        return False, None

    return False, _error_response(
        request_id,
        -32001,
        "Tool call blocked by MCP Firewall policy",
        decision.reason,
    )


def filter_server_message(message: Any, policy: PolicyEngine, audit: AuditLog | None = None) -> Any:
    """Filter tools/list results while leaving other server messages unchanged."""
    if isinstance(message, list):
        return [filter_server_message(item, policy, audit) for item in message]

    if not isinstance(message, dict):
        return message

    result = message.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return message

    visible_tools = []
    hidden_names = []
    for tool in result["tools"]:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            # A malformed tool descriptor cannot be safely allowlisted.
            hidden_names.append("<malformed-tool-descriptor>")
            continue
        allowed, _reason = policy.tool_name_allowed(tool["name"])
        if allowed:
            visible_tools.append(tool)
        else:
            hidden_names.append(tool["name"])

    result = dict(result)
    result["tools"] = visible_tools
    updated = dict(message)
    updated["result"] = result

    if audit is not None and hidden_names:
        audit.record(
            "tool_catalog_filtered",
            hidden_count=len(hidden_names),
            hidden_tools=hidden_names,
            request_id=str(message.get("id")) if "id" in message else None,
        )
    return updated


def _parse_json_line(line: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"Invalid JSON constant: {value}")

    return json.loads(line.decode("utf-8"), parse_constant=reject_constant)


async def run_proxy(config: AppConfig) -> int:
    """Start the upstream MCP server and relay traffic through policy checks."""
    policy = PolicyEngine(config)
    audit = AuditLog(config.audit_path, config.audit_max_bytes, config.audit_backup_count)
    environment = os.environ.copy()
    environment.update(config.upstream_env)

    try:
        process = await asyncio.create_subprocess_exec(
            *config.upstream_command,
            cwd=str(config.upstream_cwd) if config.upstream_cwd else None,
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
            limit=config.max_message_bytes + 1,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        LOG.error("Could not start upstream MCP server: %s", exc)
        audit.record("upstream_start_failed", error_type=type(exc).__name__)
        audit.close()
        return 2

    assert process.stdin is not None
    assert process.stdout is not None
    write_lock = asyncio.Lock()
    audit.record("proxy_started", upstream_executable=config.upstream_command[0])

    # A daemon reader thread keeps stdin portable across Windows and POSIX.
    # It avoids awaiting a blocking stdin read in the asyncio executor, which
    # could otherwise delay shutdown if the upstream process exits first.
    loop = asyncio.get_running_loop()
    input_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def read_stdin() -> None:
        try:
            while True:
                item = sys.stdin.buffer.readline(config.max_message_bytes + 2)
                try:
                    loop.call_soon_threadsafe(input_queue.put_nowait, item)
                except RuntimeError:
                    return
                if not item:
                    return
        except Exception:
            try:
                loop.call_soon_threadsafe(input_queue.put_nowait, b"")
            except RuntimeError:
                return

    threading.Thread(target=read_stdin, name="mcp-firewall-stdin", daemon=True).start()

    async def write_client(data: bytes) -> None:
        async with write_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def client_to_server() -> None:
        while True:
            line = await input_queue.get()
            if not line:
                return

            payload = line.rstrip(b"\r\n")
            if len(payload) > config.max_message_bytes or (len(line) >= config.max_message_bytes + 2 and not line.endswith(b"\n")):
                LOG.error("Client message exceeded max_message_bytes; closing proxy to avoid stream desynchronization")
                audit.record("message_rejected", direction="client_to_server", reason="message_size_limit_exceeded")
                return

            try:
                message = _parse_json_line(payload)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                await write_client(_json_bytes(_error_response(None, -32700, "Parse error", "invalid_json")))
                audit.record("message_rejected", direction="client_to_server", reason="invalid_json")
                continue

            if isinstance(message, list):
                await write_client(_json_bytes(_error_response(None, -32600, "Invalid Request", "json_rpc_batch_not_supported_by_this_proxy")))
                audit.record("message_rejected", direction="client_to_server", reason="batch_not_supported")
                continue

            forward, response = evaluate_client_message(message, policy, audit)
            if response is not None:
                await write_client(_json_bytes(response))
            if forward:
                process.stdin.write(payload + b"\n")
                await process.stdin.drain()

    async def server_to_client() -> None:
        while True:
            try:
                line = await process.stdout.readline()
            except (ValueError, asyncio.LimitOverrunError):
                LOG.error("Upstream message exceeded max_message_bytes")
                audit.record("message_rejected", direction="server_to_client", reason="message_size_limit_exceeded")
                return
            if not line:
                return
            payload = line.rstrip(b"\r\n")
            if len(payload) > config.max_message_bytes:
                LOG.error("Upstream message exceeded max_message_bytes")
                audit.record("message_rejected", direction="server_to_client", reason="message_size_limit_exceeded")
                return
            try:
                message = _parse_json_line(payload)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                # Preserve malformed upstream output for the client to reject itself.
                await write_client(line if line.endswith(b"\n") else line + b"\n")
                audit.record("upstream_protocol_warning", reason="invalid_json")
                continue
            filtered = filter_server_message(message, policy, audit)
            await write_client(_json_bytes(filtered))

    client_task = asyncio.create_task(client_to_server(), name="mcp-firewall-client-reader")
    server_task = asyncio.create_task(server_to_client(), name="mcp-firewall-server-reader")
    exit_code = 0
    try:
        done, pending = await asyncio.wait(
            {client_task, server_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if server_task in done:
            client_task.cancel()
            await asyncio.gather(client_task, return_exceptions=True)
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            exit_code = process.returncode or 0
        else:
            process.stdin.close()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            server_task.cancel()
            await asyncio.gather(server_task, return_exceptions=True)
            exit_code = process.returncode or 0
    except asyncio.CancelledError:
        if process.returncode is None:
            process.terminate()
            await process.wait()
        raise
    finally:
        for task in (client_task, server_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(client_task, server_task, return_exceptions=True)
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        audit.record("proxy_stopped", upstream_exit_code=process.returncode)
        audit.close()
    return exit_code
