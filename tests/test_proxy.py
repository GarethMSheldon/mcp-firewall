from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mcp_firewall.audit import AuditLog
from mcp_firewall.config import load_config
from mcp_firewall.policy import PolicyEngine
from mcp_firewall.proxy import evaluate_client_message, filter_server_message


class ProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        config_path = root / "firewall.json"
        config_path.write_text(
            json.dumps({
                "upstream": {"command": ["python", "server.py"]},
                "policy": {"default_action": "deny", "allow_tools": ["echo"], "deny_tools": ["*delete*"]},
                "audit": {"path": "audit.jsonl"},
            }),
            encoding="utf-8",
        )
        self.config = load_config(config_path)
        self.policy = PolicyEngine(self.config)
        self.audit = AuditLog(self.config.audit_path, self.config.audit_max_bytes, self.config.audit_backup_count)
        self.addCleanup(self.audit.close)

    def test_denied_call_returns_json_rpc_error(self) -> None:
        message = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "delete_file", "arguments": {}}}
        forward, response = evaluate_client_message(message, self.policy, self.audit)
        self.assertFalse(forward)
        self.assertIsNotNone(response)
        self.assertEqual(response["error"]["code"], -32001)

    def test_allowed_call_is_forwarded(self) -> None:
        message = {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "echo", "arguments": {"message": "hi"}}}
        forward, response = evaluate_client_message(message, self.policy, self.audit)
        self.assertTrue(forward)
        self.assertIsNone(response)

    def test_blocked_notification_has_no_response(self) -> None:
        message = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_file", "arguments": {}}}
        forward, response = evaluate_client_message(message, self.policy, self.audit)
        self.assertFalse(forward)
        self.assertIsNone(response)

    def test_tools_list_hides_denied_tools(self) -> None:
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "echo"}, {"name": "delete_file"}, {"name": "unknown"}]},
        }
        filtered = filter_server_message(message, self.policy, self.audit)
        names = [tool["name"] for tool in filtered["result"]["tools"]]
        self.assertEqual(names, ["echo"])

    def test_non_tool_server_message_is_unchanged(self) -> None:
        message = {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "server"}}}
        self.assertEqual(filter_server_message(message, self.policy), message)

    def test_audit_does_not_record_argument_values(self) -> None:
        secret_value = "sensitive-demo-value-should-not-be-logged"
        message = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": secret_value}},
        }
        forward, response = evaluate_client_message(message, self.policy, self.audit)
        self.assertTrue(forward)
        self.assertIsNone(response)
        self.audit.close()
        audit_text = self.config.audit_path.read_text(encoding="utf-8")
        self.assertNotIn(secret_value, audit_text)
        self.assertIn('"argument_keys":["message"]', audit_text)


if __name__ == "__main__":
    unittest.main()
