from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_firewall.config import load_config
from mcp_firewall.policy import PolicyEngine


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.config_path = Path(self.temp_dir.name) / "firewall.json"
        self.config_path.write_text(
            '''{
              "upstream": {"command": ["python", "server.py"]},
              "policy": {
                "default_action": "deny",
                "allow_tools": ["read_*", "echo"],
                "deny_tools": ["*delete*"],
                "max_argument_bytes": 120,
                "max_argument_depth": 3,
                "blocked_argument_keys": ["password", "api_key"],
                "blocked_string_patterns": ["(?i)drop\\\\s+table"]
              },
              "audit": {"path": "audit.jsonl"}
            }''',
            encoding="utf-8",
        )
        self.config = load_config(self.config_path)
        self.policy = PolicyEngine(self.config)

    def test_default_deny(self) -> None:
        allowed, reason = self.policy.tool_name_allowed("unknown_tool")
        self.assertFalse(allowed)
        self.assertEqual(reason, "no_allow_rule_matched")

    def test_allow_pattern(self) -> None:
        allowed, _ = self.policy.tool_name_allowed("read_file")
        self.assertTrue(allowed)

    def test_deny_takes_precedence(self) -> None:
        allowed, reason = self.policy.tool_name_allowed("delete_file")
        self.assertFalse(allowed)
        self.assertEqual(reason, "tool_matches_deny_rule")

    def test_blocks_sensitive_argument_key_recursively(self) -> None:
        result = self.policy.check_tool_call({"name": "echo", "arguments": {"metadata": {"password": "not-logged"}}})
        self.assertFalse(result.allowed)
        self.assertIn("blocked_argument_key", result.reason)

    def test_blocks_oversized_arguments(self) -> None:
        result = self.policy.check_tool_call({"name": "echo", "arguments": {"message": "x" * 200}})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "argument_size_limit_exceeded")

    def test_blocks_nested_arguments_over_depth(self) -> None:
        result = self.policy.check_tool_call({"name": "echo", "arguments": {"a": {"b": {"c": {"d": "value"}}}}})
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "argument_depth_limit_exceeded")

    def test_blocks_matching_string_pattern(self) -> None:
        result = self.policy.check_tool_call({"name": "echo", "arguments": {"message": "DROP TABLE users"}})
        self.assertFalse(result.allowed)
        self.assertTrue(result.reason.startswith("blocked_string_pattern"))

    def test_allows_valid_call(self) -> None:
        result = self.policy.check_tool_call({"name": "echo", "arguments": {"message": "hello"}})
        self.assertTrue(result.allowed)
        self.assertEqual(result.argument_keys, ("message",))


if __name__ == "__main__":
    unittest.main()
