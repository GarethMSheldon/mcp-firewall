"""Tool allowlisting and argument policy enforcement."""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any

from .config import AppConfig


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    argument_bytes: int = 0
    argument_keys: tuple[str, ...] = ()


class PolicyEngine:
    """Evaluate MCP tool discovery and invocation against explicit policy."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self._blocked_keys = {key.casefold() for key in config.blocked_argument_keys}
        try:
            self._blocked_patterns = [re.compile(pattern) for pattern in config.blocked_string_patterns]
        except re.error as exc:
            raise ValueError(f"Invalid blocked_string_patterns expression: {exc}") from exc

    def tool_name_allowed(self, name: str) -> tuple[bool, str]:
        if not name or not isinstance(name, str):
            return False, "invalid_tool_name"

        if any(fnmatch.fnmatchcase(name, pattern) for pattern in self.config.deny_tools):
            return False, "tool_matches_deny_rule"

        if any(fnmatch.fnmatchcase(name, pattern) for pattern in self.config.allow_tools):
            return True, "tool_matches_allow_rule"

        if self.config.default_action == "allow":
            return True, "default_allow"
        return False, "no_allow_rule_matched"

    def check_tool_call(self, params: Any) -> Decision:
        if not isinstance(params, dict):
            return Decision(False, "invalid_tool_call_parameters")

        name = params.get("name")
        allowed, reason = self.tool_name_allowed(name) if isinstance(name, str) else (False, "missing_tool_name")
        if not allowed:
            return Decision(False, reason)

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return Decision(False, "tool_arguments_must_be_an_object")

        try:
            encoded = json.dumps(arguments, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            return Decision(False, "tool_arguments_are_not_valid_json")

        argument_bytes = len(encoded)
        top_level_keys = tuple(sorted(str(key) for key in arguments.keys()))
        if argument_bytes > self.config.max_argument_bytes:
            return Decision(False, "argument_size_limit_exceeded", argument_bytes, top_level_keys)

        if self._depth_exceeded(arguments, depth=1):
            return Decision(False, "argument_depth_limit_exceeded", argument_bytes, top_level_keys)

        blocked_key = self._find_blocked_key(arguments)
        if blocked_key is not None:
            return Decision(False, f"blocked_argument_key:{blocked_key}", argument_bytes, top_level_keys)

        blocked_pattern = self._find_blocked_string(arguments)
        if blocked_pattern is not None:
            return Decision(False, f"blocked_string_pattern:{blocked_pattern}", argument_bytes, top_level_keys)

        return Decision(True, reason, argument_bytes, top_level_keys)

    def _depth_exceeded(self, value: Any, depth: int) -> bool:
        if depth > self.config.max_argument_depth:
            return True
        if isinstance(value, dict):
            return any(self._depth_exceeded(child, depth + 1) for child in value.values())
        if isinstance(value, list):
            return any(self._depth_exceeded(child, depth + 1) for child in value)
        return False

    def _find_blocked_key(self, value: Any) -> str | None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                if key_text.casefold() in self._blocked_keys:
                    return key_text
                found = self._find_blocked_key(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = self._find_blocked_key(child)
                if found is not None:
                    return found
        return None

    def _find_blocked_string(self, value: Any) -> str | None:
        if isinstance(value, str):
            for index, pattern in enumerate(self._blocked_patterns):
                if pattern.search(value):
                    return str(index)
        elif isinstance(value, dict):
            for child in value.values():
                found = self._find_blocked_string(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = self._find_blocked_string(child)
                if found is not None:
                    return found
        return None
