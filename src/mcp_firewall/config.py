"""Configuration loading and validation for MCP Firewall."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigurationError(ValueError):
    """Raised when the firewall configuration is invalid."""


@dataclass(frozen=True)
class AppConfig:
    config_path: Path
    upstream_command: tuple[str, ...]
    upstream_cwd: Path | None
    upstream_env: dict[str, str]
    default_action: str
    allow_tools: tuple[str, ...]
    deny_tools: tuple[str, ...]
    max_message_bytes: int
    max_argument_bytes: int
    max_argument_depth: int
    blocked_argument_keys: tuple[str, ...]
    blocked_string_patterns: tuple[str, ...]
    audit_path: Path
    audit_max_bytes: int
    audit_backup_count: int


def _positive_int(section: dict[str, Any], key: str, default: int) -> int:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigurationError(f"'{key}' must be a positive integer")
    return value


def load_config(path: str | Path) -> AppConfig:
    """Load and validate a JSON configuration file."""
    config_path = Path(path).expanduser().resolve()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"Configuration file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"Invalid JSON in {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigurationError("Configuration root must be a JSON object")

    upstream = raw.get("upstream")
    policy = raw.get("policy", {})
    audit = raw.get("audit", {})
    if not isinstance(upstream, dict):
        raise ConfigurationError("'upstream' must be an object")
    if not isinstance(policy, dict):
        raise ConfigurationError("'policy' must be an object")
    if not isinstance(audit, dict):
        raise ConfigurationError("'audit' must be an object")

    command = upstream.get("command")
    if not isinstance(command, list) or not command or any(
        not isinstance(part, str) or not part.strip() for part in command
    ):
        raise ConfigurationError("'upstream.command' must be a non-empty array of strings")

    cwd_value = upstream.get("cwd")
    cwd: Path | None = None
    if cwd_value is not None:
        if not isinstance(cwd_value, str) or not cwd_value.strip():
            raise ConfigurationError("'upstream.cwd' must be a non-empty string")
        cwd = Path(cwd_value).expanduser()
        if not cwd.is_absolute():
            cwd = (config_path.parent / cwd).resolve()

    env_value = upstream.get("env", {})
    if not isinstance(env_value, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in env_value.items()
    ):
        raise ConfigurationError("'upstream.env' must be an object containing string values")

    default_action = policy.get("default_action", "deny")
    if default_action not in {"allow", "deny"}:
        raise ConfigurationError("'policy.default_action' must be 'allow' or 'deny'")

    def string_list(section: dict[str, Any], key: str) -> tuple[str, ...]:
        value = section.get(key, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ConfigurationError(f"'{key}' must be an array of strings")
        return tuple(value)

    audit_value = audit.get("path", "logs/mcp-firewall.jsonl")
    if not isinstance(audit_value, str) or not audit_value.strip():
        raise ConfigurationError("'audit.path' must be a non-empty string")
    audit_path = Path(audit_value).expanduser()
    if not audit_path.is_absolute():
        audit_path = (config_path.parent / audit_path).resolve()

    return AppConfig(
        config_path=config_path,
        upstream_command=tuple(command),
        upstream_cwd=cwd,
        upstream_env=dict(env_value),
        default_action=default_action,
        allow_tools=string_list(policy, "allow_tools"),
        deny_tools=string_list(policy, "deny_tools"),
        max_message_bytes=_positive_int(policy, "max_message_bytes", 1_048_576),
        max_argument_bytes=_positive_int(policy, "max_argument_bytes", 65_536),
        max_argument_depth=_positive_int(policy, "max_argument_depth", 12),
        blocked_argument_keys=string_list(policy, "blocked_argument_keys"),
        blocked_string_patterns=string_list(policy, "blocked_string_patterns"),
        audit_path=audit_path,
        audit_max_bytes=_positive_int(audit, "max_bytes", 5_000_000),
        audit_backup_count=_positive_int(audit, "backup_count", 5),
    )
