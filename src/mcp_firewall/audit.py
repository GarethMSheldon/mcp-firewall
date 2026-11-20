"""Structured, value-free JSONL audit logging."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class AuditLog:
    """Write compact audit events without recording tool argument values."""

    def __init__(self, path: Path, max_bytes: int, backup_count: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logging.getLogger(f"mcp_firewall.audit.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        handler = RotatingFileHandler(
            path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def record(self, event: str, **fields: Any) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        try:
            self._logger.info(json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
        except Exception:
            # A logging problem must not cause the proxy to disclose arguments or crash silently.
            logging.getLogger("mcp_firewall").exception("Could not write audit event")

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.flush()
            handler.close()
            self._logger.removeHandler(handler)
