"""Command-line entry point for MCP Firewall."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from . import __version__
from .config import ConfigurationError, load_config
from .policy import PolicyEngine
from .proxy import run_proxy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-firewall",
        description="Policy-enforcing stdio proxy for MCP tool calls.",
    )
    parser.add_argument("--config", "-c", default="config/firewall.json", help="Path to firewall JSON config")
    parser.add_argument("--check-config", action="store_true", help="Validate config and exit")
    parser.add_argument("--version", action="version", version=f"mcp-firewall {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging on stderr")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        config = load_config(args.config)
        # Compile regex rules during config validation, before a client is connected.
        PolicyEngine(config)
    except (ConfigurationError, ValueError) as exc:
        logging.getLogger("mcp_firewall").error("Configuration error: %s", exc)
        return 2

    if args.check_config:
        print(f"Configuration valid: {config.config_path}")
        print(f"Default action: {config.default_action}")
        print(f"Allow rules: {len(config.allow_tools)}; deny rules: {len(config.deny_tools)}")
        return 0

    try:
        return asyncio.run(run_proxy(config))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
