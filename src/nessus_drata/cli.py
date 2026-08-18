"""Argparse entrypoint. Exit codes per spec Section 6.5."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import AppConfig, ConfigError, load_config, redact

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_CONFIG_ERROR = 2
EXIT_NESSUS_ERROR = 3
EXIT_DRATA_ERROR = 4
EXIT_SAFETY_GATE = 5
EXIT_LOCKED = 6


def _print_resolved_config(config: AppConfig) -> None:
    print("Configuration OK")
    print(f"  nessus.base_url: {config.nessus.base_url}")
    print(f"  nessus.verify_tls: {config.nessus.verify_tls}")
    print(f"  nessus.scan_id: {config.nessus.scan_id}")
    print(f"  nessus.scan_name_exact: {config.nessus.scan_name_exact}")
    print(f"  nessus.use_latest_history: {config.nessus.use_latest_history}")
    print(f"  nessus.export_format: {config.nessus.export_format}")
    print(f"  drata.base_url: {config.drata.base_url}")
    print(f"  drata.connection_id: {config.drata.connection_id}")
    print(f"  drata.resource_id: {config.drata.resource_id}")
    print(f"  drata.use_sessions: {config.drata.use_sessions}")
    print(f"  drata.batch_size: {config.drata.batch_size}")
    print(f"  safety.min_hosts: {config.safety.min_hosts}")
    print(f"  safety.max_shrink_ratio: {config.safety.max_shrink_ratio}")
    print(f"  safety.min_manifest_coverage_pct: {config.safety.min_manifest_coverage_pct}")
    print(f"  runtime.artifacts_dir: {config.runtime.artifacts_dir}")
    print(f"  runtime.state_dir: {config.runtime.state_dir}")
    print(f"  runtime.log_dir: {config.runtime.log_dir}")
    print(f"  checks manifest: {len(config.checks)} check(s) loaded")
    for entry in config.checks:
        print(f"    - {entry.field} ({entry.match_type}, required={entry.required})")
    if config.secrets is not None:
        print(f"  NESSUS_ACCESS_KEY: {redact(config.secrets.nessus_access_key)}")
        print(f"  NESSUS_SECRET_KEY: {redact(config.secrets.nessus_secret_key)}")
        print(f"  DRATA_API_KEY: {redact(config.secrets.drata_api_key)}")


def cmd_validate_config(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config), Path(args.checks))
    _print_resolved_config(config)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m nessus_drata.cli")
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--checks", default="config/checks.yaml")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--allow-degraded-session", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "validate-config",
        help="Load config + manifest, validate field names, print resolved settings redacted",
    )

    return parser


_HANDLERS = {
    "validate-config": cmd_validate_config,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = _HANDLERS.get(args.command)
    if handler is None:
        parser.error(f"unknown command: {args.command}")
        return EXIT_UNEXPECTED  # pragma: no cover — parser.error exits before this

    try:
        return handler(args)
    except ConfigError as exc:
        print(f"[CONFIG ERROR] {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    sys.exit(main())
