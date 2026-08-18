"""Argparse entrypoint. Exit codes per spec Section 6.5."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import (
    AppConfig,
    ConfigError,
    get_required_env,
    load_checks_manifest,
    load_config,
    load_manifest_audit_file,
    redact,
)
from .drata_client import DrataApiError
from .logging_setup import setup_logging
from .parse_nessus_csv import parse_nessus_csv
from .parse_nessus_xml import parse_nessus_xml
from .report import RunReport, print_console_summary, write_report
from .safety import apply_force_bypass, bypassed_gate_names, evaluate_gates
from .schema_gen import generate_schema
from .state import LockHeldError, acquire_lock, load_last_run_state
from .transform import TransformError, transform_host_results

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
    print(f"  drata.record_id_prefix: {config.drata.record_id_prefix}")
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


def cmd_gen_schema(args: argparse.Namespace) -> int:
    checks = load_checks_manifest(Path(args.checks))
    schema = generate_schema(checks)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(schema, indent=2) + "\n")
    print(f"Wrote schema ({len(checks)} check field(s)) to {out_path}")
    return EXIT_OK


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id_from(started_at: str) -> str:
    return started_at.replace(":", "").replace("-", "")


def _parse_scan_input(args: argparse.Namespace, config: AppConfig) -> tuple[list, str, int, str]:
    """Returns (host_results, parse_mode, scan_id, scan_name).

    --fixtures skips the Nessus client entirely (spec Section 2 #4, Section
    10) — zero network, zero credentials. Live export (no --fixtures) is
    Phase 5's deliverable; nessus_client.py does not exist yet, so that path
    raises NotImplementedError for now rather than pretending to work. This
    is never hit by any offline acceptance test (1-19, 25-29 all use
    --fixtures); tests 20-24 explicitly require live access and are reported
    as pending operator execution.
    """
    if args.fixtures:
        fixtures_path = Path(args.fixtures)
        if fixtures_path.suffix.lower() == ".csv":
            hosts = list(parse_nessus_csv(fixtures_path))
            parse_mode = "csv_degraded"
        else:
            hosts = list(parse_nessus_xml(fixtures_path))
            parse_mode = "xml_full"
        scan_id = config.nessus.scan_id if config.nessus.scan_id is not None else 0
        scan_name = f"Fixture Import: {fixtures_path.name}"
        return hosts, parse_mode, scan_id, scan_name

    # Live path — Phase 5.
    get_required_env("NESSUS_ACCESS_KEY")
    get_required_env("NESSUS_SECRET_KEY")
    raise NotImplementedError(
        "live Nessus export is implemented in Phase 5 (nessus_client.py does "
        "not exist yet) — pass --fixtures for now"
    )


def _run_pipeline(args: argparse.Namespace, config: AppConfig, logger: logging.Logger) -> int:
    started_at = _now_iso()
    run_id = _run_id_from(started_at)

    hosts, parse_mode, scan_id, scan_name = _parse_scan_input(args, config)

    audit_file = load_manifest_audit_file(Path(args.checks))
    now = _now_iso()
    scan_ended_at = now
    collected_at = now

    transform_result = transform_host_results(
        hosts,
        config.checks,
        record_id_prefix=config.drata.record_id_prefix,
        scan_id=scan_id,
        scan_name=scan_name,
        scan_ended_at=scan_ended_at,
        collected_at=collected_at,
        audit_file=audit_file,
    )
    records = transform_result.records
    summary = transform_result.summary

    prior_state = load_last_run_state(Path(config.runtime.state_dir))

    gates = evaluate_gates(
        record_count=len(records),
        previous_record_count=prior_state.last_record_count,
        coverage_pct=summary.coverage_pct,
        duplicate_ids=summary.duplicate_ids,
        parse_mode=parse_mode,
        allow_degraded_session=args.allow_degraded_session,
        batch_upload_results=None,  # no live upload attempted yet (dry-run always; live push is Phase 6)
        min_hosts=config.safety.min_hosts,
        max_shrink_ratio=config.safety.max_shrink_ratio,
        min_manifest_coverage_pct=config.safety.min_manifest_coverage_pct,
    )
    gates = apply_force_bypass(gates, force=args.force)
    for name in bypassed_gate_names(gates):
        logger.warning("safety gate BYPASSED by --force: %s", name)

    payloads_dir = Path(config.runtime.artifacts_dir) / "payloads" / run_id
    payloads_dir.mkdir(parents=True, exist_ok=True)
    payload_path = payloads_dir / "records.json"
    payload_path.write_text(json.dumps(list(records), indent=2) + "\n")

    if args.dry_run:
        logger.info(
            "dry-run: wrote %d record(s) to %s, zero Drata calls made",
            len(records),
            payload_path,
        )
        exit_code = EXIT_OK
        session_id = None
        session_action = None
        batches_sent = 0
    else:
        # Live push — Phase 6. Never hit by an offline acceptance test.
        raise NotImplementedError(
            "live Drata session push is implemented in Phase 6 — pass --dry-run for now"
        )

    finished_at = _now_iso()
    report = RunReport(
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        parse_mode=parse_mode,
        scan_id=scan_id,
        scan_name=scan_name,
        scan_ended_at=scan_ended_at,
        host_count=summary.host_count,
        record_count=len(records),
        checks_in_manifest=summary.checks_in_manifest,
        manifest_coverage_pct=summary.coverage_pct,
        manifest_misses=summary.manifest_misses,
        manifest_ambiguous=summary.manifest_ambiguous,
        identity_fallbacks=summary.identity_fallbacks,
        duplicate_ids=summary.duplicate_ids,
        batches_sent=batches_sent,
        records_created=0,
        records_updated=0,
        session_id=session_id,
        session_action=session_action,
        safety_gates=tuple(
            {"name": g.name, "passed": g.passed, "reason": g.reason} for g in gates
        ),
        exit_code=exit_code,
    )
    write_report(Path(config.runtime.artifacts_dir) / "reports", report)
    print_console_summary(report)

    return exit_code


def cmd_run(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config), Path(args.checks), require_secrets=False)

    # Register any secret that happens to be set for redaction BEFORE any
    # logging happens, even though this specific invocation may not strictly
    # require it — closes the window where a log line could leak a secret
    # that gets hard-required a few lines later (get_required_env).
    candidate_secrets = [
        v
        for v in (
            os.environ.get("NESSUS_ACCESS_KEY"),
            os.environ.get("NESSUS_SECRET_KEY"),
            os.environ.get("DRATA_API_KEY"),
        )
        if v
    ]
    setup_logging(Path(config.runtime.log_dir), log_level=args.log_level, secrets=candidate_secrets)
    logger = logging.getLogger("nessus_drata.run")

    try:
        with acquire_lock(Path(config.runtime.state_dir)):
            return _run_pipeline(args, config, logger)
    except LockHeldError as exc:
        logger.error(str(exc))
        print(f"[LOCKED] {exc}", file=sys.stderr)
        return EXIT_LOCKED


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
    gen_schema_parser = sub.add_parser(
        "gen-schema",
        help="Emit the Drata JSON schema from the checks manifest. No network.",
    )
    gen_schema_parser.add_argument("--out", default="artifacts/schema.json")

    run_parser = sub.add_parser(
        "run",
        help="Full pipeline: parse, transform, safety gates, push (or --dry-run)",
    )
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument(
        "--fixtures",
        default=None,
        help="Path to a .nessus or .csv fixture file; skips the Nessus client entirely",
    )

    return parser


_HANDLERS = {
    "validate-config": cmd_validate_config,
    "gen-schema": cmd_gen_schema,
    "run": cmd_run,
}


def main(argv: Optional[list[str]] = None) -> int:
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
    except TransformError as exc:
        print(f"[DATA ERROR] {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except DrataApiError as exc:
        print(f"[DRATA ERROR] {exc}", file=sys.stderr)
        return EXIT_DRATA_ERROR
    except Exception:
        logging.getLogger("nessus_drata").exception("unexpected error")
        return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
