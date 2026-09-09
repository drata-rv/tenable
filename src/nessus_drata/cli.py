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
from .drata_client import DrataApiError, DrataClient, DrataResponseError, count_record_outcomes
from .logging_setup import setup_logging
from .nessus_client import NessusApiError, NessusClient
from .parse_nessus_csv import parse_nessus_csv
from .parse_nessus_xml import parse_nessus_xml
from .report import RunReport, print_console_summary, write_report
from .safety import all_gates_passed, apply_force_bypass, bypassed_gate_names, evaluate_gates
from .schema_gen import generate_schema
from .state import LastRunState, LockHeldError, acquire_lock, load_last_run_state, save_last_run_state
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


def _build_nessus_client(config: AppConfig, access_key: str, secret_key: str) -> NessusClient:
    if not config.nessus.verify_tls:
        print(
            "[WARNING] TLS verification is DISABLED for the Nessus console "
            "(verify_tls: false). This is insecure.",
            file=sys.stderr,
        )
    return NessusClient(
        base_url=config.nessus.base_url,
        access_key=access_key,
        secret_key=secret_key,
        verify_tls=config.nessus.verify_tls,
        ca_bundle=config.nessus.ca_bundle,
        connect_timeout=config.nessus.connect_timeout_seconds,
        read_timeout=config.nessus.read_timeout_seconds,
    )


def cmd_probe_nessus(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config), Path(args.checks), require_secrets=False)
    access_key = get_required_env("NESSUS_ACCESS_KEY")
    secret_key = get_required_env("NESSUS_SECRET_KEY")

    client = _build_nessus_client(config, access_key, secret_key)
    status = client.server_status()
    print(f"server_status: {status}")

    scans_response = client.list_scans()
    scans = scans_response.get("scans") or []
    print(f"scans: {len(scans)} found")
    for scan in scans:
        print(
            f"  id={scan.get('id')} name={scan.get('name')!r} "
            f"status={scan.get('status')} last_modification_date={scan.get('last_modification_date')}"
        )
    return EXIT_OK


def cmd_probe_drata(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config), Path(args.checks), require_secrets=False)
    api_key = get_required_env("DRATA_API_KEY")
    client = DrataClient(
        base_url=config.drata.base_url, api_key=api_key, max_retries=config.drata.max_retries
    )
    connection = client.get_connection(config.drata.connection_id)
    resources = connection.get("customResources") or []
    resource_id = resources[0].get("id") if resources else None
    display_name_key = connection.get("displayNameKey")
    print(f"connectionId: {config.drata.connection_id}")
    print(f"resourceId: {resource_id}")
    print(f"displayNameKey: {display_name_key}")
    return EXIT_OK


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id_from(started_at: str) -> str:
    return started_at.replace(":", "").replace("-", "")


def _session_id_for(scan_id: int, scan_ended_at: str) -> str:
    """Deterministic, traceable session id (spec Section 5.3, literal format:
    'nessus-{scan_id}-{scan_ended_at as YYYYMMDDTHHMMSSZ}'). The 'nessus-'
    prefix here is a literal from the spec's own format string, distinct from
    the configurable drata.record_id_prefix used for per-record ids.
    """
    compact = scan_ended_at.replace(":", "").replace("-", "")
    return f"nessus-{scan_id}-{compact}"


def _chunk(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _resolve_scan_id(client: NessusClient, config: AppConfig) -> int:
    """Spec Section 3.5: scan_id (preferred) or scan_name_exact, requiring
    exactly one match. Never fuzzy match."""
    if config.nessus.scan_id is not None:
        return config.nessus.scan_id
    if config.nessus.scan_name_exact:
        scans_response = client.list_scans()
        scans = scans_response.get("scans") or []
        matches = [s for s in scans if s.get("name") == config.nessus.scan_name_exact]
        if len(matches) != 1:
            raise ConfigError(
                f"scan_name_exact {config.nessus.scan_name_exact!r} matched "
                f"{len(matches)} scan(s); need exactly 1"
            )
        return matches[0]["id"]
    raise ConfigError("config must supply nessus.scan_id or nessus.scan_name_exact")


def _epoch_to_iso(value) -> Optional[str]:
    if value is None:
        return None
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _live_nessus_export(
    config: AppConfig, run_id: str
) -> tuple[list, str, int, str, Optional[str]]:
    """Returns (host_results, parse_mode, scan_id, scan_name, scan_ended_at).

    UNVERIFIED against a live console — this sandbox has no reachable Nessus
    instance. Response field names (info.name, info.status,
    history[].history_id/.status/.last_modification_date) follow the
    standard, documented Nessus API shape referenced in the spec's own
    Sources section, but this whole path is pending operator verification
    per acceptance tests 20, 22, 23, 24.
    """
    access_key = get_required_env("NESSUS_ACCESS_KEY")
    secret_key = get_required_env("NESSUS_SECRET_KEY")
    client = _build_nessus_client(config, access_key, secret_key)

    scan_id = _resolve_scan_id(client, config)
    scan_detail = client.get_scan(scan_id)
    info = scan_detail.get("info")
    if not isinstance(info, dict):
        raise NessusApiError(f"scan {scan_id}: response has no 'info' object")
    scan_name = info.get("name", "")

    history_id = None
    if config.nessus.use_latest_history:
        history = scan_detail.get("history") or []
        completed = [h for h in history if h.get("status") == "completed"]
        if not completed:
            raise NessusApiError(f"scan {scan_id} has no completed history entry")
        latest = max(completed, key=lambda h: h.get("last_modification_date") or 0)
        history_id = latest.get("history_id")
        scan_ended_at = _epoch_to_iso(latest.get("last_modification_date"))
    else:
        status = info.get("status")
        if status == "running":
            raise NessusApiError(f"scan {scan_id} is in progress (status=running)")
        if status != "completed":
            raise NessusApiError(f"scan {scan_id} status is {status!r}, expected 'completed'")
        scan_ended_at = _epoch_to_iso(info.get("last_modification_date"))

    export_response = client.request_export(
        scan_id, export_format=config.nessus.export_format, history_id=history_id
    )
    file_id = export_response.get("file")
    if file_id is None:
        raise NessusApiError(f"scan {scan_id}: export response missing 'file' id")

    client.wait_for_export_ready(
        scan_id, file_id, timeout_seconds=config.nessus.export_timeout_seconds
    )

    raw_dir = Path(config.runtime.artifacts_dir) / "raw" / run_id
    extension = "csv" if config.nessus.export_format == "csv" else "nessus"
    dest_path = raw_dir / f"scan-{scan_id}.{extension}"
    client.download_export(scan_id, file_id, dest_path)

    if config.nessus.export_format == "csv":
        hosts = list(parse_nessus_csv(dest_path))
        parse_mode = "csv_degraded"
    else:
        hosts = list(parse_nessus_xml(dest_path))
        parse_mode = "xml_full"

    return hosts, parse_mode, scan_id, scan_name, scan_ended_at


def _parse_scan_input(
    args: argparse.Namespace, config: AppConfig, run_id: str
) -> tuple[list, str, int, str, Optional[str]]:
    """Returns (host_results, parse_mode, scan_id, scan_name, scan_ended_at).

    --fixtures skips the Nessus client entirely (spec Section 2 #4, Section
    10) — zero network, zero credentials. scan_ended_at is None in fixture
    mode (there's no real scan to report a freshness timestamp for); the
    caller falls back to "now" in that case.
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
        return hosts, parse_mode, scan_id, scan_name, None

    return _live_nessus_export(config, run_id)


def _cancel_other_sessions(
    client: DrataClient, config: AppConfig, session_id: str, logger: logging.Logger
) -> None:
    """Only one session may be IN_PROGRESS at a time (spec 5.3). Cancel any
    OTHER stale in-progress session — never our own about-to-be-(re)used
    session_id, since re-running the identical scan is a legitimate
    retry/continuation, not a stale leftover.

    Field-priority CONFIRMED against a live Drata sandbox (2026-09-09): a
    session-list entry carries BOTH a short internal database id under
    "id" (observed value: "1") AND the real application-level identifier
    under "sessionId" (the string this client itself creates, spec 5.3's
    "nessus-{scan_id}-{scan_ended_at}" format). Checking "id" first was a
    live, reproduced bug — Drata's own session-actions endpoint validates
    "Session ID must be between 3 and 64 characters" and correctly
    rejected the short internal id with a 400. "sessionId" is now checked
    FIRST, "id" LAST, and every candidate must be a string of 3-64 chars
    (Drata's own stated constraint) before use — a wrong-field guess now
    fails closed (tries the next candidate, then logs and skips) instead
    of sending a request Drata is guaranteed to reject.
    """
    existing_sessions = client.list_sessions(config.drata.connection_id, config.drata.resource_id)
    for existing in existing_sessions:
        candidates = (
            existing.get("sessionId"),
            existing.get("session_id"),
            existing.get("uuid"),
            existing.get("id"),
        )
        other_id = next(
            (c for c in candidates if isinstance(c, str) and 3 <= len(c) <= 64),
            None,
        )
        if other_id is None:
            logger.warning(
                "stale-session cleanup: could not determine a valid "
                "(string, 3-64 char) session id for an IN_PROGRESS session "
                "entry -- skipping it rather than guessing. entry=%r",
                existing,
            )
            continue
        if other_id != session_id:
            logger.warning("cancelling stale in-progress session %s", other_id)
            client.cancel_session(config.drata.connection_id, config.drata.resource_id, other_id)


def _upload_batch_with_409_retry(
    client: DrataClient,
    config: AppConfig,
    session_id: str,
    batch: list,
    logger: logging.Logger,
) -> tuple[bool, Optional[dict]]:
    """Upload one batch. On a 409 (session state conflict), cancel any
    stale session and retry this exact batch once, then terminal (spec
    5.4: "cancel stale session, retry once, then terminal"). Returns
    (success, response_body_or_None).
    """
    try:
        body = client.upload_session_batch(
            config.drata.connection_id, config.drata.resource_id, session_id, batch
        )
        return True, body
    except DrataResponseError as exc:
        if exc.status_code != 409:
            logger.error("batch upload failed: %s", exc)
            return False, None
        logger.warning(
            "409 conflict uploading batch to session %s; cancelling stale "
            "session(s) and retrying this batch once",
            session_id,
        )
        try:
            _cancel_other_sessions(client, config, session_id, logger)
            body = client.upload_session_batch(
                config.drata.connection_id, config.drata.resource_id, session_id, batch
            )
            return True, body
        except DrataApiError as retry_exc:
            logger.error("batch upload failed after 409 retry: %s", retry_exc)
            return False, None
    except DrataApiError as exc:
        logger.error("batch upload failed: %s", exc)
        return False, None


def _live_drata_push(
    config: AppConfig,
    records: tuple,
    parse_mode: str,
    summary,
    prior_state: LastRunState,
    scan_id: int,
    scan_ended_at: str,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> tuple[int, Optional[str], str, int, int, int, tuple]:
    """Session-based push (spec Section 5.3) with safety-gate enforcement
    (Section 5.5). Returns (exit_code, session_id, session_action,
    batches_sent, records_created, records_updated, final_gates).

    scan_id/scan_ended_at are the same values already resolved earlier in
    _run_pipeline (not re-derived from records[0]) so the session id stays
    deterministic per spec 5.3 even when records is empty.

    UNVERIFIED against a live Drata sandbox — no reachable instance in this
    build environment. Pending operator execution (acceptance test 22
    specifically exercises this path end to end).
    """
    if config.drata.connection_id == 0 or config.drata.resource_id == 0:
        raise ConfigError(
            "drata.connection_id and drata.resource_id must be set after "
            "one-time connection creation (spec Section 11 Runbook) — both "
            "are still 0 (placeholder default)"
        )

    def _evaluate(batch_upload_results):
        gates = evaluate_gates(
            record_count=len(records),
            previous_record_count=prior_state.last_record_count,
            coverage_pct=summary.coverage_pct,
            duplicate_ids=summary.duplicate_ids,
            parse_mode=parse_mode,
            allow_degraded_session=args.allow_degraded_session,
            batch_upload_results=batch_upload_results,
            min_hosts=config.safety.min_hosts,
            max_shrink_ratio=config.safety.max_shrink_ratio,
            min_manifest_coverage_pct=config.safety.min_manifest_coverage_pct,
        )
        return apply_force_bypass(gates, force=args.force)

    pre_gates = _evaluate(batch_upload_results=None)
    for name in bypassed_gate_names(pre_gates):
        logger.warning("safety gate BYPASSED by --force: %s", name)

    api_key = get_required_env("DRATA_API_KEY")
    client = DrataClient(
        base_url=config.drata.base_url, api_key=api_key, max_retries=config.drata.max_retries
    )

    session_id = _session_id_for(scan_id, scan_ended_at)

    _cancel_other_sessions(client, config, session_id, logger)

    if not all_gates_passed(pre_gates):
        # No batch has been uploaded under session_id yet, so there is no
        # session for Drata to actually cancel (a session only exists
        # server-side once the first batch POST creates it) — distinct from
        # the post-upload failure path below, which does call cancel_session
        # on a session that genuinely exists.
        logger.error("safety gate(s) failed before any upload; nothing sent")
        return EXIT_SAFETY_GATE, session_id, "aborted_pre_upload", 0, 0, 0, pre_gates

    batch_upload_results = []
    batches_sent = 0
    records_created = 0
    records_updated = 0
    for batch in _chunk(list(records), config.drata.batch_size):
        success, response_body = _upload_batch_with_409_retry(
            client, config, session_id, batch, logger
        )
        batch_upload_results.append(success)
        if not success:
            break  # spec: a single failed batch aborts completion
        batches_sent += 1
        created, updated = count_record_outcomes(response_body)
        records_created += created
        records_updated += updated

    final_gates = _evaluate(batch_upload_results=batch_upload_results)

    if all_gates_passed(final_gates):
        client.complete_session(config.drata.connection_id, config.drata.resource_id, session_id)
        return (
            EXIT_OK,
            session_id,
            "complete",
            batches_sent,
            records_created,
            records_updated,
            final_gates,
        )

    logger.error("safety gate(s) failed after upload; cancelling session %s", session_id)
    client.cancel_session(config.drata.connection_id, config.drata.resource_id, session_id)
    return (
        EXIT_SAFETY_GATE,
        session_id,
        "cancel",
        batches_sent,
        records_created,
        records_updated,
        final_gates,
    )


def _run_pipeline(args: argparse.Namespace, config: AppConfig, logger: logging.Logger) -> int:
    started_at = _now_iso()
    run_id = _run_id_from(started_at)

    hosts, parse_mode, scan_id, scan_name, live_scan_ended_at = _parse_scan_input(
        args, config, run_id
    )

    audit_file = load_manifest_audit_file(Path(args.checks))
    now = _now_iso()
    scan_ended_at = live_scan_ended_at or now
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

    payloads_dir = Path(config.runtime.artifacts_dir) / "payloads" / run_id
    payloads_dir.mkdir(parents=True, exist_ok=True)
    payload_path = payloads_dir / "records.json"
    payload_path.write_text(json.dumps(list(records), indent=2) + "\n")

    if args.dry_run:
        gates = evaluate_gates(
            record_count=len(records),
            previous_record_count=prior_state.last_record_count,
            coverage_pct=summary.coverage_pct,
            duplicate_ids=summary.duplicate_ids,
            parse_mode=parse_mode,
            allow_degraded_session=args.allow_degraded_session,
            batch_upload_results=None,  # dry-run: no live upload attempted, gate 6 not evaluated
            min_hosts=config.safety.min_hosts,
            max_shrink_ratio=config.safety.max_shrink_ratio,
            min_manifest_coverage_pct=config.safety.min_manifest_coverage_pct,
        )
        gates = apply_force_bypass(gates, force=args.force)
        for name in bypassed_gate_names(gates):
            logger.warning("safety gate BYPASSED by --force: %s", name)

        logger.info(
            "dry-run: wrote %d record(s) to %s, zero Drata calls made",
            len(records),
            payload_path,
        )
        exit_code = EXIT_OK
        session_id = None
        session_action = None
        batches_sent = 0
        records_created = 0
        records_updated = 0
    else:
        (
            exit_code,
            session_id,
            session_action,
            batches_sent,
            records_created,
            records_updated,
            gates,
        ) = _live_drata_push(
            config, records, parse_mode, summary, prior_state, scan_id, scan_ended_at, args, logger
        )

    finished_at = _now_iso()

    if not args.dry_run and exit_code == EXIT_OK:
        save_last_run_state(
            Path(config.runtime.state_dir),
            LastRunState(
                last_success_at=finished_at,
                last_record_count=len(records),
                last_session_id=session_id,
                last_scan_ended_at=scan_ended_at,
            ),
        )
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
        records_created=records_created,
        records_updated=records_updated,
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
    # --force and --allow-degraded-session deliberately do NOT live on the
    # top-level parser (only run_parser defines them, below). argparse's
    # subparser mechanism parses each subcommand's own arguments into a
    # FRESH namespace and then copies every one of its dests back onto the
    # parent namespace (see _SubParsersAction.__call__) -- so a dest defined
    # on BOTH the parent and a subparser gets silently overwritten by the
    # subparser's own default whenever the flag is supplied before the
    # subcommand instead of after, with no error. Defining it only where
    # it's actually used (run) makes "after run" the one unambiguous
    # position, consistent with --dry-run/--fixtures.

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

    sub.add_parser(
        "probe-nessus",
        help="GET /server/status and /scans. Confirms credentials and reachability.",
    )
    sub.add_parser(
        "probe-drata",
        help="GET the connection with expand[]=customResources. Confirms key, scopes, IDs.",
    )

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
    # --force and --allow-degraded-session live ONLY here, not on the
    # top-level parser -- see the comment above parser.add_argument calls
    # for why defining them on both would silently misbehave. `run` is the
    # only command that reads either flag.
    run_parser.add_argument("--force", action="store_true")
    run_parser.add_argument("--allow-degraded-session", action="store_true")

    return parser


_HANDLERS = {
    "validate-config": cmd_validate_config,
    "gen-schema": cmd_gen_schema,
    "probe-nessus": cmd_probe_nessus,
    "probe-drata": cmd_probe_drata,
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
    except NessusApiError as exc:
        print(f"[NESSUS ERROR] {exc}", file=sys.stderr)
        return EXIT_NESSUS_ERROR
    except DrataApiError as exc:
        print(f"[DRATA ERROR] {exc}", file=sys.stderr)
        return EXIT_DRATA_ERROR
    except Exception:
        logging.getLogger("nessus_drata").exception("unexpected error")
        return EXIT_UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
