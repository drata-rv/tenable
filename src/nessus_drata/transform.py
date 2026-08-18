"""Host-grain record builder (spec Section 4). Pure function of parsed input
and manifest — no I/O, no wall-clock reads. This purity is what makes the
golden-file test possible: every timestamp and identifier the caller wants
baked into the output must be passed in explicitly.

Judgment call (spec ambiguity, flagged per CLAUDE.md "use your best judgement"
guidance): Sections 4.2 and 4.4 describe duplicate record ids and low manifest
coverage as "exit code 2" hard failures, while Section 5.5 lists the identical
two conditions as safety gates 3 and 4 (exit code 5, tied to session-cancel
behavior with --force interaction). This module does NOT raise or exit for
either condition — it only computes and exposes the numbers
(CoverageSummary.duplicate_ids, .coverage_pct) so that a single
enforcement point (safety.py, Phase 6) can apply the Section 5.5 gate
mechanism consistently. Treat Section 5.5 as authoritative for these two
checks; the exit-2 language in 4.2/4.4 appears to be an earlier, looser
description of the same gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Sequence

from nessus_drata.config import CheckEntry
from nessus_drata.models import HostKeyCandidates, HostResult

_SLUG_RE = re.compile(r"[^a-z0-9]+")


class TransformError(Exception):
    """Raised only for input malformed enough that no record can be built at
    all (a host with no netbios-name, host-fqdn, or host-ip whatsoever).
    Maps to exit code 2 — this is not a safety gate, it's unusable data.
    """


@dataclass(frozen=True)
class CoverageSummary:
    host_count: int
    checks_in_manifest: int
    manifest_misses: int
    manifest_ambiguous: int
    identity_fallbacks: int
    duplicate_ids: tuple[str, ...]
    coverage_pct: float


@dataclass(frozen=True)
class TransformResult:
    records: tuple[dict, ...]
    summary: CoverageSummary


def _slug(value: str) -> str:
    """Section 4.4: lowercase, replace any run of non [a-z0-9] with '-',
    strip leading/trailing '-'."""
    return _SLUG_RE.sub("-", value.lower()).strip("-")


def _resolve_host_key(candidates: HostKeyCandidates) -> tuple[str, bool]:
    """Section 4.4 fallback chain. Returns (host_key, used_ip_fallback).
    used_ip_fallback drives the identity_fallbacks counter — spec is explicit
    that ONLY the ip tier counts ("When id falls back to IP, increment
    identity_fallbacks"), not the netbios->fqdn tier.
    """
    if candidates.netbios_name:
        return candidates.netbios_name.upper(), False
    if candidates.host_fqdn:
        first_label = candidates.host_fqdn.lower().split(".")[0]
        return first_label.upper(), False
    if candidates.host_ip:
        return candidates.host_ip, True
    raise TransformError(
        "host has no identity candidates: missing netbios-name, host-fqdn, and host-ip"
    )


def _match_check(check: CheckEntry, items) -> list:
    if check.match_type == "check_name_exact":
        return [i for i in items if i.check_name == check.match_value]
    if check.match_type == "check_name_prefix":
        return [i for i in items if i.check_name.startswith(check.match_value)]
    if check.match_type == "check_name_contains":
        return [i for i in items if check.match_value in i.check_name]
    raise TransformError(f"unknown match_type {check.match_type!r}")  # pragma: no cover


def transform_host_results(
    host_results: Sequence[HostResult],
    checks: Sequence[CheckEntry],
    *,
    record_id_prefix: str,
    scan_id: int,
    scan_name: str,
    scan_ended_at: str,
    collected_at: str,
    audit_file: Optional[str] = None,
) -> TransformResult:
    """Apply the checks manifest to each host, resolve identity, compute
    rollups. See Sections 4.2, 4.4, 4.5 for the exact rules encoded here.
    """
    records: list[dict] = []
    manifest_misses = 0
    manifest_ambiguous = 0
    identity_fallbacks = 0

    for host in host_results:
        host_key, used_ip_fallback = _resolve_host_key(host.host_key_candidates)
        if used_ip_fallback:
            identity_fallbacks += 1
        record_id = f"{record_id_prefix}-{_slug(host_key)}"

        # Field order below matches the spec Section 4.6 example exactly.
        # Rollup keys are reserved here with placeholder values and updated
        # in place after the checks loop below — updating a dict value never
        # changes its insertion-order position, so per-check fields (added
        # inside the loop) still land after these placeholders and before
        # nothing, i.e. last, matching the example's field order.
        record: dict = {
            "id": record_id,
            "hostname": host_key,
            "host_ip": host.host_properties.get("host-ip"),
            "host_fqdn": host.host_properties.get("host-fqdn"),
            "operating_system": host.host_properties.get("operating-system"),
            "scan_id": scan_id,
            "scan_name": scan_name,
            "scan_ended_at": scan_ended_at,
            "collected_at": collected_at,
            "audit_file": audit_file,
            "checks_evaluated": None,
            "checks_passed": None,
            "checks_failed": None,
            "checks_inconclusive": None,
            "failed_check_fields": None,
            "all_required_checks_passed": None,
            "source_fidelity": host.source_fidelity,
        }

        checks_passed = 0
        checks_failed = 0
        checks_inconclusive = 0
        failed_fields: list[str] = []
        all_required_passed = True

        for check in checks:
            matches = _match_check(check, host.compliance_items)
            if len(matches) == 0:
                value = "NOT_FOUND"
                manifest_misses += 1
            elif len(matches) == 1:
                value = matches[0].result
            else:
                value = "AMBIGUOUS"
                manifest_ambiguous += 1

            record[check.field] = value

            if value == "PASSED":
                checks_passed += 1
            elif value == "FAILED":
                checks_failed += 1
                failed_fields.append(check.field)
            else:
                checks_inconclusive += 1

            if check.required and value != "PASSED":
                all_required_passed = False

        record["checks_evaluated"] = len(checks)
        record["checks_passed"] = checks_passed
        record["checks_failed"] = checks_failed
        record["checks_inconclusive"] = checks_inconclusive
        record["failed_check_fields"] = ",".join(failed_fields)
        record["all_required_checks_passed"] = all_required_passed

        records.append(record)

    id_counts: dict[str, int] = {}
    for record in records:
        id_counts[record["id"]] = id_counts.get(record["id"], 0) + 1
    duplicate_ids = tuple(sorted(rid for rid, count in id_counts.items() if count > 1))

    host_count = len(records)
    checks_in_manifest = len(checks)
    total_attempts = host_count * checks_in_manifest
    coverage_pct = (
        100.0 * (total_attempts - manifest_misses) / total_attempts
        if total_attempts > 0
        else 100.0
    )

    summary = CoverageSummary(
        host_count=host_count,
        checks_in_manifest=checks_in_manifest,
        manifest_misses=manifest_misses,
        manifest_ambiguous=manifest_ambiguous,
        identity_fallbacks=identity_fallbacks,
        duplicate_ids=duplicate_ids,
        coverage_pct=coverage_pct,
    )
    return TransformResult(records=tuple(records), summary=summary)
