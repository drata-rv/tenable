from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Optional, Sequence

from nessus_drata.config import CheckEntry
from nessus_drata.models import HostKeyCandidates, HostResult

_SLUG_RE = re.compile(r"[^a-z0-9]+")

_TYPOGRAPHY_MAP = str.maketrans(
    {
        "\u2018": "'",
        "\u2019": "'",
        "\u201a": "'",
        "\u201b": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u201e": '"',
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": "-",
        "\u2212": "-",
    }
)


class TransformError(Exception):
    pass


@dataclass(frozen=True)
class CoverageSummary:
    host_count: int
    checks_in_manifest: int
    manifest_misses: int
    manifest_ambiguous: int
    identity_fallbacks: int
    duplicate_ids: tuple[str, ...]
    coverage_pct: float
    missing_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class TransformResult:
    records: tuple[dict, ...]
    summary: CoverageSummary


def _slug(value: str) -> str:
    return _SLUG_RE.sub("-", value.lower()).strip("-")


def _resolve_host_key(candidates: HostKeyCandidates) -> tuple[str, bool]:
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


def normalize_check_name(name: str) -> str:
    folded = unicodedata.normalize("NFKC", name).translate(_TYPOGRAPHY_MAP)
    return " ".join(folded.split())


def match_check(check: CheckEntry, items) -> list:
    wanted = normalize_check_name(check.match_value)
    if check.match_type == "check_name_exact":
        return [i for i in items if normalize_check_name(i.check_name) == wanted]
    if check.match_type == "check_name_prefix":
        return [i for i in items if normalize_check_name(i.check_name).startswith(wanted)]
    if check.match_type == "check_name_contains":
        return [i for i in items if wanted in normalize_check_name(i.check_name)]
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
    records: list[dict] = []
    manifest_misses = 0
    manifest_ambiguous = 0
    identity_fallbacks = 0
    missing_fields: set[str] = set()

    for host in host_results:
        host_key, used_ip_fallback = _resolve_host_key(host.host_key_candidates)
        if used_ip_fallback:
            identity_fallbacks += 1
        host_key_slug = _slug(host_key)
        if not host_key_slug:
            raise TransformError(
                f"host_key {host_key!r} slugs to an empty string; cannot "
                f"build a stable record id"
            )
        record_id = f"{record_id_prefix}-{host_key_slug}"

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
            matches = match_check(check, host.compliance_items)
            if len(matches) == 0:
                value = "NOT_FOUND"
                manifest_misses += 1
                missing_fields.add(check.field)
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
        missing_fields=tuple(c.field for c in checks if c.field in missing_fields),
    )
    return TransformResult(records=tuple(records), summary=summary)
