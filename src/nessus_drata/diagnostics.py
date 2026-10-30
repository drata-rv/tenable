"""Operator-facing explanation of how the checks manifest lines up with what a
Nessus export actually contains.

The manifest is the contract (spec 4.2); when the audited checks change
underneath it, the run must say WHICH manifest entries lost their match, what
the export contains instead, and which checks in the export nothing tracks.
`analyze_manifest` is pure; `log_diagnosis` only writes log lines. Nothing here
changes a record, a field name, or a gate outcome.
"""

from __future__ import annotations

import difflib
import logging
from dataclasses import dataclass
from typing import Sequence

from nessus_drata.config import CheckEntry
from nessus_drata.models import HostResult
from nessus_drata.transform import match_check, normalize_check_name

_MAX_LISTED_NAMES = 25
_MAX_CLOSEST = 3


@dataclass(frozen=True)
class ManifestGap:
    field: str
    rule: str
    value: str
    hosts_missing: int
    closest: tuple[str, ...]


@dataclass(frozen=True)
class ManifestDiagnosis:
    host_count: int
    item_count: int
    distinct_names: tuple[str, ...]
    gaps: tuple[ManifestGap, ...]
    unmapped_names: tuple[str, ...]


def analyze_manifest(
    checks: Sequence[CheckEntry], hosts: Sequence[HostResult]
) -> ManifestDiagnosis:
    first_seen: dict[str, str] = {}  # normalized name -> name as exported
    item_count = 0
    for host in hosts:
        for item in host.compliance_items:
            item_count += 1
            first_seen.setdefault(normalize_check_name(item.check_name), item.check_name)

    matched_norm: set[str] = set()
    gaps: list[ManifestGap] = []
    for check in checks:
        hosts_missing = 0
        for host in hosts:
            hits = match_check(check, host.compliance_items)
            if hits:
                matched_norm.update(normalize_check_name(h.check_name) for h in hits)
            else:
                hosts_missing += 1
        if hosts_missing:
            wanted = normalize_check_name(check.match_value)
            near = difflib.get_close_matches(
                wanted, list(first_seen), n=_MAX_CLOSEST, cutoff=0.3
            )
            gaps.append(
                ManifestGap(
                    field=check.field,
                    rule=check.match_type,
                    value=check.match_value,
                    hosts_missing=hosts_missing,
                    closest=tuple(first_seen[n] for n in near),
                )
            )

    return ManifestDiagnosis(
        host_count=len(hosts),
        item_count=item_count,
        distinct_names=tuple(first_seen.values()),
        gaps=tuple(gaps),
        unmapped_names=tuple(n for k, n in first_seen.items() if k not in matched_norm),
    )


def _listed(names: Sequence[str]) -> str:
    shown = [repr(n) for n in names[:_MAX_LISTED_NAMES]]
    extra = len(names) - len(shown)
    return "[" + ", ".join(shown) + (f", ... +{extra} more" if extra > 0 else "") + "]"


def log_diagnosis(logger: logging.Logger, diagnosis: ManifestDiagnosis) -> None:
    logger.info(
        "export contents: %d host(s), %d compliance item(s), %d distinct check name(s)",
        diagnosis.host_count,
        diagnosis.item_count,
        len(diagnosis.distinct_names),
    )
    if diagnosis.host_count == 0:
        logger.warning(
            "export contains no ReportHost elements: the scan result has no hosts "
            "(wrong scan or history entry, or no target was reachable)"
        )
    elif diagnosis.item_count == 0:
        logger.warning(
            "export has %d host(s) but ZERO compliance items: the audit did not run "
            "or its credentialed login failed on this result",
            diagnosis.host_count,
        )

    for gap in diagnosis.gaps:
        closest = _listed(gap.closest) if gap.closest else "none similar"
        logger.warning(
            "manifest field %s (%s=%r): no match on %d of %d host(s). "
            "Closest check names in the export: %s",
            gap.field,
            gap.rule,
            gap.value,
            gap.hosts_missing,
            diagnosis.host_count,
            closest,
        )

    if diagnosis.unmapped_names:
        logger.info(
            "%d check name(s) in the export are not tracked by the manifest and are "
            "ignored (add an entry to checks.yaml to track one): %s",
            len(diagnosis.unmapped_names),
            _listed(diagnosis.unmapped_names),
        )
