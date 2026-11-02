from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Iterator, Union

from nessus_drata.models import ComplianceItem, HostKeyCandidates, HostResult

logger = logging.getLogger(__name__)

_RISK_TO_RESULT = {
    "none": "PASSED",
    "medium": "WARNING",
    "high": "FAILED",
}

_GENERIC_NAME_LABELS = {
    "windows compliance checks",
    "unix compliance checks",
    "policy compliance",
}

_DEGRADED_WARNING = (
    "CSV compliance parser (parse_nessus_csv) in use: this is the degraded "
    "fallback path. Results carry no compliance-actual-value or "
    "compliance-policy-value (both are always null), and host identity is "
    "IP-only. Do not treat this dataset as authoritative; session "
    "completion from CSV-parsed data requires --allow-degraded-session."
)


def _derive_check_name(name: str, description: str) -> str:
    if name.lower() in _GENERIC_NAME_LABELS:
        lines = description.splitlines()
        return lines[0].strip() if lines else description.strip()
    return name


def _map_risk(risk: str) -> str:
    return _RISK_TO_RESULT.get(risk.strip().lower(), "ERROR")


def parse_nessus_csv(path: Union[str, Path]) -> Iterator[HostResult]:
    path = Path(path)
    logger.warning(_DEGRADED_WARNING)

    hosts: dict[str, list[ComplianceItem]] = {}

    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            host = (row.get("Host") or "").strip()
            risk = row.get("Risk") or ""
            name = (row.get("Name") or "").strip()
            description = row.get("Description") or ""

            item = ComplianceItem(
                check_name=_derive_check_name(name, description),
                result=_map_risk(risk),
                actual_value=None,
                policy_value=None,
                audit_file=None,
                reference=None,
            )
            hosts.setdefault(host, []).append(item)

    for host, items in hosts.items():
        yield HostResult(
            host_key_candidates=HostKeyCandidates(
                netbios_name=None,
                host_fqdn=None,
                host_ip=host,
            ),
            host_properties={"host-ip": host},
            compliance_items=tuple(items),
            source_fidelity="degraded",
        )
