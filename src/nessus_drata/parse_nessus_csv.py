"""Degraded fallback parser for Tenable Nessus CSV compliance exports.

Retained per spec Section 3.8 because an engineer already has a CSV export
saved from a CIS check and wants an offline smoke test. This path is NEVER
the default and must never be as trustworthy as the primary `.nessus` XML
parser (parse_nessus_xml.py):

* CSV collapses the structured compliance result into a bare `Risk` column
  and loses `compliance-actual-value` / `compliance-policy-value` entirely.
* Every HostResult yielded here is stamped `source_fidelity="degraded"`.
* A warning is logged once per call so degraded mode never passes silently.

Callers (transform.py, safety.py) key off `source_fidelity` to refuse
session completion from this data unless `--allow-degraded-session` is
passed explicitly (spec Section 3.8 / 5.5 gate 5).
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Iterator, Union

from nessus_drata.models import ComplianceItem, HostKeyCandidates, HostResult

logger = logging.getLogger(__name__)

# Exact table from spec Section 3.8. Case-insensitive match on the Risk
# column value. Any value not present here -- including blank/unknown -- is
# ERROR, never silently folded into PASSED or FAILED.
_RISK_TO_RESULT = {
    "none": "PASSED",
    "medium": "WARNING",
    "high": "FAILED",
}

# Generic Nessus plugin/family labels that appear verbatim in the CSV `Name`
# column for every compliance row of that plugin type (mirrors the
# pluginName/pluginFamily attributes on <ReportItem> in the spec's XML
# example, e.g. pluginName="Windows Compliance Checks",
# pluginFamily="Policy Compliance"). When `Name` is one of these, it carries
# no per-check information, so the actual check text is recovered from the
# leading line of `Description` instead.
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
    """Section 3.8: derive check_name from `Name`, unless `Name` is a
    generic plugin-level label, in which case fall back to the leading
    line of `Description`.
    """
    if name.lower() in _GENERIC_NAME_LABELS:
        lines = description.splitlines()
        return lines[0].strip() if lines else description.strip()
    return name


def _map_risk(risk: str) -> str:
    """Section 3.8 Risk -> compliance-result table, case-insensitive.
    Anything not in the table -- including empty string -- is ERROR.
    """
    return _RISK_TO_RESULT.get(risk.strip().lower(), "ERROR")


def parse_nessus_csv(path: Union[str, Path]) -> Iterator[HostResult]:
    """Parse a degraded Tenable Nessus CSV compliance export into HostResults.

    Grain: one HostResult per distinct `Host` column value (a Nessus CSV
    compliance export's host identifier, standardly the scanned host's IP),
    one ComplianceItem per row. CSV cannot distinguish netbios-name / fqdn /
    ip, so identity always lands in the lowest-priority host-ip bucket of
    the Section 4.4 fallback chain -- degraded parsing gets degraded
    identity confidence too.

    Zero I/O side effects beyond reading `path`. Tolerates a UTF-8 BOM.
    Always yields `source_fidelity="degraded"` HostResults and always logs
    a one-time warning that this is the degraded path.
    """
    path = Path(path)
    logger.warning(_DEGRADED_WARNING)

    # host -> list[ComplianceItem], insertion order preserved (dict, py3.7+)
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
