"""Shared data shapes produced by both parsers (XML primary, CSV degraded fallback)
and consumed by transform.py. Owned by the lead agent — both parser modules import
from here rather than defining their own competing shapes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ComplianceItem:
    """One <ReportItem> compliance result. Fields consumed by this MVP per spec
    Section 3.6: check-name, result, actual-value, policy-value, audit-file,
    reference. compliance-info, compliance-solution, and compliance-check-id are
    deliberately not captured — remediation prose and plugin-internal IDs are not
    evidence.
    """

    check_name: str
    result: str  # raw compliance-result text: PASSED | FAILED | WARNING | ERROR
    actual_value: Optional[str]
    policy_value: Optional[str]
    audit_file: Optional[str]
    reference: Optional[str]


@dataclass(frozen=True)
class HostKeyCandidates:
    """The three identity inputs used by transform.py's Section 4.4 fallback
    chain: netbios-name, then host-fqdn, then host-ip. Values are raw/unnormalized
    as read from XML or CSV — transform.py owns uppercasing/slugging.
    """

    netbios_name: Optional[str]
    host_fqdn: Optional[str]
    host_ip: Optional[str]


@dataclass(frozen=True)
class HostResult:
    """One host's parsed compliance results, regardless of source format.

    host_properties holds every raw HostProperties <tag name="..."> value keyed
    by its bare tag name (e.g. "operating-system", "HOST_END_TIMESTAMP") for the
    XML path. The CSV path only ever populates the identity-relevant keys it can
    read from the export (see parse_nessus_csv.py for the exact column contract)
    and leaves the rest absent — never guess a value CSV cannot provide.
    """

    host_key_candidates: HostKeyCandidates
    host_properties: dict[str, str]
    compliance_items: tuple[ComplianceItem, ...]
    source_fidelity: str = "full"  # "full" | "degraded"
