from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ComplianceItem:
    check_name: str
    result: str
    actual_value: Optional[str]
    policy_value: Optional[str]
    audit_file: Optional[str]
    reference: Optional[str]


@dataclass(frozen=True)
class HostKeyCandidates:
    netbios_name: Optional[str]
    host_fqdn: Optional[str]
    host_ip: Optional[str]


@dataclass(frozen=True)
class HostResult:
    host_key_candidates: HostKeyCandidates
    host_properties: dict[str, str]
    compliance_items: tuple[ComplianceItem, ...]
    source_fidelity: str = "full"
