from __future__ import annotations

from typing import Sequence

from nessus_drata.config import CheckEntry

_BASE_PROPERTIES = {
    "id": {"type": "string"},
    "hostname": {"type": "string"},
    "host_ip": {"type": "string"},
    "host_fqdn": {"type": ["string", "null"]},
    "operating_system": {"type": ["string", "null"]},
    "scan_id": {"type": "number"},
    "scan_name": {"type": "string"},
    "scan_ended_at": {"type": "string"},
    "collected_at": {"type": "string"},
    "audit_file": {"type": ["string", "null"]},
    "checks_evaluated": {"type": "number"},
    "checks_passed": {"type": "number"},
    "checks_failed": {"type": "number"},
    "checks_inconclusive": {"type": "number"},
    "failed_check_fields": {"type": "string"},
    "all_required_checks_passed": {"type": "boolean"},
    "source_fidelity": {"type": "string"},
}


def generate_schema(checks: Sequence[CheckEntry]) -> dict:
    properties = dict(_BASE_PROPERTIES)
    for check in checks:
        properties[check.field] = {"type": "string"}
    return {
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }
