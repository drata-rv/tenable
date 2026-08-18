"""Generate the Drata Custom Connection JSON schema from the checks manifest
(spec Section 4.3). Pure function, no I/O — cli.py's gen-schema command owns
writing the result to artifacts/schema.json.
"""

from __future__ import annotations

from typing import Sequence

from nessus_drata.config import CheckEntry

# Fixed base properties, verbatim from spec Section 4.3. Every dynamic check
# field added below is typed "string" to match the section's own example
# (compliance results are always emitted as one of PASSED/FAILED/WARNING/
# ERROR/NOT_FOUND/AMBIGUOUS text, never a number or boolean).
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
    """additionalProperties stays true (spec 4.3): adding a check to the
    manifest is then an additive change existing records tolerate, with no
    connection rebuild required.
    """
    properties = dict(_BASE_PROPERTIES)
    for check in checks:
        properties[check.field] = {"type": "string"}
    return {
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }
