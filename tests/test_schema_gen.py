"""Acceptance test 9 (schema-generation half): gen-schema output structure,
plus a minimal structural validation of transform's own records against it.

Full dry-run payload validation happens in Phase 4 once `run --dry-run`
exists; this test proves schema_gen.py's contract now on already-available
transform output. No `jsonschema` dependency is added (Section 6.3 pins
exactly requests/lxml/PyYAML + pytest/responses for tests) — the type check
below is a deliberately minimal stand-in, not a general JSON Schema validator.
"""

from __future__ import annotations

from pathlib import Path

from nessus_drata.config import load_checks_manifest
from nessus_drata.parse_nessus_xml import parse_nessus_xml
from nessus_drata.schema_gen import generate_schema
from nessus_drata.transform import transform_host_results

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _type_matches(value, type_spec) -> bool:
    allowed = type_spec if isinstance(type_spec, list) else [type_spec]
    for t in allowed:
        if t == "null" and value is None:
            return True
        if t == "string" and isinstance(value, str):
            return True
        if t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if t == "boolean" and isinstance(value, bool):
            return True
    return False


def _validate_record(record: dict, schema: dict) -> list[str]:
    """Return a list of validation error strings (empty means valid)."""
    errors = []
    for prop, spec in schema["properties"].items():
        if prop not in record:
            errors.append(f"missing property: {prop}")
            continue
        if not _type_matches(record[prop], spec["type"]):
            errors.append(f"{prop}: value {record[prop]!r} does not match type {spec['type']}")
    return errors


def test_generate_schema_has_base_properties_and_dynamic_check_fields():
    checks = load_checks_manifest(FIXTURES_DIR / "checks_small.yaml")
    schema = generate_schema(checks)

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is True

    # displayNameKey ("hostname") must be a top-level property (spec 4.3/5.2).
    assert "hostname" in schema["properties"]
    assert schema["properties"]["hostname"] == {"type": "string"}

    for base_field in (
        "id",
        "host_ip",
        "scan_id",
        "scan_name",
        "scan_ended_at",
        "collected_at",
        "checks_evaluated",
        "checks_passed",
        "checks_failed",
        "checks_inconclusive",
        "failed_check_fields",
        "all_required_checks_passed",
        "source_fidelity",
    ):
        assert base_field in schema["properties"]

    # host_fqdn / operating_system / audit_file are nullable.
    assert schema["properties"]["host_fqdn"]["type"] == ["string", "null"]
    assert schema["properties"]["operating_system"]["type"] == ["string", "null"]
    assert schema["properties"]["audit_file"]["type"] == ["string", "null"]

    # Every manifest check becomes a string-typed dynamic property.
    for check in checks:
        assert schema["properties"][check.field] == {"type": "string"}


def test_transform_output_for_sample_small_validates_against_generated_schema():
    checks = load_checks_manifest(FIXTURES_DIR / "checks_small.yaml")
    schema = generate_schema(checks)
    hosts = list(parse_nessus_xml(FIXTURES_DIR / "sample_small.nessus"))
    result = transform_host_results(
        hosts,
        checks,
        record_id_prefix="nessus",
        scan_id=47,
        scan_name="CIS Workstation Audit",
        scan_ended_at="2026-08-18T04:15:00Z",
        collected_at="2026-08-18T11:00:03Z",
        audit_file="CIS_MS_Windows_11_Enterprise_v3.0.0_L1.audit",
    )

    assert len(result.records) == 3
    for record in result.records:
        errors = _validate_record(record, schema)
        assert errors == [], f"record {record['id']} failed schema validation: {errors}"
