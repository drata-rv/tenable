from __future__ import annotations

from pathlib import Path

import pytest

from nessus_drata.config import CheckEntry
from nessus_drata.models import HostKeyCandidates, HostResult
from nessus_drata.parse_nessus_xml import parse_nessus_xml
from nessus_drata.transform import TransformError, transform_host_results

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_COMMON_KWARGS = dict(
    record_id_prefix="nessus",
    scan_id=1,
    scan_name="Test Scan",
    scan_ended_at="2026-08-18T00:00:00Z",
    collected_at="2026-08-18T00:05:00Z",
    audit_file="CIS_MS_Windows_11_Enterprise_v3.0.0_L1.audit",
)


def test_sample_ambiguous_yields_ambiguous_field_and_counter():
    hosts = list(parse_nessus_xml(FIXTURES_DIR / "sample_ambiguous.nessus"))
    checks = [
        CheckEntry(
            field="password_policy_min_length_14",
            label="Password Policy: Minimum password length is 14",
            match_type="check_name_exact",
            match_value="5.1 Ensure 'Password Policy: Minimum password length' is '14'",
            required=True,
        ),
        CheckEntry(
            field="cis_4_5_firewall_public_state",
            label="Windows Firewall public profile enabled",
            match_type="check_name_exact",
            match_value="4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'On'",
            required=True,
        ),
    ]

    result = transform_host_results(hosts, checks, **_COMMON_KWARGS)

    assert len(result.records) == 1
    record = result.records[0]
    assert record["password_policy_min_length_14"] == "AMBIGUOUS"
    assert record["cis_4_5_firewall_public_state"] == "PASSED"
    assert result.summary.manifest_ambiguous == 1
    assert result.summary.manifest_misses == 0

    assert record["checks_inconclusive"] == 1
    assert record["checks_passed"] == 1
    assert record["checks_failed"] == 0
    assert record["all_required_checks_passed"] is False


def test_sample_no_netbios_identity_fallback_chain_and_counter():
    hosts = list(parse_nessus_xml(FIXTURES_DIR / "sample_no_netbios.nessus"))
    checks = [
        CheckEntry(
            field="cis_4_5_firewall_public_state",
            label="Windows Firewall public profile enabled",
            match_type="check_name_exact",
            match_value="4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'On'",
            required=True,
        ),
    ]

    result = transform_host_results(hosts, checks, **_COMMON_KWARGS)

    assert len(result.records) == 2
    fqdn_tier_record, ip_tier_record = result.records

    assert fqdn_tier_record["hostname"] == "WKS-UNREGISTERED-55"
    assert fqdn_tier_record["id"] == "nessus-wks-unregistered-55"

    assert ip_tier_record["hostname"] == "198.51.100.56"
    assert ip_tier_record["id"] == "nessus-198-51-100-56"

    assert result.summary.identity_fallbacks == 1


def test_all_symbol_host_key_raises_instead_of_producing_empty_slug():
    host = HostResult(
        host_key_candidates=HostKeyCandidates(
            netbios_name="###", host_fqdn=None, host_ip=None
        ),
        host_properties={"host-ip": "203.0.113.200"},
        compliance_items=(),
        source_fidelity="full",
    )
    with pytest.raises(TransformError, match="slugs to an empty string"):
        transform_host_results([host], [], **_COMMON_KWARGS)
