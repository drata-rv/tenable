"""Acceptance tests 7 and 8: AMBIGUOUS match outcomes and the identity
fallback chain (spec Section 4.2 match-outcome table, Section 4.4 identity).
"""

from __future__ import annotations

from pathlib import Path

from nessus_drata.config import CheckEntry
from nessus_drata.parse_nessus_xml import parse_nessus_xml
from nessus_drata.transform import transform_host_results

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

    # AMBIGUOUS is inconclusive, not passed/failed, and forces the required
    # gate false per Section 4.5 ("any inconclusive value forces false").
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

    # Host 1: no netbios, has host-fqdn -> fqdn tier. First label of the
    # fqdn, uppercased. This tier does NOT increment identity_fallbacks
    # (spec 4.4 ties the counter specifically to the ip tier).
    assert fqdn_tier_record["hostname"] == "WKS-UNREGISTERED-55"
    assert fqdn_tier_record["id"] == "nessus-wks-unregistered-55"

    # Host 2: no netbios, no host-fqdn -> falls all the way to host-ip,
    # used as-is (no case transform for an IP). This IS the tier that
    # increments identity_fallbacks.
    assert ip_tier_record["hostname"] == "198.51.100.56"
    assert ip_tier_record["id"] == "nessus-198-51-100-56"

    assert result.summary.identity_fallbacks == 1
