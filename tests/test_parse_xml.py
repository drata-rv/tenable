"""Acceptance tests for the primary .nessus XML parser (spec Section 12,
tests 4 and 5, plus the fixture-proving tests implied by Section 10).

Scope note: this module tests parse_nessus_xml.py only. No golden-file /
transform assertions and no rollup counts (checks_evaluated, etc.) belong
here — those are transform.py's contract in a later phase.
"""

from __future__ import annotations

from pathlib import Path

from nessus_drata.parse_nessus_xml import local_name, parse_nessus_xml

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_local_name_strips_clark_notation_uri():
    assert local_name("{http://example.test/cm}compliance-check-name") == "compliance-check-name"


def test_local_name_strips_undeclared_prefix():
    assert local_name("cm:compliance-check-name") == "compliance-check-name"


def test_local_name_passes_through_bare_name():
    assert local_name("ReportHost") == "ReportHost"


def test_sample_small_yields_three_hosts_with_mixed_results():
    results = list(parse_nessus_xml(FIXTURES_DIR / "sample_small.nessus"))
    assert len(results) == 3

    all_results = [
        item.result
        for host in results
        for item in host.compliance_items
    ]
    assert "PASSED" in all_results
    assert "FAILED" in all_results
    assert "WARNING" in all_results

    # Every host in this fixture carries a netbios-name.
    for host in results:
        assert host.host_key_candidates.netbios_name is not None
        assert host.source_fidelity == "full"

    # Continuity check: the spec's own example check name is present.
    check_names = {item.check_name for host in results for item in host.compliance_items}
    assert "4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'On'" in check_names


def test_sample_undeclared_ns_parses_without_exception():
    results = list(parse_nessus_xml(FIXTURES_DIR / "sample_undeclared_ns.nessus"))
    assert len(results) == 1

    host = results[0]
    assert len(host.compliance_items) == 2
    check_names = {item.check_name for item in host.compliance_items}
    assert "4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'On'" in check_names
    assert "18.9.47.5.1 Ensure 'Turn off Windows Defender' is 'Disabled'" in check_names

    # Fields beyond the six consumed by the MVP must not leak onto the
    # ComplianceItem shape (compliance-check-id, -info, -solution excluded).
    firewall_item = next(
        item for item in host.compliance_items
        if item.check_name.startswith("4.5 Ensure 'Windows Firewall: Public")
    )
    assert not hasattr(firewall_item, "check_id")
    assert not hasattr(firewall_item, "info")
    assert not hasattr(firewall_item, "solution")
    assert firewall_item.result == "PASSED"
    assert firewall_item.actual_value == "On"
    assert firewall_item.policy_value == "On"
    assert firewall_item.audit_file == "CIS_MS_Windows_11_Enterprise_v3.0.0_L1.audit"
    assert firewall_item.reference == "800-53|SC-7,CSCv8|4.5,LEVEL|1S"


def test_sample_with_vulns_excludes_vulnerability_report_items():
    results = list(parse_nessus_xml(FIXTURES_DIR / "sample_with_vulns.nessus"))
    assert len(results) == 1

    host = results[0]
    # Fixture authored 2 vuln ReportItems + 2 compliance ReportItems.
    assert len(host.compliance_items) == 2

    check_names = {item.check_name for item in host.compliance_items}
    assert "4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'On'" in check_names
    assert "2.3.1.1 Ensure 'Accounts: Administrator account status' is 'Disabled'" in check_names

    # None of the vulnerability plugin names/synopses leaked in as a check_name.
    for item in host.compliance_items:
        assert "TLS Library" not in item.check_name
        assert "Patch Missing" not in item.check_name


def test_sample_ambiguous_yields_two_items_same_check_name():
    results = list(parse_nessus_xml(FIXTURES_DIR / "sample_ambiguous.nessus"))
    assert len(results) == 1

    host = results[0]
    target_name = "5.1 Ensure 'Password Policy: Minimum password length' is '14'"
    matching = [item for item in host.compliance_items if item.check_name == target_name]
    assert len(matching) == 2

    # Not deduped: the two results are surfaced as authored (conflicting).
    results_seen = {item.result for item in matching}
    assert results_seen == {"FAILED", "PASSED"}

    # The unambiguous check on the same host is also present, untouched.
    assert len(host.compliance_items) == 3


def test_sample_no_netbios_identity_fallback_candidates():
    results = list(parse_nessus_xml(FIXTURES_DIR / "sample_no_netbios.nessus"))
    assert len(results) == 1

    host = results[0]
    candidates = host.host_key_candidates
    assert candidates.netbios_name is None
    assert candidates.host_fqdn == "wks-unregistered-55.example.internal"
    assert candidates.host_ip == "198.51.100.55"
