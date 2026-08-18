"""Tests for the degraded CSV compliance parser (parse_nessus_csv.py).

Spec Section 3.8 / 10 (sample_compliance.csv fixture): CSV is the never-default
fallback path. These tests prove it stays visibly degraded -- IP-only identity,
null actual/policy values, exact Risk->result mapping, generic-label check-name
recovery from Description, and a single one-time warning per call.
"""

import logging
from pathlib import Path

import pytest

from nessus_drata.parse_nessus_csv import parse_nessus_csv

FIXTURE = Path(__file__).parent / "fixtures" / "sample_compliance.csv"


def _results_by_ip(path=FIXTURE):
    return {r.host_key_candidates.host_ip: r for r in parse_nessus_csv(path)}


def _items_by_check_name(host_result):
    return {item.check_name: item for item in host_result.compliance_items}


def test_groups_by_host_with_correct_item_counts():
    by_ip = _results_by_ip()

    assert set(by_ip) == {"203.0.113.10", "203.0.113.11"}
    assert len(by_ip["203.0.113.10"].compliance_items) == 4
    assert len(by_ip["203.0.113.11"].compliance_items) == 3


def test_every_host_result_is_degraded():
    for result in _results_by_ip().values():
        assert result.source_fidelity == "degraded"


def test_risk_to_result_mapping_exact():
    by_ip = _results_by_ip()
    host10 = _items_by_check_name(by_ip["203.0.113.10"])
    host11 = _items_by_check_name(by_ip["203.0.113.11"])

    # None -> PASSED
    assert (
        host10["4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'On'"].result
        == "PASSED"
    )
    # Medium -> WARNING
    assert (
        host10["2.3.1.1 Ensure 'Accounts: Guest account status' is 'Disabled'"].result
        == "WARNING"
    )
    # High -> FAILED
    assert (
        host10["18.9.47.5.1 Ensure 'Turn on PUA Protection' is set to 'Enabled'"].result
        == "FAILED"
    )
    # Unrecognized ("Critical") -> ERROR
    assert host10["EDR Agent Service Running"].result == "ERROR"

    # None -> PASSED (second host)
    assert host11["Defender Service Running"].result == "PASSED"
    # Medium -> WARNING (second host)
    assert (
        host11[
            "4.5 Ensure 'Windows Firewall: Private: Firewall state' is 'On'"
        ].result
        == "WARNING"
    )
    # Blank Risk -> ERROR
    assert (
        host11[
            "3.1.1 Ensure 'Minimum password length' is '14' or more characters"
        ].result
        == "ERROR"
    )


def test_actual_and_policy_values_and_audit_file_and_reference_always_none():
    for result in _results_by_ip().values():
        for item in result.compliance_items:
            assert item.actual_value is None
            assert item.policy_value is None
            assert item.audit_file is None
            assert item.reference is None


def test_generic_label_falls_back_to_description_first_line():
    by_ip = _results_by_ip()
    host10 = _items_by_check_name(by_ip["203.0.113.10"])
    host11 = _items_by_check_name(by_ip["203.0.113.11"])

    # Name column was the generic plugin label "Windows Compliance Checks" --
    # the derived check_name must come from Description's first line instead.
    assert "Windows Compliance Checks" not in host10
    assert (
        "18.9.47.5.1 Ensure 'Turn on PUA Protection' is set to 'Enabled'" in host10
    )

    # Name column was the generic plugin label "Policy Compliance".
    assert "Policy Compliance" not in host11
    assert (
        "3.1.1 Ensure 'Minimum password length' is '14' or more characters"
        in host11
    )


def test_non_generic_name_used_as_is():
    by_ip = _results_by_ip()
    host10 = _items_by_check_name(by_ip["203.0.113.10"])

    assert "EDR Agent Service Running" in host10
    assert (
        "4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'On'" in host10
    )


def test_host_identity_is_ip_only():
    for result in _results_by_ip().values():
        candidates = result.host_key_candidates
        assert candidates.host_ip is not None
        assert candidates.host_ip != ""
        assert candidates.netbios_name is None
        assert candidates.host_fqdn is None
        assert result.host_properties == {"host-ip": candidates.host_ip}


def test_bom_tolerant_decode_path_even_without_a_real_bom(tmp_path):
    # Belt-and-braces on top of the fixture's real BOM (verified separately):
    # opening any file with encoding="utf-8-sig" must not raise even when no
    # byte-level BOM is present, proving the decode path itself is BOM-safe.
    no_bom = tmp_path / "no_bom.csv"
    no_bom.write_text(
        "Host,Risk,Name,Description\n"
        "203.0.113.20,None,Some Check,Some description.\n",
        encoding="utf-8",
    )

    results = list(parse_nessus_csv(no_bom))

    assert len(results) == 1
    assert results[0].host_key_candidates.host_ip == "203.0.113.20"
    assert results[0].compliance_items[0].result == "PASSED"


def test_warning_logged_exactly_once_per_call(caplog):
    with caplog.at_level(logging.WARNING, logger="nessus_drata.parse_nessus_csv"):
        list(parse_nessus_csv(FIXTURE))

    degraded_warnings = [
        record
        for record in caplog.records
        if record.name == "nessus_drata.parse_nessus_csv"
        and record.levelno == logging.WARNING
    ]

    assert len(degraded_warnings) == 1
    message = degraded_warnings[0].getMessage()
    assert "degraded" in message.lower()
    assert "actual" in message.lower() or "policy" in message.lower()
