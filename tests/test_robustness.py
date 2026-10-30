"""The collector must survive the scan changing underneath the manifest and
must say what changed: tolerant check-name matching, fail-closed on damaged
exports, and diagnostics that name the manifest entries that lost their match.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

import pytest

from nessus_drata.config import CheckEntry
from nessus_drata.diagnostics import analyze_manifest, log_diagnosis
from nessus_drata.models import ComplianceItem, HostKeyCandidates, HostResult
from nessus_drata.parse_nessus_xml import ExportParseError, parse_nessus_xml
from nessus_drata.transform import normalize_check_name, transform_host_results

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"


def _item(name: str, result: str = "PASSED") -> ComplianceItem:
    return ComplianceItem(name, result, None, None, None, None)


def _host(*names: str) -> HostResult:
    return HostResult(
        host_key_candidates=HostKeyCandidates("WKS-1", None, "10.0.0.1"),
        host_properties={"host-ip": "10.0.0.1"},
        compliance_items=tuple(_item(n) for n in names),
    )


def _transform(hosts, checks):
    return transform_host_results(
        hosts,
        checks,
        record_id_prefix="nessus",
        scan_id=1,
        scan_name="s",
        scan_ended_at="2026-01-01T00:00:00Z",
        collected_at="2026-01-01T00:00:01Z",
    )


def _check(field, match_type, value, required=True):
    return CheckEntry(field=field, label=field, match_type=match_type, match_value=value, required=required)


# --- matching survives cosmetic edits to the audit -------------------------


@pytest.mark.parametrize(
    "exported",
    [
        "4.9 Ensure ‘DNS’ is set",  # curly quotes
        "4.9  Ensure 'DNS'   is set",  # doubled spaces
        "4.9 Ensure 'DNS' is set",  # non-breaking space
        " 4.9 Ensure 'DNS' is set\n",  # surrounding whitespace
    ],
)
def test_exact_match_ignores_whitespace_and_quote_style(exported):
    checks = [_check("dns", "check_name_exact", "4.9 Ensure 'DNS' is set")]
    rec = _transform([_host(exported)], checks).records[0]
    assert rec["dns"] == "PASSED"


def test_matching_is_still_case_sensitive_and_never_fuzzy():
    checks = [_check("dns", "check_name_exact", "4.9 Ensure 'DNS' is set")]
    assert _transform([_host("4.9 ensure 'dns' is set")], checks).records[0]["dns"] == "NOT_FOUND"
    assert _transform([_host("4.9 Ensure 'DNS' is set now")], checks).records[0]["dns"] == "NOT_FOUND"


def test_normalize_check_name_is_idempotent():
    once = normalize_check_name("a’b –  c")
    assert once == "a'b - c"
    assert normalize_check_name(once) == once


def test_added_checks_in_the_scan_do_not_disturb_existing_manifest_entries():
    checks = [_check("dns", "check_name_exact", "4.9 DNS")]
    before = _transform([_host("4.9 DNS")], checks)
    after = _transform([_host("1.1 other", "4.9 DNS", "1.2 other", "7.1 more")], checks)
    assert before.records[0]["dns"] == after.records[0]["dns"] == "PASSED"
    assert after.summary.manifest_misses == 0
    assert after.summary.missing_fields == ()


def test_summary_names_missing_fields_in_manifest_order():
    checks = [
        _check("a_check", "check_name_exact", "A"),
        _check("b_check", "check_name_exact", "B"),
        _check("c_check", "check_name_exact", "C"),
    ]
    result = _transform([_host("B")], checks)
    assert result.summary.missing_fields == ("a_check", "c_check")
    assert result.summary.manifest_misses == 2


# --- diagnostics explain a broken contract ----------------------------------


def test_diagnosis_offers_closest_names_and_lists_untracked_checks():
    checks = [_check("dns", "check_name_exact", "4.9 Ensure 'Configure DNS' is set")]
    hosts = [_host("4.9 Ensure 'Configure Trusted DNS' is set", "1.1.1 Unrelated check")]
    diag = analyze_manifest(checks, hosts)
    assert diag.host_count == 1 and diag.item_count == 2
    (gap,) = diag.gaps
    assert gap.field == "dns" and gap.hosts_missing == 1
    assert gap.closest[0] == "4.9 Ensure 'Configure Trusted DNS' is set"
    assert set(diag.unmapped_names) == {
        "4.9 Ensure 'Configure Trusted DNS' is set",
        "1.1.1 Unrelated check",
    }


def test_diagnosis_has_no_gaps_when_manifest_matches_and_lists_extras_only():
    checks = [_check("dns", "check_name_exact", "4.9 DNS")]
    diag = analyze_manifest(checks, [_host("4.9 DNS", "5.1 extra")])
    assert diag.gaps == ()
    assert diag.unmapped_names == ("5.1 extra",)


def test_log_diagnosis_flags_hosts_with_zero_compliance_items(caplog):
    diag = analyze_manifest([_check("dns", "check_name_exact", "4.9 DNS")], [_host()])
    with caplog.at_level(logging.INFO, logger="t"):
        log_diagnosis(logging.getLogger("t"), diag)
    text = caplog.text
    assert "ZERO compliance items" in text
    assert "manifest field dns" in text


def test_log_diagnosis_flags_empty_export(caplog):
    diag = analyze_manifest([_check("dns", "check_name_exact", "4.9 DNS")], [])
    with caplog.at_level(logging.INFO, logger="t"):
        log_diagnosis(logging.getLogger("t"), diag)
    assert "no ReportHost" in caplog.text


def test_log_diagnosis_caps_long_name_lists(caplog):
    names = [f"{i}.0 check number {i}" for i in range(60)]
    diag = analyze_manifest([_check("dns", "check_name_exact", names[0])], [_host(*names)])
    with caplog.at_level(logging.INFO, logger="t"):
        log_diagnosis(logging.getLogger("t"), diag)
    assert "+34 more" in caplog.text  # 59 untracked, 25 shown


# --- the parser refuses damaged exports instead of returning partial data ---

_HEAD = (
    b'<?xml version="1.0"?><NessusClientData_v2><Report name="r"><ReportHost name="h">'
    b'<HostProperties><tag name="netbios-name">WKS-1</tag></HostProperties>'
)
_TAIL = b"</ReportHost></Report></NessusClientData_v2>"


def _ri(name: bytes, actual: bytes = b"On") -> bytes:
    return (
        b'<ReportItem pluginID="21156"><compliance>true</compliance>'
        b"<cm:compliance-check-name>" + name + b"</cm:compliance-check-name>"
        b"<cm:compliance-result>PASSED</cm:compliance-result>"
        b"<cm:compliance-actual-value>" + actual + b"</cm:compliance-actual-value></ReportItem>"
    )


def _write(tmp_path, data: bytes) -> Path:
    p = tmp_path / "x.nessus"
    p.write_bytes(data)
    return p


def test_truncated_export_raises_instead_of_returning_partial_hosts(tmp_path):
    full = _HEAD + _ri(b"A") + _ri(b"B") + _TAIL
    path = _write(tmp_path, full[: full.index(b"B") + 3])
    with pytest.raises(ExportParseError, match="truncated"):
        list(parse_nessus_xml(path))


def test_empty_file_raises(tmp_path):
    with pytest.raises(ExportParseError):
        list(parse_nessus_xml(_write(tmp_path, b"")))


def test_html_error_body_raises(tmp_path):
    path = _write(tmp_path, b"<html><body>502 Bad Gateway</body></html>")
    with pytest.raises(ExportParseError, match="NessusClientData_v2"):
        list(parse_nessus_xml(path))


def test_stray_control_character_is_recovered_with_a_warning(tmp_path, caplog):
    path = _write(tmp_path, _HEAD + _ri(b"A", b"bad\x1bvalue") + _ri(b"B") + _TAIL)
    with caplog.at_level(logging.WARNING, logger="nessus_drata.parse"):
        hosts = list(parse_nessus_xml(path))
    assert [i.check_name for i in hosts[0].compliance_items] == ["A", "B"]
    assert "recovered while parsing" in caplog.text


@pytest.mark.parametrize("fixture", sorted(p.name for p in FIXTURES.glob("*.nessus")))
def test_healthy_fixtures_parse_without_warnings(fixture, caplog):
    with caplog.at_level(logging.WARNING, logger="nessus_drata.parse"):
        list(parse_nessus_xml(FIXTURES / fixture))
    assert caplog.text == ""


# --- end to end through the CLI --------------------------------------------


def _cli(args, cwd):
    return subprocess.run(
        [sys.executable, "-m", "nessus_drata.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _base_args(checks: Path, fixture: Path):
    return [
        "--config", str(FIXTURES / "config_offline.yaml"),
        "--checks", str(checks),
        "run", "--fixtures", str(fixture), "--dry-run",
    ]


def test_cli_truncated_export_exits_3_and_writes_nothing(tmp_path):
    raw = (FIXTURES / "sample_small.nessus").read_bytes()
    broken = tmp_path / "broken.nessus"
    broken.write_bytes(raw[: len(raw) // 2])
    result = _cli(_base_args(FIXTURES / "checks_small.yaml", broken), tmp_path)
    assert result.returncode == 3, result.stderr
    assert "truncated" in result.stderr
    assert not (tmp_path / "artifacts" / "payloads").exists()


def test_cli_manifest_mismatch_reports_missing_fields_and_closest_names(tmp_path):
    checks = tmp_path / "checks.yaml"
    checks.write_text(
        "schema_version: 1\n"
        "checks:\n"
        "  - field: firewall_public\n"
        "    label: x\n"
        "    match:\n"
        "      check_name_exact: \"4.5 Ensure 'Windows Firewall: Public: Firewall state' is 'Off'\"\n"
        "    required: true\n"
    )
    result = _cli(_base_args(checks, FIXTURES / "sample_small.nessus"), tmp_path)
    assert result.returncode == 0, result.stderr  # dry-run is report-only
    assert "manifest_missing_fields=firewall_public" in result.stdout
    log = (tmp_path / "logs" / "collector.log").read_text()
    assert "manifest field firewall_public" in log
    assert "Closest check names in the export" in log
    assert "Windows Firewall: Public: Firewall state" in log
