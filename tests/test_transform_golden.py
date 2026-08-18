"""Acceptance test 6: transform output for sample_small.nessus must be
byte-identical to tests/golden/sample_small.records.json.

If this test fails, that is a signal about transform.py, not about the
golden file — never regenerate the golden file to make a failing test pass.
A deliberate, called-out transform change gets a deliberate, called-out
golden-file update; see CLAUDE.md.
"""

from __future__ import annotations

import json
from pathlib import Path

from nessus_drata.config import load_checks_manifest
from nessus_drata.parse_nessus_xml import parse_nessus_xml
from nessus_drata.transform import transform_host_results

FIXTURES_DIR = Path(__file__).parent / "fixtures"
GOLDEN_DIR = Path(__file__).parent / "golden"

# Fixed, arbitrary-but-documented scan-level parameters. Not read from any
# live source — transform.py is pure, so these are supplied by the caller
# exactly as a later-phase Nessus API client would supply them from a real
# scan's history/detail response.
_SCAN_ID = 47
_SCAN_NAME = "CIS Workstation Audit"
_SCAN_ENDED_AT = "2026-08-18T04:15:00Z"
_COLLECTED_AT = "2026-08-18T11:00:03Z"
_AUDIT_FILE = "CIS_MS_Windows_11_Enterprise_v3.0.0_L1.audit"
_RECORD_ID_PREFIX = "nessus"


def _build_records():
    hosts = list(parse_nessus_xml(FIXTURES_DIR / "sample_small.nessus"))
    checks = load_checks_manifest(FIXTURES_DIR / "checks_small.yaml")
    result = transform_host_results(
        hosts,
        checks,
        record_id_prefix=_RECORD_ID_PREFIX,
        scan_id=_SCAN_ID,
        scan_name=_SCAN_NAME,
        scan_ended_at=_SCAN_ENDED_AT,
        collected_at=_COLLECTED_AT,
        audit_file=_AUDIT_FILE,
    )
    return result


def test_transform_sample_small_matches_golden_file_byte_identical():
    result = _build_records()
    actual_json = json.dumps(list(result.records), indent=2) + "\n"
    golden_json = (GOLDEN_DIR / "sample_small.records.json").read_text()
    assert actual_json == golden_json


def test_transform_sample_small_summary_has_full_coverage_no_anomalies():
    result = _build_records()
    summary = result.summary
    assert summary.host_count == 3
    assert summary.checks_in_manifest == 4
    assert summary.manifest_misses == 0
    assert summary.manifest_ambiguous == 0
    assert summary.identity_fallbacks == 0
    assert summary.duplicate_ids == ()
    assert summary.coverage_pct == 100.0
