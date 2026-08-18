"""Basic correctness for report.py: the run report is written and read back
faithfully, and the console summary doesn't crash on a representative report.
"""

from __future__ import annotations

import json

from nessus_drata.report import RunReport, print_console_summary, write_report


def _sample_report(**overrides) -> RunReport:
    kwargs = dict(
        run_id="20260818T110003Z",
        started_at="2026-08-18T11:00:00Z",
        finished_at="2026-08-18T11:00:03Z",
        parse_mode="xml_full",
        scan_id=47,
        scan_name="CIS Workstation Audit",
        scan_ended_at="2026-08-18T04:15:00Z",
        host_count=3,
        record_count=3,
        checks_in_manifest=4,
        manifest_coverage_pct=100.0,
        manifest_misses=0,
        manifest_ambiguous=0,
        identity_fallbacks=0,
        duplicate_ids=(),
        batches_sent=0,
        records_created=0,
        records_updated=0,
        session_id=None,
        session_action=None,
        safety_gates=(
            {"name": "min_hosts", "passed": True, "reason": "3 >= 3"},
        ),
        exit_code=0,
    )
    kwargs.update(overrides)
    return RunReport(**kwargs)


def test_write_report_round_trips_as_json(tmp_path):
    report = _sample_report()
    path = write_report(tmp_path / "reports", report)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["run_id"] == "20260818T110003Z"
    assert data["exit_code"] == 0
    assert data["safety_gates"][0]["name"] == "min_hosts"


def test_print_console_summary_does_not_raise(capsys):
    report = _sample_report(
        session_id="nessus-47-20260818T041500Z",
        session_action="complete",
        batches_sent=1,
        records_created=3,
        exit_code=0,
    )
    print_console_summary(report)
    captured = capsys.readouterr()
    assert "run_id=20260818T110003Z" in captured.out
    assert "gate[min_hosts]: PASS" in captured.out
    assert "session_id=nessus-47-20260818T041500Z" in captured.out
