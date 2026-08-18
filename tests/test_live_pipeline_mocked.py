"""End-to-end pipeline test with BOTH Nessus and Drata HTTP calls mocked via
`responses`, run in-process (not subprocess, so `responses` can intercept).

This is NOT a substitute for acceptance tests 20-24, which require a real
Nessus console and a real Drata sandbox connection and remain pending
operator execution — nothing here proves the real APIs behave as documented.
What this DOES prove, fully offline: the orchestration wiring in cli.py
(_live_nessus_export, _live_drata_push, _resolve_scan_id, session id
construction, safety-gate sequencing, complete-vs-cancel branching, and
state persistence) is internally consistent and calls each client method
with the right arguments in the right order.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import responses

from nessus_drata import cli
from nessus_drata.state import load_last_run_state

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_SMALL = REPO_ROOT / "tests" / "fixtures" / "sample_small.nessus"
SAMPLE_CSV = REPO_ROOT / "tests" / "fixtures" / "sample_compliance.csv"
CHECKS = REPO_ROOT / "tests" / "fixtures" / "checks_small.yaml"

NESSUS_BASE = "https://nessus.test:8834"
DRATA_BASE = "https://drata.test"


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
nessus:
  base_url: "{NESSUS_BASE}"
  verify_tls: true
  ca_bundle: null
  scan_id: 47
  scan_name_exact: null
  use_latest_history: true
  export_format: "nessus"
  export_timeout_seconds: 60
  connect_timeout_seconds: 10
  read_timeout_seconds: 30

drata:
  base_url: "{DRATA_BASE}"
  connection_id: 99
  resource_id: 5
  use_sessions: true
  batch_size: 25
  max_retries: 3
  record_id_prefix: "nessus"

safety:
  min_hosts: 1
  max_shrink_ratio: 0.8
  min_manifest_coverage_pct: 90

runtime:
  artifacts_dir: "artifacts"
  state_dir: "state"
  log_dir: "logs"
  keep_raw_exports_days: 30
  keep_payloads_days: 14
"""
    )
    return config_path


def _register_nessus_mocks(rsps: responses.RequestsMock, download_body: bytes = None) -> None:
    rsps.add(
        responses.GET,
        f"{NESSUS_BASE}/scans/47",
        json={
            "info": {"name": "CIS Workstation Audit", "status": "completed"},
            "history": [
                {
                    "history_id": 555,
                    "status": "completed",
                    "last_modification_date": 1755500000,
                }
            ],
        },
        status=200,
    )
    rsps.add(
        responses.POST,
        f"{NESSUS_BASE}/scans/47/export",
        json={"file": 1, "token": "tok-abc"},
        status=200,
    )
    rsps.add(
        responses.GET,
        f"{NESSUS_BASE}/scans/47/export/1/status",
        json={"status": "ready"},
        status=200,
    )
    rsps.add(
        responses.GET,
        f"{NESSUS_BASE}/scans/47/export/1/download",
        body=download_body if download_body is not None else SAMPLE_SMALL.read_bytes(),
        status=200,
        content_type="application/octet-stream",
    )


def _register_drata_mocks(rsps: responses.RequestsMock, session_action_capture: list) -> None:
    rsps.add(
        responses.GET,
        f"{DRATA_BASE}/public/v2/custom-connections/99/resources/5/sessions",
        json=[],
        status=200,
    )

    # Session id depends on a computed timestamp, so match by regex instead
    # of a literal URL.
    import re

    session_batch_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+$"
    )
    session_action_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+/actions$"
    )

    def batch_callback(request):
        return (200, {}, json.dumps({"data": []}))

    def action_callback(request):
        body = json.loads(request.body)
        session_action_capture.append(body.get("action"))
        return (200, {}, json.dumps({}))

    rsps.add_callback(responses.POST, session_batch_re, callback=batch_callback)
    rsps.add_callback(responses.POST, session_action_re, callback=action_callback)


@responses.activate
def test_live_pipeline_completes_session_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

    config_path = _write_config(tmp_path)

    _register_nessus_mocks(responses)
    session_actions: list = []
    _register_drata_mocks(responses, session_actions)

    exit_code = cli.main(
        [
            "--config",
            str(config_path),
            "--checks",
            str(CHECKS),
            "run",
        ]
    )

    assert exit_code == 0, "expected a clean completed run"
    assert session_actions == ["complete"]

    state = load_last_run_state(tmp_path / "state")
    assert state.last_record_count == 3
    assert state.last_session_id is not None
    assert state.last_session_id.startswith("nessus-47-")

    reports = list((tmp_path / "artifacts" / "reports").glob("*.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text())
    assert report["exit_code"] == 0
    assert report["session_action"] == "complete"
    assert report["parse_mode"] == "xml_full"
    assert report["record_count"] == 3


@responses.activate
def test_live_pipeline_cancels_session_when_safety_gate_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

    # min_hosts set higher than the 3 hosts in sample_small.nessus so gate 1
    # fails before any batch is ever uploaded.
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        _write_config(tmp_path).read_text().replace("min_hosts: 1", "min_hosts: 50")
    )

    _register_nessus_mocks(responses)
    session_actions: list = []
    _register_drata_mocks(responses, session_actions)

    exit_code = cli.main(
        [
            "--config",
            str(config_path),
            "--checks",
            str(CHECKS),
            "run",
        ]
    )

    assert exit_code == 5
    # No batch was ever uploaded, so there's no session for Drata to cancel
    # server-side — the pipeline must not call the cancel action on a
    # session that was never created.
    assert session_actions == []

    reports = list((tmp_path / "artifacts" / "reports").glob("*.json"))
    report = json.loads(reports[0].read_text())
    assert report["session_action"] == "aborted_pre_upload"
    gate_by_name = {g["name"]: g for g in report["safety_gates"]}
    assert gate_by_name["min_hosts"]["passed"] is False

    # A failed run must not update last-success state.
    state = load_last_run_state(tmp_path / "state")
    assert state.last_record_count is None


@responses.activate
def test_live_pipeline_cancels_real_session_when_batch_upload_fails(tmp_path, monkeypatch):
    """Gates 1-5 all pass (so a batch upload is actually attempted and a
    session genuinely gets created server-side), but the batch upload
    itself fails -- gate 6 then fails post-upload, and THIS is the path
    that must call the real cancel_session action, unlike the pre-upload
    abort case above.
    """
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

    config_path = _write_config(tmp_path)

    _register_nessus_mocks(responses)

    responses.add(
        responses.GET,
        f"{DRATA_BASE}/public/v2/custom-connections/99/resources/5/sessions",
        json=[],
        status=200,
    )

    import re

    session_batch_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+$"
    )
    session_action_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+/actions$"
    )

    # The batch upload itself fails (schema validation failure, no retry).
    responses.add(responses.POST, session_batch_re, json={"message": "bad record"}, status=400)

    session_actions: list = []

    def action_callback(request):
        body = json.loads(request.body)
        session_actions.append(body.get("action"))
        return (200, {}, json.dumps({}))

    responses.add_callback(responses.POST, session_action_re, callback=action_callback)

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 5
    # A real session was created (a batch was actually POSTed to it), so the
    # real cancel action must have been called on it.
    assert session_actions == ["cancel"]

    reports = list((tmp_path / "artifacts" / "reports").glob("*.json"))
    report = json.loads(reports[0].read_text())
    assert report["session_action"] == "cancel"
    gate_by_name = {g["name"]: g for g in report["safety_gates"]}
    assert gate_by_name["batch_uploads"]["passed"] is False
    assert gate_by_name["min_hosts"]["passed"] is True

    state = load_last_run_state(tmp_path / "state")
    assert state.last_record_count is None


def _write_csv_config(tmp_path: Path) -> Path:
    """Like _write_config, but export_format: csv and manifest-coverage gate
    disabled (min_manifest_coverage_pct: 0) so these tests isolate the
    parse_mode gate specifically -- the CSV fixture's check names only
    partially match checks_small.yaml, which would otherwise also fail the
    coverage gate and muddy what's being proven here (acceptance test 13).
    """
    config_path = tmp_path / "config_csv.yaml"
    config_path.write_text(
        _write_config(tmp_path)
        .read_text()
        .replace('export_format: "nessus"', 'export_format: "csv"')
        .replace("min_manifest_coverage_pct: 90", "min_manifest_coverage_pct: 0")
    )
    return config_path


@responses.activate
def test_acceptance_13_csv_degraded_session_refused_without_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

    config_path = _write_csv_config(tmp_path)
    _register_nessus_mocks(responses, download_body=SAMPLE_CSV.read_bytes())
    responses.add(
        responses.GET,
        f"{DRATA_BASE}/public/v2/custom-connections/99/resources/5/sessions",
        json=[],
        status=200,
    )

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 5
    reports = list((tmp_path / "artifacts" / "reports").glob("*.json"))
    report = json.loads(reports[0].read_text())
    assert report["parse_mode"] == "csv_degraded"
    assert report["session_action"] == "aborted_pre_upload"
    gate_by_name = {g["name"]: g for g in report["safety_gates"]}
    assert gate_by_name["parse_mode"]["passed"] is False

    payloads_dir = list((tmp_path / "artifacts" / "payloads").iterdir())[0]
    records = json.loads((payloads_dir / "records.json").read_text())
    assert all(r["source_fidelity"] == "degraded" for r in records)


@responses.activate
def test_csv_degraded_session_proceeds_with_allow_degraded_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

    config_path = _write_csv_config(tmp_path)
    _register_nessus_mocks(responses, download_body=SAMPLE_CSV.read_bytes())

    import re

    responses.add(
        responses.GET,
        f"{DRATA_BASE}/public/v2/custom-connections/99/resources/5/sessions",
        json=[],
        status=200,
    )
    session_batch_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+$"
    )
    session_action_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+/actions$"
    )
    responses.add(responses.POST, session_batch_re, json={"data": []}, status=200)
    session_actions: list = []

    def action_callback(request):
        body = json.loads(request.body)
        session_actions.append(body.get("action"))
        return (200, {}, json.dumps({}))

    responses.add_callback(responses.POST, session_action_re, callback=action_callback)

    exit_code = cli.main(
        [
            "--config",
            str(config_path),
            "--checks",
            str(CHECKS),
            "--allow-degraded-session",
            "run",
        ]
    )

    assert exit_code == 0, "expected --allow-degraded-session to let the CSV session complete"
    assert session_actions == ["complete"]
