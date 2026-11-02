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

    import re

    session_batch_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+$"
    )
    session_action_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+/actions$"
    )

    def batch_callback(request):
        sent = json.loads(request.body)["data"]
        results = [
            {"id": r["id"], "statusCode": 201 if i == 0 else 200}
            for i, r in enumerate(sent)
        ]
        return (200, {}, json.dumps({"data": results}))

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
    assert report["records_created"] == 1
    assert report["records_updated"] == 2


@responses.activate
def test_stale_session_cleanup_failure_does_not_abort_the_run(tmp_path, monkeypatch):
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
        json={"message": "unspecified"},
        status=422,
    )

    import re

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

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 0, "a failed cleanup listing must not abort the run"
    assert session_actions == ["complete"]


@responses.activate
def test_stale_session_cleanup_prefers_sessionId_over_short_internal_id(tmp_path, monkeypatch):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

    config_path = _write_config(tmp_path)
    _register_nessus_mocks(responses)

    stale_session_id = "nessus-999-20250101T000000Z"

    responses.add(
        responses.GET,
        f"{DRATA_BASE}/public/v2/custom-connections/99/resources/5/sessions",
        json=[{"id": 1, "sessionId": stale_session_id, "status": "IN_PROGRESS"}],
        status=200,
    )

    import re

    session_batch_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+$"
    )
    session_action_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/([^/]+)/actions$"
    )
    responses.add(responses.POST, session_batch_re, json={"data": []}, status=200)

    cancelled_ids: list = []
    completed_ids: list = []

    def action_callback(request):
        match = session_action_re.match(request.url)
        session_id_in_url = match.group(1)
        body = json.loads(request.body)
        if body.get("action") == "cancel":
            cancelled_ids.append(session_id_in_url)
        elif body.get("action") == "complete":
            completed_ids.append(session_id_in_url)
        return (200, {}, json.dumps({}))

    responses.add_callback(responses.POST, session_action_re, callback=action_callback)

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 0, "expected the run to complete despite the stale session"
    assert "1" not in cancelled_ids
    assert cancelled_ids == [stale_session_id]
    assert len(completed_ids) == 1
    assert completed_ids[0].startswith("nessus-47-")


@responses.activate
def test_stale_session_cleanup_only_cancels_in_progress_sessions(tmp_path, monkeypatch):
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
        json={
            "data": [
                {"id": 3, "sessionId": "nessus-999-20250103T000000Z", "status": "ACTIVE"},
                {"id": 2, "sessionId": "nessus-999-20250102T000000Z", "status": "IN_PROGRESS"},
                {"id": 1, "sessionId": "nessus-999-20250101T000000Z", "status": "CANCELED"},
            ],
            "pagination": {"cursor": None},
        },
        status=200,
    )

    import re

    session_batch_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/[^/]+$"
    )
    session_action_re = re.compile(
        rf"{re.escape(DRATA_BASE)}/public/v2/custom-connections/99/resources/5/sessions/([^/]+)/actions$"
    )
    responses.add(responses.POST, session_batch_re, json={"data": []}, status=200)

    cancelled_ids: list = []

    def action_callback(request):
        match = session_action_re.match(request.url)
        if json.loads(request.body).get("action") == "cancel":
            cancelled_ids.append(match.group(1))
        return (200, {}, json.dumps({}))

    responses.add_callback(responses.POST, session_action_re, callback=action_callback)

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 0
    assert cancelled_ids == ["nessus-999-20250102T000000Z"]


@responses.activate
def test_live_pipeline_aborts_and_cancels_when_record_rejected_with_201(tmp_path, monkeypatch):
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

    def batch_callback(request):
        sent = json.loads(request.body)["data"]
        results = [
            {
                "statusCode": 201,
                "error": {
                    "message": "Schema validation failed for data: [{\"\":\"must have "
                    "required property 'some_check_field'\"}]",
                    "code": 28022,
                },
                "data": {"id": r["id"]},
            }
            for r in sent
        ]
        return (200, {}, json.dumps(results))

    responses.add_callback(responses.POST, session_batch_re, callback=batch_callback)

    session_actions: list = []

    def action_callback(request):
        session_actions.append(json.loads(request.body).get("action"))
        return (200, {}, json.dumps({}))

    responses.add_callback(responses.POST, session_action_re, callback=action_callback)

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 5
    assert session_actions == ["cancel"]
    report = json.loads(next((tmp_path / "artifacts" / "reports").glob("*.json")).read_text())
    gate_by_name = {g["name"]: g for g in report["safety_gates"]}
    assert gate_by_name["batch_uploads"]["passed"] is False


@responses.activate
def test_live_pipeline_cancels_session_when_safety_gate_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

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
    assert session_actions == []

    reports = list((tmp_path / "artifacts" / "reports").glob("*.json"))
    report = json.loads(reports[0].read_text())
    assert report["session_action"] == "aborted_pre_upload"
    gate_by_name = {g["name"]: g for g in report["safety_gates"]}
    assert gate_by_name["min_hosts"]["passed"] is False

    state = load_last_run_state(tmp_path / "state")
    assert state.last_record_count is None


@responses.activate
def test_live_pipeline_cancels_real_session_when_batch_upload_fails(tmp_path, monkeypatch):
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

    responses.add(responses.POST, session_batch_re, json={"message": "bad record"}, status=400)

    session_actions: list = []

    def action_callback(request):
        body = json.loads(request.body)
        session_actions.append(body.get("action"))
        return (200, {}, json.dumps({}))

    responses.add_callback(responses.POST, session_action_re, callback=action_callback)

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 5
    assert session_actions == ["cancel"]

    reports = list((tmp_path / "artifacts" / "reports").glob("*.json"))
    report = json.loads(reports[0].read_text())
    assert report["session_action"] == "cancel"
    gate_by_name = {g["name"]: g for g in report["safety_gates"]}
    assert gate_by_name["batch_uploads"]["passed"] is False
    assert gate_by_name["min_hosts"]["passed"] is True

    state = load_last_run_state(tmp_path / "state")
    assert state.last_record_count is None


@responses.activate
def test_409_conflict_retries_batch_once_then_succeeds(tmp_path, monkeypatch):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)

    config_path = _write_config(tmp_path)
    _register_nessus_mocks(responses)

    import re

    responses.add(
        responses.GET,
        f"{DRATA_BASE}/public/v2/custom-connections/99/resources/5/sessions",
        json=[],
        status=200,
    )
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

    responses.add(
        responses.POST, session_batch_re, json={"message": "session state conflict"}, status=409
    )
    responses.add(responses.POST, session_batch_re, json={"data": []}, status=200)

    session_actions: list = []

    def action_callback(request):
        body = json.loads(request.body)
        session_actions.append(body.get("action"))
        return (200, {}, json.dumps({}))

    responses.add_callback(responses.POST, session_action_re, callback=action_callback)

    exit_code = cli.main(["--config", str(config_path), "--checks", str(CHECKS), "run"])

    assert exit_code == 0, "expected the 409 retry to succeed and the session to complete"
    assert session_actions == ["complete"]

    batch_calls = [
        c for c in responses.calls if session_batch_re.match(c.request.url or "")
    ]
    assert len(batch_calls) == 2


def _write_csv_config(tmp_path: Path) -> Path:
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
            "run",
            "--allow-degraded-session",
        ]
    )

    assert exit_code == 0, "expected --allow-degraded-session to let the CSV session complete"
    assert session_actions == ["complete"]


_EMPTY_EXPORT_TEMPLATE = (
    b'<?xml version="1.0"?><NessusClientData_v2><Report name="r">%s</Report></NessusClientData_v2>'
)
_HOST_WITHOUT_COMPLIANCE = (
    b'<ReportHost name="h"><HostProperties><tag name="netbios-name">WKS-1</tag>'
    b"</HostProperties></ReportHost>"
)


def _live_run(tmp_path, monkeypatch, *, download_body, extra_args=(), checks=CHECKS):
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "test-nessus-access")
    monkeypatch.setenv("NESSUS_SECRET_KEY", "test-nessus-secret")
    monkeypatch.setenv("DRATA_API_KEY", "test-drata-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda _s: None)
    config_path = _write_config(tmp_path)
    _register_nessus_mocks(responses, download_body=download_body)
    session_actions: list = []
    _register_drata_mocks(responses, session_actions)
    exit_code = cli.main(
        ["--config", str(config_path), "--checks", str(checks), "run", *extra_args]
    )
    report = json.loads(next((tmp_path / "artifacts" / "reports").glob("*.json")).read_text())
    return exit_code, session_actions, report


@responses.activate
def test_live_partial_coverage_pushes_not_found_instead_of_aborting(tmp_path, monkeypatch):
    checks = tmp_path / "checks_with_missing.yaml"
    checks.write_text(
        CHECKS.read_text()
        + "\n  - field: removed_from_audit\n"
        + "    label: gone\n"
        + "    match:\n"
        + "      check_name_exact: \"9.9.9 A check the scan no longer has\"\n"
        + "    required: true\n"
    )
    exit_code, session_actions, report = _live_run(
        tmp_path, monkeypatch, download_body=SAMPLE_SMALL.read_bytes(), checks=checks
    )

    assert exit_code == 0
    assert session_actions == ["complete"]
    assert report["manifest_coverage_pct"] < 90
    assert report["manifest_missing_fields"] == ["removed_from_audit"]
    assert report["no_results_reason"] is None
    gate = {g["name"]: g for g in report["safety_gates"]}["manifest_coverage"]
    assert gate["passed"] is True and "NOT_FOUND" in gate["reason"]

    payload = next((tmp_path / "artifacts" / "payloads").iterdir()) / "records.json"
    records = json.loads(payload.read_text())
    assert records and all(r["removed_from_audit"] == "NOT_FOUND" for r in records)
    assert all(r["all_required_checks_passed"] is False for r in records)


@responses.activate
def test_live_scan_with_hosts_but_no_compliance_results_sends_nothing(tmp_path, monkeypatch):
    exit_code, session_actions, report = _live_run(
        tmp_path,
        monkeypatch,
        download_body=_EMPTY_EXPORT_TEMPLATE % _HOST_WITHOUT_COMPLIANCE,
    )

    assert exit_code == 5
    assert session_actions == []
    assert report["session_action"] == "aborted_pre_upload"
    assert "no compliance results" in report["no_results_reason"]
    gate = {g["name"]: g for g in report["safety_gates"]}["manifest_coverage"]
    assert gate["passed"] is False and gate["reason"].startswith("NO RESULTS:")
    assert load_last_run_state(tmp_path / "state").last_record_count is None


@responses.activate
def test_live_scan_with_no_hosts_sends_nothing_even_with_force(tmp_path, monkeypatch):
    exit_code, session_actions, report = _live_run(
        tmp_path,
        monkeypatch,
        download_body=_EMPTY_EXPORT_TEMPLATE % b"",
        extra_args=("--force",),
    )

    assert exit_code == 5
    assert session_actions == []
    assert report["record_count"] == 0
    assert "no hosts" in report["no_results_reason"]
    gates = {g["name"]: g for g in report["safety_gates"]}
    assert gates["min_hosts"]["passed"] is True
    assert gates["manifest_coverage"]["passed"] is False
