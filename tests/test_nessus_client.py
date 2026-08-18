"""Tests for nessus_client.py -- the read-only Tenable Nessus API client.

All HTTP is mocked via `responses`; zero real network calls. Zero real
credentials -- fake keys only.

Highest-value test in this file is
test_request_export_sends_json_body_not_form_encoded, which proves the
json=/data= gotcha (spec Section 3.3) is actually guarded: a regression to
`data=` would change the request Content-Type and body shape and fail this
test.
"""

from __future__ import annotations

import json
import logging
import time

import pytest
import responses

from nessus_drata.nessus_client import (
    NessusApiError,
    NessusClient,
    NessusExportTimeoutError,
)

BASE_URL = "https://localhost:8834"
FAKE_ACCESS_KEY = "test-access-key-1234"
FAKE_SECRET_KEY = "test-secret-key-5678"


def make_client(**kwargs):
    defaults = dict(connect_timeout=1, read_timeout=1)
    defaults.update(kwargs)
    return NessusClient(BASE_URL, FAKE_ACCESS_KEY, FAKE_SECRET_KEY, **defaults)


# ---------------------------------------------------------------------------
# server_status / auth header
# ---------------------------------------------------------------------------


@responses.activate
def test_server_status_hits_right_url_and_returns_json():
    responses.add(
        responses.GET,
        f"{BASE_URL}/server/status",
        json={"code": 200, "status": "ready"},
        status=200,
    )
    client = make_client()
    body = client.server_status()

    assert body == {"code": 200, "status": "ready"}
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == f"{BASE_URL}/server/status"


@responses.activate
def test_x_apikeys_header_exact_format_on_every_request():
    responses.add(
        responses.GET,
        f"{BASE_URL}/server/status",
        json={"code": 200, "status": "ready"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans",
        json={"folders": [], "scans": []},
        status=200,
    )
    client = make_client()
    client.server_status()
    client.list_scans()

    expected = f"accessKey={FAKE_ACCESS_KEY}; secretKey={FAKE_SECRET_KEY}"
    for call in responses.calls:
        assert call.request.headers.get("X-ApiKeys") == expected


# ---------------------------------------------------------------------------
# list_scans
# ---------------------------------------------------------------------------


@responses.activate
def test_list_scans_handles_null_scans_without_raising():
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans",
        json={"folders": [], "scans": None},
        status=200,
    )
    client = make_client()
    body = client.list_scans()

    assert body["scans"] is None
    assert body["folders"] == []


@responses.activate
def test_list_scans_with_folder_id_includes_query_param():
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans",
        json={"folders": [], "scans": []},
        status=200,
    )
    client = make_client()
    client.list_scans(folder_id=5)

    assert "folder_id=5" in responses.calls[0].request.url


# ---------------------------------------------------------------------------
# get_scan
# ---------------------------------------------------------------------------


@responses.activate
def test_get_scan_returns_body_as_is():
    body = {
        "info": {"status": "completed"},
        "history": [{"history_id": 1, "status": "completed", "last_modification_date": 123}],
    }
    responses.add(responses.GET, f"{BASE_URL}/scans/47", json=body, status=200)
    client = make_client()

    assert client.get_scan(47) == body


# ---------------------------------------------------------------------------
# request_export -- the json=/data= gotcha (spec Section 3.3)
# ---------------------------------------------------------------------------


@responses.activate
def test_request_export_sends_json_body_not_form_encoded():
    """The single highest-value test in this file. If someone changes the
    implementation from `json=` to `data=`, the request Content-Type
    changes to `application/x-www-form-urlencoded` and the body is no
    longer a JSON object -- both assertions below would fail."""
    responses.add(
        responses.POST,
        f"{BASE_URL}/scans/47/export",
        json={"file": 1, "token": "tok"},
        status=200,
    )
    client = make_client()
    body = client.request_export(47, export_format="nessus")

    assert body == {"file": 1, "token": "tok"}
    assert len(responses.calls) == 1
    request = responses.calls[0].request

    assert request.headers.get("Content-Type") == "application/json"
    # request.body is bytes/str of a JSON-encoded object -- if this were
    # form-encoded instead, json.loads would raise or yield the wrong shape.
    parsed = json.loads(request.body)
    assert parsed == {"format": "nessus"}


@responses.activate
def test_request_export_with_history_id_includes_query_param():
    responses.add(
        responses.POST,
        f"{BASE_URL}/scans/47/export",
        json={"file": 1, "token": "tok"},
        status=200,
    )
    client = make_client()
    client.request_export(47, history_id=99)

    assert "history_id=99" in responses.calls[0].request.url


# ---------------------------------------------------------------------------
# export_status
# ---------------------------------------------------------------------------


@responses.activate
def test_export_status_loading_and_ready():
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/status",
        json={"status": "loading"},
        status=200,
    )
    client = make_client()
    assert client.export_status(47, 1) == {"status": "loading"}


@responses.activate
def test_export_status_ready():
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/status",
        json={"status": "ready"},
        status=200,
    )
    client = make_client()
    assert client.export_status(47, 1) == {"status": "ready"}


# ---------------------------------------------------------------------------
# download_export
# ---------------------------------------------------------------------------


@responses.activate
def test_download_export_writes_file_byte_for_byte(tmp_path):
    # Body bigger than one 1 MB chunk, to exercise multi-chunk streaming.
    body_bytes = (b"NESSUS-EXPORT-CHUNK-DATA" * 100_000)  # ~2.4 MB
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/download",
        body=body_bytes,
        status=200,
        content_type="application/octet-stream",
    )
    dest = tmp_path / "nested" / "scan-47.nessus"
    client = make_client()
    client.download_export(47, 1, str(dest))

    assert dest.exists()
    assert dest.read_bytes() == body_bytes


@responses.activate
def test_download_export_raises_on_error_status(tmp_path):
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/download",
        json={"error": "not found"},
        status=404,
    )
    dest = tmp_path / "scan-47.nessus"
    client = make_client()

    with pytest.raises(NessusApiError):
        client.download_export(47, 1, str(dest))
    assert not dest.exists()


# ---------------------------------------------------------------------------
# wait_for_export_ready -- bounded polling (spec Section 3.4)
# ---------------------------------------------------------------------------


@responses.activate
def test_wait_for_export_ready_polls_loading_twice_then_ready(monkeypatch):
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/status",
        json={"status": "loading"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/status",
        json={"status": "loading"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/status",
        json={"status": "ready"},
        status=200,
    )

    sleep_calls = []
    monkeypatch.setattr(
        "nessus_drata.nessus_client.time.sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    client = make_client()
    client.wait_for_export_ready(47, 1, timeout_seconds=900)

    assert len(responses.calls) == 3
    assert sleep_calls[0] == 2
    for later in sleep_calls[1:]:
        assert later == 3


@responses.activate
def test_wait_for_export_ready_timeout(monkeypatch):
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/status",
        json={"status": "loading"},
        status=200,
    )

    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda seconds: None)

    # Fake monotonic clock: advances by 3 seconds on every call, so elapsed
    # exceeds a 5-second timeout deterministically, with no wall-clock delay.
    clock = {"t": 0.0}

    def fake_monotonic():
        clock["t"] += 3.0
        return clock["t"]

    monkeypatch.setattr("nessus_drata.nessus_client.time.monotonic", fake_monotonic)

    client = make_client()
    with pytest.raises(NessusExportTimeoutError) as excinfo:
        client.wait_for_export_ready(47, 1, timeout_seconds=5)

    message = str(excinfo.value)
    assert "47" in message
    assert "1" in message


@responses.activate
def test_wait_for_export_ready_terminal_error_stops_immediately(monkeypatch):
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47/export/1/status",
        json={"status": "error"},
        status=200,
    )
    monkeypatch.setattr("nessus_drata.nessus_client.time.sleep", lambda seconds: None)

    client = make_client()
    with pytest.raises(NessusApiError):
        client.wait_for_export_ready(47, 1, timeout_seconds=900)

    assert len(responses.calls) == 1


# ---------------------------------------------------------------------------
# non-2xx raises NessusApiError
# ---------------------------------------------------------------------------


@responses.activate
def test_non_2xx_response_raises_nessus_api_error():
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47",
        json={"error": "boom"},
        status=500,
    )
    client = make_client()

    with pytest.raises(NessusApiError):
        client.get_scan(47)


# ---------------------------------------------------------------------------
# verify_tls=False -- loud per-call warning, never global suppression
# ---------------------------------------------------------------------------


@responses.activate
def test_verify_tls_false_logs_warning_on_every_call(caplog):
    responses.add(
        responses.GET,
        f"{BASE_URL}/server/status",
        json={"code": 200, "status": "ready"},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/server/status",
        json={"code": 200, "status": "ready"},
        status=200,
    )
    client = make_client(verify_tls=False)

    with caplog.at_level(logging.WARNING, logger="nessus_drata.nessus_client"):
        client.server_status()
        client.server_status()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2
    for record in warnings:
        assert "TLS verification is DISABLED" in record.getMessage()


# ---------------------------------------------------------------------------
# secret redaction
# ---------------------------------------------------------------------------


@responses.activate
def test_exception_message_never_contains_raw_credentials():
    responses.add(
        responses.GET,
        f"{BASE_URL}/scans/47",
        json={"error": "boom"},
        status=500,
    )
    client = make_client()

    with pytest.raises(NessusApiError) as excinfo:
        client.get_scan(47)

    message = str(excinfo.value)
    assert FAKE_ACCESS_KEY not in message
    assert FAKE_SECRET_KEY not in message


# ---------------------------------------------------------------------------
# read-only guarantee: no mutating methods exist on the client
# ---------------------------------------------------------------------------


def test_no_mutating_scan_methods_exist():
    forbidden_names = {
        "launch",
        "launch_scan",
        "stop",
        "stop_scan",
        "kill",
        "kill_scan",
        "pause",
        "pause_scan",
        "resume",
        "resume_scan",
        "create_scan",
        "configure_scan",
        "delete_scan",
        "import_scan",
        "delete",
        "create",
        "update",
        "put",
        "patch",
    }
    public_methods = {
        name
        for name in dir(NessusClient)
        if not name.startswith("_") and callable(getattr(NessusClient, name))
    }

    assert public_methods == {
        "server_status",
        "list_scans",
        "get_scan",
        "request_export",
        "export_status",
        "download_export",
        "wait_for_export_ready",
    }
    assert public_methods.isdisjoint(forbidden_names)
