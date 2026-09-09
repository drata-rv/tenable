"""Tests for drata_client.py -- raw authenticated HTTP calls against the Drata
public API v2, retry-on-429/5xx behavior, and the Section 5.4 / 5.6 error
handling contract. All HTTP is mocked via `responses`; zero real network calls.
"""

from __future__ import annotations

import json

import pytest
import responses

from nessus_drata.drata_client import (
    DRATA_401_10000_CHECKLIST,
    DrataApiError,
    DrataClient,
    DrataResponseError,
    count_record_outcomes,
)

BASE_URL = "https://public-api.drata.com"
FAKE_KEY = "test-drata-key-1234"


def make_client(**kwargs):
    defaults = dict(max_retries=5, connect_timeout=1, read_timeout=1)
    defaults.update(kwargs)
    return DrataClient(BASE_URL, FAKE_KEY, **defaults)


def _auth_headers(calls):
    return [call.request.headers.get("Authorization") for call in calls]


# ---------------------------------------------------------------------------
# get_connection
# ---------------------------------------------------------------------------


@responses.activate
def test_get_connection_hits_right_url_and_returns_json():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/42",
        json={"id": 42, "customResources": [{"id": 7}]},
        status=200,
    )
    client = make_client()
    body = client.get_connection(42)

    assert body == {"id": 42, "customResources": [{"id": 7}]}
    assert len(responses.calls) == 1
    call = responses.calls[0]
    assert "/public/v2/custom-connections/42" in call.request.url
    assert "expand" in call.request.url
    assert "customResources" in call.request.url


@responses.activate
def test_authorization_header_is_bearer_prefixed_on_every_request():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"id": 1},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/2/resources/9/sessions",
        json=[],
        status=200,
    )
    client = make_client()
    client.get_connection(1)
    client.list_sessions(2, 9)

    for header in _auth_headers(responses.calls):
        assert header == f"Bearer {FAKE_KEY}"


# ---------------------------------------------------------------------------
# list_sessions -- defensive shape handling
# ---------------------------------------------------------------------------


@responses.activate
def test_list_sessions_bare_list_shape():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions",
        json=[{"id": "s1"}, {"id": "s2"}],
        status=200,
    )
    client = make_client()
    result = client.list_sessions(1, 2, status="IN_PROGRESS")
    assert result == [{"id": "s1"}, {"id": "s2"}]


@responses.activate
def test_list_sessions_dict_with_data_key():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions",
        json={"data": [{"id": "s1"}]},
        status=200,
    )
    client = make_client()
    result = client.list_sessions(1, 2)
    assert result == [{"id": "s1"}]


@responses.activate
def test_list_sessions_dict_with_sessions_key():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions",
        json={"sessions": [{"id": "s9"}]},
        status=200,
    )
    client = make_client()
    result = client.list_sessions(1, 2)
    assert result == [{"id": "s9"}]


@responses.activate
def test_list_sessions_unexpected_shape_returns_empty_list():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions",
        json={"totally": "unexpected"},
        status=200,
    )
    client = make_client()
    result = client.list_sessions(1, 2)
    assert result == []


# ---------------------------------------------------------------------------
# cancel_session / complete_session -- correct body + URL
# ---------------------------------------------------------------------------


@responses.activate
def test_cancel_session_sends_correct_body_and_url():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1/actions",
        json={},
        status=200,
    )
    client = make_client()
    client.cancel_session(1, 2, "sess-1")

    assert len(responses.calls) == 1
    call = responses.calls[0]
    assert call.request.url == (
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1/actions"
    )
    assert json.loads(call.request.body) == {"action": "cancel"}


@responses.activate
def test_complete_session_sends_correct_body_and_url():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1/actions",
        json={},
        status=200,
    )
    client = make_client()
    client.complete_session(1, 2, "sess-1")

    assert len(responses.calls) == 1
    call = responses.calls[0]
    assert json.loads(call.request.body) == {"action": "complete"}


# ---------------------------------------------------------------------------
# upload_session_batch / upsert_records -- per-record statusCode inspection
# ---------------------------------------------------------------------------


@responses.activate
def test_upload_session_batch_sends_data_body():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1",
        json={"data": [{"id": "host-1", "statusCode": 200}]},
        status=200,
    )
    client = make_client()
    records = [{"id": "host-1", "hostname": "WKS-1"}]
    body = client.upload_session_batch(1, 2, "sess-1", records)

    assert body == {"data": [{"id": "host-1", "statusCode": 200}]}
    call = responses.calls[0]
    assert json.loads(call.request.body) == {"data": records}


@responses.activate
def test_upload_session_batch_raises_on_per_record_failure_despite_200():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1",
        json={
            "data": [
                {"id": "host-1", "statusCode": 200},
                {"id": "host-2", "statusCode": 400, "message": "bad field"},
            ]
        },
        status=200,
    )
    client = make_client()
    records = [{"id": "host-1"}, {"id": "host-2"}]

    with pytest.raises(DrataResponseError) as exc_info:
        client.upload_session_batch(1, 2, "sess-1", records)

    assert "host-2" in str(exc_info.value)
    assert "400" in str(exc_info.value)


@responses.activate
def test_upsert_records_raises_on_per_record_failure_despite_200():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/records",
        json=[{"id": "host-1", "statusCode": 422}],
        status=200,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.upsert_records(1, 2, [{"id": "host-1"}])

    assert "host-1" in str(exc_info.value)
    assert "422" in str(exc_info.value)


@responses.activate
def test_upsert_records_success_returns_body():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/records",
        json=[{"id": "host-1", "statusCode": 200}],
        status=200,
    )
    client = make_client()
    body = client.upsert_records(1, 2, [{"id": "host-1"}])
    assert body == [{"id": "host-1", "statusCode": 200}]


# ---------------------------------------------------------------------------
# 401 code 10000 -- checklist printed verbatim, no retry
# ---------------------------------------------------------------------------


@responses.activate
def test_401_code_10000_prints_checklist_and_raises_no_retry(capsys):
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"code": 10000, "message": "Unauthorized"},
        status=401,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.get_connection(1)

    assert exc_info.value.status_code == 401
    assert exc_info.value.error_code == 10000
    assert len(responses.calls) == 1  # no retry

    captured = capsys.readouterr()
    assert DRATA_401_10000_CHECKLIST in captured.err


@responses.activate
def test_401_code_12310_no_retry():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"code": 12310, "message": "API key not found"},
        status=401,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.get_connection(1)

    assert exc_info.value.status_code == 401
    assert exc_info.value.error_code == 12310
    assert len(responses.calls) == 1


@responses.activate
def test_401_code_26430_no_retry():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"code": 26430, "message": "No Authorization header"},
        status=401,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.get_connection(1)

    assert exc_info.value.status_code == 401
    assert exc_info.value.error_code == 26430
    assert len(responses.calls) == 1


@responses.activate
def test_403_no_retry():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"message": "Forbidden"},
        status=403,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.get_connection(1)

    assert exc_info.value.status_code == 403
    assert len(responses.calls) == 1


@responses.activate
def test_409_no_retry_caller_must_handle():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1/actions",
        json={"message": "conflict"},
        status=409,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.complete_session(1, 2, "sess-1")

    assert exc_info.value.status_code == 409
    assert len(responses.calls) == 1


# ---------------------------------------------------------------------------
# 400 schema validation -- no retry, offending id surfaced
# ---------------------------------------------------------------------------


@responses.activate
def test_400_schema_validation_no_retry_names_offending_record():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/records",
        json={"id": "nessus-wks-0041", "field": "hostname", "message": "invalid type"},
        status=400,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.upsert_records(1, 2, [{"id": "nessus-wks-0041"}])

    assert exc_info.value.status_code == 400
    assert "nessus-wks-0041" in str(exc_info.value)
    assert len(responses.calls) == 1  # no retry on 400


# ---------------------------------------------------------------------------
# 429 retry honoring Retry-After
# ---------------------------------------------------------------------------


@responses.activate
def test_429_retries_honoring_retry_after_then_succeeds(monkeypatch):
    sleep_calls = []
    monkeypatch.setattr(
        "nessus_drata.drata_client.time.sleep", lambda seconds: sleep_calls.append(seconds)
    )

    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"message": "rate limited"},
        status=429,
        headers={"Retry-After": "1"},
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"id": 1},
        status=200,
    )

    client = make_client(max_retries=5)
    body = client.get_connection(1)

    assert body == {"id": 1}
    assert len(responses.calls) == 2
    assert sleep_calls == [1.0]  # honored Retry-After exactly, no backoff jitter


@responses.activate
def test_429_exhausts_retries_and_raises(monkeypatch):
    monkeypatch.setattr("nessus_drata.drata_client.time.sleep", lambda seconds: None)

    for _ in range(3):
        responses.add(
            responses.GET,
            f"{BASE_URL}/public/v2/custom-connections/1",
            json={"message": "rate limited"},
            status=429,
        )

    client = make_client(max_retries=3)

    with pytest.raises(DrataResponseError) as exc_info:
        client.get_connection(1)

    assert exc_info.value.status_code == 429
    assert len(responses.calls) == 3


# ---------------------------------------------------------------------------
# 5xx retry then success, and retry exhaustion
# ---------------------------------------------------------------------------


@responses.activate
def test_5xx_retries_then_succeeds(monkeypatch):
    sleep_calls = []
    monkeypatch.setattr(
        "nessus_drata.drata_client.time.sleep", lambda seconds: sleep_calls.append(seconds)
    )

    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"message": "server error"},
        status=500,
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"message": "server error"},
        status=502,
    )
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"id": 1},
        status=200,
    )

    client = make_client(max_retries=5)
    body = client.get_connection(1)

    assert body == {"id": 1}
    assert len(responses.calls) == 3
    assert len(sleep_calls) == 2
    # monotonically increasing, bounded backoff
    assert sleep_calls[1] >= sleep_calls[0]


@responses.activate
def test_max_retries_exhausted_raises_after_exact_attempt_count(monkeypatch):
    monkeypatch.setattr("nessus_drata.drata_client.time.sleep", lambda seconds: None)

    max_retries = 4
    for _ in range(max_retries):
        responses.add(
            responses.GET,
            f"{BASE_URL}/public/v2/custom-connections/1",
            json={"message": "server error"},
            status=503,
        )

    client = make_client(max_retries=max_retries)

    with pytest.raises(DrataResponseError) as exc_info:
        client.get_connection(1)

    assert exc_info.value.status_code == 503
    # Internally consistent: this client makes exactly `max_retries` total
    # attempts (no retry-after-the-last-failure sleep), then raises.
    assert len(responses.calls) == max_retries


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


@responses.activate
def test_api_key_never_appears_in_exception_string():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1",
        json={"code": 10000, "message": "Unauthorized"},
        status=401,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.get_connection(1)

    message = str(exc_info.value)
    assert FAKE_KEY not in message
    assert message.count("****") >= 0  # redacted form permitted
    if "****" in message:
        assert FAKE_KEY[-4:] in message  # only the last-4 redacted form


@responses.activate
def test_api_key_never_appears_in_400_exception_string():
    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/records",
        json={"id": "host-1", "message": "invalid"},
        status=400,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.upsert_records(1, 2, [{"id": "host-1"}])

    assert FAKE_KEY not in str(exc_info.value)


@responses.activate
def test_unspecified_status_code_includes_response_body_in_message():
    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions",
        json={"message": "some Drata-side validation detail"},
        status=422,
    )
    client = make_client()

    with pytest.raises(DrataResponseError) as exc_info:
        client.list_sessions(1, 2)

    assert exc_info.value.status_code == 422
    assert "some Drata-side validation detail" in str(exc_info.value)


def test_drata_response_error_is_a_drata_api_error():
    assert issubclass(DrataResponseError, DrataApiError)


# ---------------------------------------------------------------------------
# Connection-level failures (review finding: these were leaking as bare
# requests exceptions, misclassified as exit code 1 instead of 4)
# ---------------------------------------------------------------------------


@responses.activate
def test_connection_error_is_wrapped_as_drata_api_error():
    import requests

    responses.add(
        responses.GET,
        f"{BASE_URL}/public/v2/custom-connections/1?expand[]=customResources",
        body=requests.exceptions.ConnectionError("simulated DNS/connection failure"),
    )
    client = make_client()

    with pytest.raises(DrataApiError) as exc_info:
        client.get_connection(1)

    assert not isinstance(exc_info.value, DrataResponseError)
    assert "get_connection" in str(exc_info.value) or "/custom-connections/1" in str(exc_info.value)


def test_count_record_outcomes_counts_created_and_updated():
    body = {
        "data": [
            {"id": "a", "statusCode": 201},
            {"id": "b", "statusCode": 200},
            {"id": "c", "statusCode": 201},
            {"id": "d", "statusCode": 200},
            {"id": "e", "statusCode": 200},
        ]
    }
    created, updated = count_record_outcomes(body)
    assert created == 2
    assert updated == 3


def test_count_record_outcomes_unrecognized_shape_returns_zero_zero():
    assert count_record_outcomes({"summary": "ok"}) == (0, 0)
    assert count_record_outcomes(None) == (0, 0)
    assert count_record_outcomes([]) == (0, 0)


@responses.activate
def test_upload_session_batch_logs_warning_on_unrecognized_response_shape(caplog):
    import logging as _logging

    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1",
        json={"summary": "accepted, no per-record detail"},
        status=200,
    )
    client = make_client()
    with caplog.at_level(_logging.WARNING, logger="nessus_drata.drata_client"):
        client.upload_session_batch(1, 2, "sess-1", [{"id": "host-1"}])
    assert any("did not match any recognized per-record shape" in r.message for r in caplog.records)


@responses.activate
def test_timeout_is_wrapped_as_drata_api_error_not_bare_exception():
    import requests

    responses.add(
        responses.POST,
        f"{BASE_URL}/public/v2/custom-connections/1/resources/2/sessions/sess-1/actions",
        body=requests.exceptions.ConnectTimeout("simulated timeout"),
    )
    client = make_client()

    with pytest.raises(DrataApiError):
        client.complete_session(1, 2, "sess-1")
