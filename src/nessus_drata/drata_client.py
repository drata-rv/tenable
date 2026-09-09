"""Thin, authenticated HTTP client for the Drata public API v2.

Scope is deliberately bounded to raw authenticated HTTP calls plus generic
retry-on-429/5xx behavior (spec Section 5.4). Session-orchestration logic
("on 409, cancel the stale session and retry the whole upload") is a
higher-level workflow that belongs to a later build phase, not here.

Hard constraints enforced in this module (spec Section 2 / 5.1 / 5.6):
  * The ``Bearer`` prefix is hardcoded in __init__ and applied to every
    request via ``session.headers``. Callers never supply a pre-formatted
    Authorization header and cannot override it via a `headers=` kwarg.
  * The raw api_key value never appears in any exception message or log
    line -- only its last 4 characters, prefixed with ``****``.
  * On HTTP 401 with body ``{"code": 10000, ...}`` the Section 5.6
    diagnostic checklist is printed verbatim to stderr before raising.
"""

from __future__ import annotations

import json
import logging
import random
import sys
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# Section 5.6 checklist, printed verbatim to stderr on 401 code 10000.
DRATA_401_10000_CHECKLIST = """\
Drata returned 401 (code 10000). All API-key auth failures collapse into this
code, so check each cause in order:
  1. Authorization header must read "Bearer <key>". A bare key returns this exact error.
  2. Key revoked.
  3. Key expired.
  4. Source IP not in the key's allowed-IP list.
  5. Key lacks Custom Connections Data scopes (Create, Create and Update, Delete).
A different connection returning 403 instead of 401 indicates the key itself is
valid and the problem is scope or connection ownership, not authentication.
"""

_RETRYABLE_STATUS_CODES = {429}
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0
_BACKOFF_JITTER_SECONDS = 0.5


class DrataApiError(Exception):
    """Base class for any unrecoverable Drata API error. Maps to exit code 4
    in the CLI (mapping happens in a later phase, not here)."""


class DrataResponseError(DrataApiError):
    def __init__(self, message, *, status_code=None, error_code=None, response_body=None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.response_body = response_body


def _redact_key(api_key: str) -> str:
    """Redact an API key to its last 4 characters, e.g. '****abcd'. A key at
    or under 4 characters is masked completely rather than shown in full.
    """
    if not api_key or len(api_key) <= 4:
        return "****"
    return f"****{api_key[-4:]}"


def _is_server_error(status_code: int) -> bool:
    return 500 <= status_code < 600


def _parse_json(response: requests.Response) -> Any:
    """Best-effort JSON parse. Returns None if the body is empty or not JSON --
    callers must treat that as "no structured body available", never as a
    reason to crash while classifying a response."""
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _find_error_code(body: Any) -> Optional[int]:
    """Pull Drata's numeric `code` field out of a parsed error body, if present."""
    if isinstance(body, dict):
        code = body.get("code")
        if isinstance(code, int):
            return code
    return None


def _format_body_for_message(body: Any, max_chars: int = 500) -> str:
    """Compact, truncated stringification of a response body for inclusion
    directly in an exception message. response_body is already attached as
    an exception attribute for programmatic access, but str(exc) previously
    dropped it entirely -- forcing anyone debugging a failure to manually
    replicate the HTTP call just to see what Drata actually said. Every
    raise site below now includes this in the message text itself.
    """
    if body is None:
        return "(empty response body)"
    try:
        text = json.dumps(body, separators=(",", ":"))
    except (TypeError, ValueError):
        text = str(body)
    if len(text) > max_chars:
        text = text[:max_chars] + "...(truncated)"
    return text


def _extract_offending_record(body: Any) -> Optional[str]:
    """Best-effort extraction of an offending record id/field for error messages.
    Never raises -- returns None when the shape is unrecognized."""
    if body is None:
        return None
    try:
        if isinstance(body, dict):
            for key in ("id", "recordId", "field"):
                if key in body:
                    return f"{key}={body[key]!r}"
            for key in ("message", "error", "errors"):
                if key in body:
                    return f"{key}={body[key]!r}"
        elif isinstance(body, list) and body:
            first = body[0]
            if isinstance(first, dict):
                for key in ("id", "recordId"):
                    if key in first:
                        return f"{key}={first[key]!r}"
    except Exception:
        return None
    return None


def _iter_record_results(body: Any):
    """Yield (index, record_result_dict) for a per-record response body, handling
    the documented shapes defensively:
      * a bare list of per-record result dicts
      * a dict with the list under "data" or "results"
    Yields nothing for any other shape -- an unrecognized shape here is not
    treated as a per-record failure, only a genuinely present statusCode >= 400
    is."""
    items = None
    if isinstance(body, list):
        items = body
    elif isinstance(body, dict):
        for key in ("data", "results"):
            value = body.get(key)
            if isinstance(value, list):
                items = value
                break
    if not items:
        return
    for index, item in enumerate(items):
        if isinstance(item, dict):
            yield index, item


def count_record_outcomes(body: Any) -> tuple[int, int]:
    """Count per-record outcomes in a session-batch/upsert response body:
    (created_count, updated_count), per spec Section 5.4 (201=created,
    200=updated). Unrecognized shapes or entries without a recognized
    statusCode contribute to neither count -- this is an observability
    helper for the run report, not a correctness gate (that's
    _check_per_record_failures's job).
    """
    created = 0
    updated = 0
    for _index, item in _iter_record_results(body):
        status_code = item.get("statusCode")
        if status_code == 201:
            created += 1
        elif status_code == 200:
            updated += 1
    return created, updated


class DrataClient:
    """Authenticated HTTP client for the Drata public API v2.

    All paths use the ``/public/v2`` prefix -- never the legacy non-v2 path,
    which carries a known auth-guard bug (spec Section 5, "Base URL").
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        max_retries: int = 5,
        connect_timeout: float = 10,
        read_timeout: float = 30,
    ):
        self._base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._timeout = (connect_timeout, read_timeout)
        self._redacted_key = _redact_key(api_key)

        self._session = requests.Session()
        # Bearer prefix hardcoded here. Callers never supply Authorization
        # directly and per-request headers passed to _request() are merged
        # on top of session.headers by requests -- but _request() never
        # accepts a headers kwarg from callers, so nothing can clobber this.
        self._session.headers["Authorization"] = f"Bearer {api_key}"
        self._session.headers["Content-Type"] = "application/json"

    # -- internal request machinery -----------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _sleep_for_attempt(self, attempt: int, response: Optional[requests.Response]) -> None:
        """Sleep before the next retry attempt. Honors Retry-After (seconds) on
        a 429 if present; otherwise falls back to exponential backoff with
        jitter, capped at _BACKOFF_MAX_SECONDS."""
        delay = None
        if response is not None:
            retry_after = response.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    delay = float(int(retry_after))
                except (TypeError, ValueError):
                    delay = None
        if delay is None:
            computed = _BACKOFF_BASE_SECONDS * (2 ** attempt)
            delay = min(computed, _BACKOFF_MAX_SECONDS) + random.uniform(0, _BACKOFF_JITTER_SECONDS)
        time.sleep(delay)

    def _request(self, method: str, path: str, *, json_body: Optional[dict] = None) -> requests.Response:
        """Issue one HTTP request, retrying on 429/5xx up to max_retries total
        attempts. Returns the final requests.Response (which may still be an
        error response after the classifier below decides what to do with it).
        Never accepts caller-supplied headers -- the auth header is fixed at
        __init__ time.

        Connection-level failures (DNS, refused connection, TLS handshake,
        timeout before any response) are not in the spec's 429/5xx retry
        table, so -- mirroring nessus_client.py's identical choice for the
        same class of error -- they are wrapped as DrataApiError immediately,
        not retried and not left to leak out as a bare requests exception
        (which would misclassify a Drata connectivity failure as exit code 1
        "unexpected error" instead of exit code 4 "Drata API error").
        """
        url = self._url(path)
        attempt = 0
        last_response: Optional[requests.Response] = None

        while attempt < self._max_retries:
            try:
                response = self._session.request(
                    method,
                    url,
                    json=json_body,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                raise DrataApiError(f"Drata API request failed: {method} {path}: {exc}") from exc
            last_response = response

            if response.status_code in _RETRYABLE_STATUS_CODES or _is_server_error(response.status_code):
                attempt += 1
                if attempt >= self._max_retries:
                    break
                self._sleep_for_attempt(attempt, response)
                continue

            return response

        return last_response

    def _classify_and_raise_if_error(self, response: requests.Response) -> Any:
        """Given a final (post-retry) response, return parsed JSON on success or
        raise DrataResponseError per the Section 5.4 table."""
        status = response.status_code
        body = _parse_json(response)
        body_detail = _format_body_for_message(body)

        if status in (200, 201):
            return body
        if status == 204:
            return body if body is not None else {}

        if status == 401:
            error_code = _find_error_code(body)
            if error_code == 10000:
                sys.stderr.write(DRATA_401_10000_CHECKLIST)
                sys.stderr.flush()
                raise DrataResponseError(
                    "Drata 401: auth rejected before resource logic (code 10000). "
                    "See diagnostic checklist printed to stderr. "
                    f"key={self._redacted_key}",
                    status_code=401,
                    error_code=10000,
                    response_body=body,
                )
            if error_code == 12310:
                raise DrataResponseError(
                    f"Drata 401: API key not found (code 12310). key={self._redacted_key} "
                    f"body={body_detail}",
                    status_code=401,
                    error_code=12310,
                    response_body=body,
                )
            if error_code == 26430:
                raise DrataResponseError(
                    f"Drata 401: no Authorization header sent (code 26430). "
                    f"key={self._redacted_key} body={body_detail}",
                    status_code=401,
                    error_code=26430,
                    response_body=body,
                )
            raise DrataResponseError(
                f"Drata 401: auth rejected (code {error_code}). key={self._redacted_key} "
                f"body={body_detail}",
                status_code=401,
                error_code=error_code,
                response_body=body,
            )

        if status == 400:
            offending = _extract_offending_record(body)
            detail = f" ({offending})" if offending else ""
            raise DrataResponseError(
                f"Drata 400: schema validation failure{detail}. body={body_detail}",
                status_code=400,
                response_body=body,
            )

        if status == 403:
            raise DrataResponseError(
                "Drata 403: key valid but not authorized for this connection "
                f"(check scopes and connection ownership). body={body_detail}",
                status_code=403,
                response_body=body,
            )

        if status == 409:
            raise DrataResponseError(
                "Drata 409: session state conflict. Caller must cancel the "
                f"stale session and retry -- not handled in this module. body={body_detail}",
                status_code=409,
                response_body=body,
            )

        if status == 429:
            raise DrataResponseError(
                f"Drata 429: rate limited, retries exhausted. body={body_detail}",
                status_code=429,
                response_body=body,
            )

        if _is_server_error(status):
            raise DrataResponseError(
                f"Drata {status}: server error, retries exhausted. body={body_detail}",
                status_code=status,
                response_body=body,
            )

        # Any other 4xx not explicitly listed above.
        raise DrataResponseError(
            f"Drata {status}: unspecified client error. body={body_detail}",
            status_code=status,
            response_body=body,
        )

    def _check_per_record_failures(self, body: Any) -> None:
        """Inspect a session-batch/upsert response body for per-record failures.
        A 200-level HTTP response can still contain individually rejected
        records -- that must not be silently treated as success."""
        saw_any = False
        for index, item in _iter_record_results(body):
            saw_any = True
            status_code = item.get("statusCode")
            if isinstance(status_code, int) and status_code >= 400:
                record_id = item.get("id", f"index={index}")
                raise DrataResponseError(
                    f"Drata session batch: record {record_id!r} rejected with "
                    f"statusCode {status_code}.",
                    status_code=status_code,
                    response_body=item,
                )
        if not saw_any and body:
            # The response body is non-empty but doesn't match any of the
            # three recognized per-record shapes (list, {"data":[...]},
            # {"results":[...]}) -- this assumption about Drata's real
            # response shape is unverified against a live sandbox (see
            # cli.py's own UNVERIFIED comments on the live push path).
            # Surface that loudly rather than silently treating "we
            # couldn't check" the same as "we checked and it passed".
            logger.warning(
                "session batch/upsert response body did not match any "
                "recognized per-record shape -- individual record success "
                "could not be verified. body=%r",
                body,
            )

    # -- public API -----------------------------------------------------

    def get_connection(self, connection_id: int) -> dict:
        """GET /public/v2/custom-connections/{connection_id}?expand[]=customResources"""
        path = f"/public/v2/custom-connections/{connection_id}?expand[]=customResources"
        response = self._request("GET", path)
        return self._classify_and_raise_if_error(response)

    def list_sessions(self, connection_id: int, resource_id: int, status: str = "IN_PROGRESS") -> list:
        """GET /public/v2/custom-connections/{connection_id}/resources/{resource_id}/sessions?status={status}

        Handles the response shape defensively: a bare list, a dict with a
        "data" or "sessions" list, or (if neither) returns an empty list
        rather than raising. A status-filtered listing endpoint returning an
        unexpected shape is not the same class of error as an auth failure.
        """
        path = (
            f"/public/v2/custom-connections/{connection_id}/resources/"
            f"{resource_id}/sessions?status={status}"
        )
        response = self._request("GET", path)
        body = self._classify_and_raise_if_error(response)

        if isinstance(body, list):
            return body
        if isinstance(body, dict):
            for key in ("data", "sessions"):
                value = body.get(key)
                if isinstance(value, list):
                    return value
        return []

    def cancel_session(self, connection_id: int, resource_id: int, session_id: str) -> None:
        """POST .../sessions/{session_id}/actions body {"action": "cancel"}"""
        path = (
            f"/public/v2/custom-connections/{connection_id}/resources/"
            f"{resource_id}/sessions/{session_id}/actions"
        )
        response = self._request("POST", path, json_body={"action": "cancel"})
        self._classify_and_raise_if_error(response)

    def complete_session(self, connection_id: int, resource_id: int, session_id: str) -> None:
        """POST .../sessions/{session_id}/actions body {"action": "complete"}"""
        path = (
            f"/public/v2/custom-connections/{connection_id}/resources/"
            f"{resource_id}/sessions/{session_id}/actions"
        )
        response = self._request("POST", path, json_body={"action": "complete"})
        self._classify_and_raise_if_error(response)

    def upload_session_batch(
        self, connection_id: int, resource_id: int, session_id: str, records: list
    ) -> dict:
        """POST .../sessions/{session_id} body {"data": records}

        Also inspects the response body for per-record statusCode >= 400
        entries and raises DrataResponseError if any are found, even though
        the outer HTTP response was 200-level.
        """
        path = (
            f"/public/v2/custom-connections/{connection_id}/resources/"
            f"{resource_id}/sessions/{session_id}"
        )
        response = self._request("POST", path, json_body={"data": records})
        body = self._classify_and_raise_if_error(response)
        self._check_per_record_failures(body)
        return body

    def upsert_records(self, connection_id: int, resource_id: int, records: list) -> dict:
        """POST .../records body {"data": records}

        Direct upsert fallback for `drata.use_sessions: false` / single-record
        smoke tests. Same per-record statusCode inspection as
        upload_session_batch.
        """
        path = f"/public/v2/custom-connections/{connection_id}/resources/{resource_id}/records"
        response = self._request("POST", path, json_body={"data": records})
        body = self._classify_and_raise_if_error(response)
        self._check_per_record_failures(body)
        return body
