"""Read-only HTTP client for the Tenable Nessus Professional on-prem API.

Scope is deliberately bounded to exactly six methods, all of them read-only
except one export *request* (which itself only asks for a results package
that already exists -- it never launches, modifies, or deletes a scan):

    server_status, list_scans, get_scan, request_export, export_status,
    download_export

and one higher-level bounded-polling helper built on top of export_status:

    wait_for_export_ready

The absence of any launch/stop/kill/pause/resume/create/configure/delete/
import method is the actual safety guardrail described in spec Section 2 #1
and Section 8 -- do not add a generic ``_request(method, path)`` helper that
a future caller could point at a mutating endpoint, and do not add any method
beyond the six-plus-one above "for completeness".

Hard constraints enforced in this module (spec Section 2 / 3.1 / 3.3 / 9.6):
  * Auth is the stateless ``X-ApiKeys`` header, built once in __init__ and
    applied to every request via ``requests.Session`` headers. The
    session-token ``/session`` + ``X-Cookie`` flow is deliberately not used.
  * ``request_export`` sends its body via ``json=``, never ``data=`` -- the
    form-encoded body is silently accepted by Nessus but yields the wrong
    (default-shaped) report. This is the single highest-value behavior in
    this module.
  * TLS verification defaults on. ``verify_tls=False`` is an explicit escape
    hatch that logs a loud warning on *every* call (not once at startup) and
    never globally suppresses urllib3's InsecureRequestWarning.
  * The raw access_key/secret_key values never appear in any exception
    message or log line -- only their last 4 characters, prefixed ``****``.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_DOWNLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MB, per spec Section 3.2 / 8.

_EXPORT_POLL_INITIAL_DELAY_SECONDS = 2
_EXPORT_POLL_INTERVAL_SECONDS = 3


class NessusApiError(Exception):
    """Base class for any unrecoverable Nessus API error. Maps to exit code 3
    in the CLI (mapping happens in a later phase, not here)."""


class NessusExportTimeoutError(NessusApiError):
    """Raised by wait_for_export_ready when the timeout ceiling is hit before
    the export reaches status "ready"."""


def _redact_key(key: str) -> str:
    """Redact a credential to its last 4 characters, e.g. '****abcd'. Never
    let a raw access_key/secret_key value reach an exception message or log
    line (spec Section 2 #6 / 6.4). A credential at or under 4 characters is
    masked completely rather than shown in full.
    """
    if not key or len(key) <= 4:
        return "****"
    return f"****{key[-4:]}"


class NessusClient:
    """Authenticated HTTP client for the Tenable Nessus Professional API.

    Read-only by construction: the public surface is exactly the six raw
    methods documented at module level, plus the ``wait_for_export_ready``
    polling helper. Nothing here can launch, stop, kill, pause, resume,
    create, configure, delete, or import a scan.
    """

    def __init__(
        self,
        base_url: str,
        access_key: str,
        secret_key: str,
        verify_tls: bool = True,
        ca_bundle: Optional[str] = None,
        connect_timeout: float = 10,
        read_timeout: float = 120,
    ):
        self._base_url = base_url.rstrip("/")
        self._verify_tls = verify_tls
        self._ca_bundle = ca_bundle
        self._timeout = (connect_timeout, read_timeout)
        self._redacted_access_key = _redact_key(access_key)
        self._redacted_secret_key = _redact_key(secret_key)

        self._session = requests.Session()
        # Built once, applied to every request via session.headers. Never the
        # session-token /session + X-Cookie flow (spec Section 3.1).
        self._session.headers["X-ApiKeys"] = (
            f"accessKey={access_key}; secretKey={secret_key}"
        )

        # Precompute the `verify` kwarg passed to every request (spec Section
        # 2 #7 / 9.6). verify_tls=False disables verification but must never
        # suppress urllib3's InsecureRequestWarning globally -- the warning
        # fires per-request from urllib3 itself; this client additionally
        # logs its own loud warning on every call in that mode.
        if self._verify_tls:
            self._verify = self._ca_bundle if self._ca_bundle else True
        else:
            self._verify = False

    # -- internal request machinery -----------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _warn_if_tls_disabled(self, path: str) -> None:
        if not self._verify_tls:
            logger.warning(
                "TLS verification is DISABLED for this Nessus API call "
                "(verify_tls=false) -- connection to %s is NOT verified "
                "and is vulnerable to interception. This is an explicit "
                "escape hatch (spec Section 2 #7 / 9.6); do not use in "
                "production without documented customer acknowledgement.",
                path,
            )

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Issue one HTTP request. Single attempt, no retry -- the spec does
        not describe a retry contract for Nessus (unlike drata_client.py)."""
        self._warn_if_tls_disabled(path)
        url = self._url(path)
        try:
            return self._session.request(
                method,
                url,
                timeout=self._timeout,
                verify=self._verify,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise NessusApiError(
                f"Nessus API request failed: {method} {path}: {exc}"
            ) from exc

    def _raise_for_status(self, response: requests.Response, path: str) -> None:
        if not (200 <= response.status_code < 300):
            raise NessusApiError(
                f"Nessus API error: {response.status_code} on {path}"
            )

    def _get_json(self, path: str) -> dict:
        response = self._request("GET", path)
        self._raise_for_status(response, path)
        return response.json()

    # -- public API: read-only, exactly six raw methods ------------------

    def server_status(self) -> dict:
        """GET /server/status -> {"code": 200, "status": "ready"}

        Returns the parsed body as-is. Does not raise on status != "ready" --
        that interpretation belongs to the probe-nessus CLI command.
        """
        return self._get_json("/server/status")

    def list_scans(self, folder_id: Optional[int] = None) -> dict:
        """GET /scans (optionally ?folder_id=<id>)

        Returns {"folders": [...], "scans": [...]} as-is. `scans` may
        literally be JSON null when no scans exist -- returned unchanged,
        never normalized to an empty list here (that is the caller's call).
        """
        path = "/scans"
        if folder_id is not None:
            path = f"/scans?folder_id={folder_id}"
        return self._get_json(path)

    def get_scan(self, scan_id: int) -> dict:
        """GET /scans/{scan_id} -> info plus history[]. Returned as-is."""
        return self._get_json(f"/scans/{scan_id}")

    def request_export(
        self,
        scan_id: int,
        export_format: str = "nessus",
        history_id: Optional[int] = None,
    ) -> dict:
        """POST /scans/{scan_id}/export -> {"file": <file_id>, "token": "..."}

        THE critical detail (spec Section 3.3): the body is sent via `json=`,
        never `data=`. Form-encoding is silently accepted by Nessus but
        yields a default-shaped report instead of the one actually
        requested -- a real, previously-hit production bug in this exact
        integration.
        """
        path = f"/scans/{scan_id}/export"
        if history_id is not None:
            path = f"{path}?history_id={history_id}"
        response = self._request(
            "POST",
            path,
            json={"format": export_format},
            headers={"Content-Type": "application/json"},
        )
        self._raise_for_status(response, path)
        return response.json()

    def export_status(self, scan_id: int, file_id) -> dict:
        """GET /scans/{scan_id}/export/{file_id}/status -> {"status": ...}

        Single-call status check, no polling logic here -- see
        wait_for_export_ready for the bounded polling loop.
        """
        return self._get_json(f"/scans/{scan_id}/export/{file_id}/status")

    def download_export(self, scan_id: int, file_id, dest_path) -> None:
        """GET /scans/{scan_id}/export/{file_id}/download, streamed to
        dest_path in 1 MB chunks. Never buffers the whole export in memory
        (spec Section 3.2 / 8)."""
        path = f"/scans/{scan_id}/export/{file_id}/download"
        response = self._request("GET", path, stream=True)
        self._raise_for_status(response, path)

        parent = os.path.dirname(dest_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK_SIZE):
                if chunk:
                    f.write(chunk)

    # -- bounded export-lifecycle polling (spec Section 3.4) -------------

    def wait_for_export_ready(
        self, scan_id: int, file_id, timeout_seconds: int = 900
    ) -> None:
        """Poll export_status with initial delay 2s, then fixed 3s interval,
        until status == "ready", enforcing a hard ceiling of timeout_seconds
        total elapsed wait.

        Never re-issues the export POST -- this only polls status. Any
        status other than "loading"/"ready" is treated as a terminal error
        and raises NessusApiError immediately, without further polling.
        """
        start = time.monotonic()
        time.sleep(_EXPORT_POLL_INITIAL_DELAY_SECONDS)

        while True:
            body = self.export_status(scan_id, file_id)
            status = body.get("status")

            if status == "ready":
                return

            if status != "loading":
                raise NessusApiError(
                    f"Nessus export entered terminal non-ready status "
                    f"{status!r} for scan_id={scan_id} file_id={file_id}"
                )

            elapsed = time.monotonic() - start
            if elapsed >= timeout_seconds:
                raise NessusExportTimeoutError(
                    f"Nessus export timed out after {timeout_seconds}s "
                    f"waiting for scan_id={scan_id} file_id={file_id} to "
                    f"become ready"
                )

            time.sleep(_EXPORT_POLL_INTERVAL_SECONDS)
