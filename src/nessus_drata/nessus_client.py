from __future__ import annotations

import logging
import os
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_DOWNLOAD_CHUNK_SIZE = 1024 * 1024

_EXPORT_POLL_INITIAL_DELAY_SECONDS = 2
_EXPORT_POLL_INTERVAL_SECONDS = 3


class NessusApiError(Exception):
    pass


class NessusExportTimeoutError(NessusApiError):
    pass


def _redact_key(key: str) -> str:
    if not key or len(key) <= 4:
        return "****"
    return f"****{key[-4:]}"


class NessusClient:
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
        self._session.headers["X-ApiKeys"] = (
            f"accessKey={access_key}; secretKey={secret_key}"
        )

        if self._verify_tls:
            self._verify = self._ca_bundle if self._ca_bundle else True
        else:
            self._verify = False

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _warn_if_tls_disabled(self, path: str) -> None:
        if not self._verify_tls:
            logger.warning(
                "TLS verification is DISABLED for this Nessus API call "
                "(verify_tls=false) do not use in production.",
                path,
            )

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
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

    def server_status(self) -> dict:
        return self._get_json("/server/status")

    def list_scans(self, folder_id: Optional[int] = None) -> dict:
        path = "/scans"
        if folder_id is not None:
            path = f"/scans?folder_id={folder_id}"
        return self._get_json(path)

    def get_scan(self, scan_id: int) -> dict:
        return self._get_json(f"/scans/{scan_id}")

    def request_export(
        self,
        scan_id: int,
        export_format: str = "nessus",
        history_id: Optional[int] = None,
    ) -> dict:
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
        return self._get_json(f"/scans/{scan_id}/export/{file_id}/status")

    def download_export(self, scan_id: int, file_id, dest_path) -> None:
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

    def wait_for_export_ready(
        self, scan_id: int, file_id, timeout_seconds: int = 900
    ) -> None:
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
