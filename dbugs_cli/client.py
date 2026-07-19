"""HTTP client for the dbugs.ptsecurity.com /v1 API.

This is the only module that touches HTTP. It injects the browser headers
required to pass the QRATOR anti-bot layer.
"""
from __future__ import annotations

from typing import Any

import httpx

DEFAULT_BASE_URL = "https://dbugs.ptsecurity.com/v1/"
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
DEFAULT_REFERER = "https://dbugs.ptsecurity.com/"


class DbugsAPIError(Exception):
    """Raised when the dbugs API is unreachable or returns an error status."""

    def __init__(self, status: int | None, reason: str, details: list | None = None):
        self.status = status
        self.reason = reason
        self.details = details
        super().__init__(self._message())

    def _message(self) -> str:
        if self.status is None:
            return f"Could not reach dbugs API: {self.reason}"
        return f"dbugs API error {self.status}: {self.reason}"


class DbugsClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        locale: str = "en",
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ):
        self.locale = locale
        self._client = client or httpx.Client(
            base_url=base_url,
            timeout=timeout,
            headers={
                "User-Agent": DEFAULT_UA,
                "Referer": DEFAULT_REFERER,
                "Accept": "application/json",
            },
        )
        # Ensure the QRATOR-bypass headers are present unconditionally, even
        # when a caller injects a pre-built httpx.Client.
        #
        # NOTE: httpx.Client() always pre-populates its own "User-Agent"
        # (e.g. "python-httpx/0.28.1") and "Accept" ("*/*") headers, even
        # when no headers are passed to its constructor — only "Referer" is
        # left unset. That means headers.setdefault() would silently keep
        # httpx's own User-Agent/Accept on an injected client and never
        # apply ours, defeating the whole point of this transport layer
        # (the Global Constraint requires the exact browser User-Agent and
        # Referer on every request or the real API 403s). So User-Agent and
        # Referer are force-set unconditionally here. Accept is applied with
        # setdefault since it is a convenience default, not part of the
        # anti-bot bypass, so an explicit caller preference is honored.
        self._client.headers["User-Agent"] = DEFAULT_UA
        self._client.headers["Referer"] = DEFAULT_REFERER
        self._client.headers.setdefault("Accept", "application/json")

    def close(self) -> None:
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> Any:
        try:
            resp = self._client.request(method, path, params=params, json=json_body)
        except httpx.TransportError as exc:
            raise DbugsAPIError(status=None, reason=str(exc)) from exc

        if resp.status_code >= 400:
            reason: str
            details = None
            try:
                payload = resp.json()
                reason = payload.get("reason") or f"HTTP {resp.status_code}"
                details = payload.get("details")
            except Exception:
                reason = resp.text.strip() or f"HTTP {resp.status_code}"
            raise DbugsAPIError(resp.status_code, reason, details)

        return resp.json()
