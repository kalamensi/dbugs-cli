import httpx
import pytest
import respx

from dbugs_cli.client import (
    DEFAULT_BASE_URL,
    DEFAULT_REFERER,
    DEFAULT_UA,
    DbugsAPIError,
    DbugsClient,
)


@respx.mock
def test_request_sends_browser_headers_and_returns_json():
    route = respx.get(f"{DEFAULT_BASE_URL}stats").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    client = DbugsClient()
    result = client._request("GET", "stats")

    assert result == {"ok": True}
    sent = route.calls.last.request
    assert sent.headers["user-agent"] == DEFAULT_UA
    assert sent.headers["referer"] == DEFAULT_REFERER


@respx.mock
def test_request_maps_422_to_api_error_with_reason():
    respx.post(f"{DEFAULT_BASE_URL}vulnerabilities").mock(
        return_value=httpx.Response(
            422, json={"reason": "Validation error", "details": [{"x": 1}]}
        )
    )
    client = DbugsClient()
    with pytest.raises(DbugsAPIError) as exc:
        client._request("POST", "vulnerabilities", json_body={"bad": 1})

    assert exc.value.status == 422
    assert exc.value.reason == "Validation error"
    assert exc.value.details == [{"x": 1}]


@respx.mock
def test_request_maps_transport_error():
    respx.get(f"{DEFAULT_BASE_URL}stats").mock(side_effect=httpx.ConnectError("boom"))
    client = DbugsClient()
    with pytest.raises(DbugsAPIError) as exc:
        client._request("GET", "stats")

    assert exc.value.status is None
    assert "reach" in str(exc.value).lower()


@respx.mock
def test_injected_client_still_gets_browser_headers():
    route = respx.get(f"{DEFAULT_BASE_URL}stats").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    injected = httpx.Client(base_url=DEFAULT_BASE_URL)
    client = DbugsClient(client=injected)
    result = client._request("GET", "stats")

    assert result == {"ok": True}
    sent = route.calls.last.request
    assert sent.headers["user-agent"] == DEFAULT_UA
    assert sent.headers["referer"] == DEFAULT_REFERER
