import json
from pathlib import Path

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
def test_request_maps_non_json_200_to_api_error():
    respx.get(f"{DEFAULT_BASE_URL}stats").mock(
        return_value=httpx.Response(200, text="<html>blocked</html>")
    )
    client = DbugsClient()
    with pytest.raises(DbugsAPIError) as exc:
        client._request("GET", "stats")

    assert exc.value.status == 200


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


FIXTURES = Path(__file__).parent / "fixtures"


def _fx(name):
    return json.loads((FIXTURES / name).read_text())


@respx.mock
def test_stats_returns_model():
    respx.get(f"{DEFAULT_BASE_URL}stats").mock(
        return_value=httpx.Response(200, json=_fx("stats.json"))
    )
    s = DbugsClient().stats()
    assert s.total_vulnerabilities == 392506


@respx.mock
def test_search_vulns_builds_body_and_drops_none():
    route = respx.post(f"{DEFAULT_BASE_URL}vulnerabilities").mock(
        return_value=httpx.Response(200, json=_fx("vuln_list.json"))
    )
    vl = DbugsClient().search_vulns(
        fts="apache", vendor=["microsoft"], severity=["CRITICAL"],
        score_from=9.0, has_exploit=True, sort="max_score", descending=True,
        limit=10, page=2,
    )
    assert vl.count == 392506
    assert vl.rows[0].vulner_id == "PT-2026-61063"

    body = json.loads(route.calls.last.request.content)
    assert body["layer"] == "catalog"
    assert body["fts"] == "apache"
    assert body["vendor"] == ["microsoft"]
    assert body["severity"] == ["CRITICAL"]
    assert body["score_from"] == 9.0
    assert body["has_exploits"] is True
    assert body["sorts"] == [{"field": "max_score", "reversed": True}]
    assert body["limit"] == 10 and body["page"] == 2
    assert "product" not in body  # None args dropped
    assert "score_to" not in body


@respx.mock
def test_get_vuln_passes_fts_and_locale():
    route = respx.get(f"{DEFAULT_BASE_URL}vulnerabilities/PT-2026-61063").mock(
        return_value=httpx.Response(200, json=_fx("vuln_detail.json"))
    )
    d = DbugsClient().get_vuln("PT-2026-61063", fts="widget")
    assert d.vuln.max_severity == "CRITICAL"
    assert len(d.references) == 2
    assert dict(route.calls.last.request.url.params) == {"locale": "en", "fts": "widget"}


@respx.mock
def test_trends_returns_trendlist():
    respx.get(f"{DEFAULT_BASE_URL}trending").mock(
        return_value=httpx.Response(200, json=_fx("trending.json"))
    )
    tl = DbugsClient().trends()
    assert tl.rows[0].vuln.severity == "HIGH"


@respx.mock
def test_trend_posts_returns_raw_dict():
    respx.get(f"{DEFAULT_BASE_URL}trending/PT-1/posts").mock(
        return_value=httpx.Response(200, json={"count": 1, "rows": [
            {"url": "https://x", "text": "hi", "published": "2026-07-18"}]})
    )
    posts = DbugsClient().trend_posts("PT-1", limit=2)
    assert posts["rows"][0]["text"] == "hi"


@respx.mock
def test_news_returns_newslist():
    respx.post(f"{DEFAULT_BASE_URL}news/").mock(
        return_value=httpx.Response(200, json=_fx("news_list.json"))
    )
    nl = DbugsClient().news(limit=5)
    assert nl.rows[0].slug == "critical-widget"


@respx.mock
def test_researcher_returns_raw_dict():
    respx.get(f"{DEFAULT_BASE_URL}researchers/alice").mock(
        return_value=httpx.Response(200, json={"researcher": {"name": "alice"},
                                               "author_count": 3})
    )
    r = DbugsClient().researcher("alice")
    assert r["author_count"] == 3


@respx.mock
def test_news_builds_filtered_body_and_drops_none():
    route = respx.post(f"{DEFAULT_BASE_URL}news/").mock(
        return_value=httpx.Response(200, json=_fx("news_list.json"))
    )
    nl = DbugsClient().news(
        fts="wordpress", product=["Wordpress"], vendor=["Microsoft"],
        cve_id=["CVE-2026-63030"], category=["cve"],
        published_from="2026-07-01", published_to="2026-07-20",
        limit=5, page=2,
    )
    assert nl.rows[0].slug == "critical-widget"
    body = json.loads(route.calls.last.request.content)
    assert body["fts"] == "wordpress"
    assert body["product"] == ["Wordpress"]
    assert body["vendor"] == ["Microsoft"]
    assert body["cve_id"] == ["CVE-2026-63030"]
    assert body["category"] == ["cve"]
    assert body["published_from"] == "2026-07-01"
    assert body["published_to"] == "2026-07-20"
    assert body["limit"] == 5 and body["page"] == 2
    assert "researcher" not in body  # None dropped


@respx.mock
def test_suggest_products_with_pattern_hits_search_path():
    route = respx.get(f"{DEFAULT_BASE_URL}news/products").mock(
        return_value=httpx.Response(200, json=["Wordpress", "Microsoft Word"])
    )
    result = DbugsClient().suggest_products("word")
    assert result == ["Wordpress", "Microsoft Word"]
    assert dict(route.calls.last.request.url.params) == {"search_pattern": "word"}


@respx.mock
def test_suggest_products_without_pattern_hits_popular():
    respx.get(f"{DEFAULT_BASE_URL}news/products/popular").mock(
        return_value=httpx.Response(200, json=["Windows", "Android"])
    )
    assert DbugsClient().suggest_products() == ["Windows", "Android"]


@respx.mock
def test_suggest_vendors_paths():
    respx.get(f"{DEFAULT_BASE_URL}news/vendors").mock(
        return_value=httpx.Response(200, json=["Microsoft"])
    )
    respx.get(f"{DEFAULT_BASE_URL}news/vendors/popular").mock(
        return_value=httpx.Response(200, json=["Google"])
    )
    assert DbugsClient().suggest_vendors("micro") == ["Microsoft"]
    assert DbugsClient().suggest_vendors() == ["Google"]
