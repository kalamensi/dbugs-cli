"""Opt-in tests that hit the real dbugs API. Run with DBUGS_LIVE=1 pytest."""
import os

import pytest

from dbugs_cli.client import DbugsClient

pytestmark = pytest.mark.skipif(
    os.environ.get("DBUGS_LIVE") != "1",
    reason="set DBUGS_LIVE=1 to run live API tests",
)


@pytest.fixture(scope="module")
def client():
    c = DbugsClient()
    yield c
    c.close()


def test_live_stats(client):
    s = client.stats()
    assert s.total_vulnerabilities > 0


def test_live_search(client):
    vl = client.search_vulns(fts="apache", limit=2)
    assert vl.count > 0
    assert len(vl.rows) <= 2


def test_live_detail_has_references(client):
    vl = client.search_vulns(limit=1)
    detail = client.get_vuln(vl.rows[0].vulner_id)
    assert detail.vuln.vulner_id == vl.rows[0].vulner_id
    assert isinstance(detail.references, list)


def test_live_trends(client):
    tl = client.trends()
    assert len(tl.rows) > 0


def test_live_news_filtered_by_product(client):
    nl = client.news(product=["Wordpress"], limit=3)
    assert nl.count >= 0
    assert len(nl.rows) <= 3


def test_live_suggest_products(client):
    items = client.suggest_products("word")
    assert isinstance(items, list)
    assert any("word" in s.lower() for s in items)


def test_live_suggest_popular(client):
    items = client.suggest_vendors()
    assert isinstance(items, list) and len(items) > 0
