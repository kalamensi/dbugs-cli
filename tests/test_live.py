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


def test_live_trends(client):
    tl = client.trends()
    assert len(tl.rows) > 0
