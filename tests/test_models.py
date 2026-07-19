from dbugs_cli.models import (
    Reference,
    Stats,
    Trend,
    TrendList,
    Vuln,
    VulnDetail,
    VulnList,
    NewsList,
)


def test_stats_from_dict():
    s = Stats.from_dict({"total_vulnerabilities": 10, "new_this_week": 2, "authors": 3})
    assert (s.total_vulnerabilities, s.new_this_week, s.authors) == (10, 2, 3)
    assert s.raw["authors"] == 3


def test_vuln_list_from_dict_parses_rows():
    data = {
        "count": 2,
        "rows": [
            {"vulner_id": "PT-1", "cve_id": "CVE-1", "max_score": 9.8,
             "max_severity": "CRITICAL", "created": "2026-01-01", "updated": "2026-01-02",
             "has_fix": True, "has_exploits": False,
             "vendors": ["acme"], "products": ["w"], "researchers": [{"name": "a"}]},
            {"vulner_id": "PT-2", "cve_id": None, "max_score": None,
             "max_severity": "NULL", "created": "2026-01-01", "updated": "2026-01-01",
             "has_fix": False, "has_exploits": True,
             "vendors": [], "products": [], "researchers": []},
        ],
    }
    vl = VulnList.from_dict(data)
    assert vl.count == 2
    assert isinstance(vl.rows[0], Vuln)
    assert vl.rows[0].vulner_id == "PT-1"
    assert vl.rows[1].cve_id is None


def test_vuln_detail_parses_references():
    data = {
        "vulner_id": "PT-1", "cve_id": "CVE-1", "max_score": 5.0, "max_severity": "MEDIUM",
        "created": "2026-01-01", "updated": "2026-01-01", "has_fix": False,
        "has_exploits": False, "vendors": [], "products": [], "researchers": [],
        "cwe_ids": ["CWE-79"], "impacts": [], "cvss": {"NVD": {}, "Mitre": {}},
        "references": [{"ref_url": "https://x", "domain": "x", "source": "Note",
                        "stars": 1, "forks": 0, "is_deleted": False}],
        "related_news": [], "duplicates": [],
    }
    d = VulnDetail.from_dict(data)
    assert d.vuln.vulner_id == "PT-1"
    assert d.cwe_ids == ["CWE-79"]
    assert isinstance(d.references[0], Reference)
    assert d.references[0].domain == "x"


def test_trend_list_uses_nested_score_keys():
    data = {"count": 1, "rows": [{
        "lvl": 1, "posts_count": 5,
        "vulnerability": {"vulner_id": "PT-9", "cve_id": "CVE-9", "score": 7.5,
                          "severity": "HIGH", "created": "2026-01-01", "updated": "2026-01-01",
                          "has_fix": True, "has_exploits": False, "vendors": [], "products": []},
    }]}
    tl = TrendList.from_dict(data)
    assert isinstance(tl.rows[0], Trend)
    assert tl.rows[0].posts_count == 5
    assert tl.rows[0].vuln.score == 7.5
    assert tl.rows[0].vuln.severity == "HIGH"


def test_news_list_from_dict():
    data = {"count": 1, "rows": [{
        "title": "T", "summary": "S", "slug": "t-slug", "category": "cve",
        "published": "2026-01-01", "body": "...",
        "cve_ids": ["CVE-1"], "vendors": ["v"], "products": ["p"], "vulners": [],
    }]}
    nl = NewsList.from_dict(data)
    assert nl.rows[0].slug == "t-slug"
    assert nl.rows[0].cve_ids == ["CVE-1"]
