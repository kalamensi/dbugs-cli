from dbugs_cli.models import TrendList
from dbugs_cli.transform import filter_sort_trends


def _tl():
    return TrendList.from_dict({"count": 3, "rows": [
        {"lvl": 1, "posts_count": 10, "vulnerability": {"vulner_id": "A", "cve_id": "CVE-A",
            "score": 9.8, "severity": "CRITICAL"}},
        {"lvl": 2, "posts_count": 50, "vulnerability": {"vulner_id": "B", "cve_id": "CVE-B",
            "score": 5.0, "severity": "MEDIUM"}},
        {"lvl": 3, "posts_count": 2, "vulnerability": {"vulner_id": "C", "cve_id": "CVE-C",
            "score": None, "severity": None}},
    ]})


def test_min_score_filters_and_drops_none_scores():
    out = filter_sort_trends(_tl(), min_score=9.0)
    assert [t.vuln.vulner_id for t in out.rows] == ["A"]
    assert out.count == 1


def test_severity_filter_case_insensitive():
    out = filter_sort_trends(_tl(), severity=["critical", "medium"])
    assert {t.vuln.vulner_id for t in out.rows} == {"A", "B"}


def test_min_posts_filter():
    out = filter_sort_trends(_tl(), min_posts=10)
    assert {t.vuln.vulner_id for t in out.rows} == {"A", "B"}


def test_sort_by_posts_desc_and_asc():
    desc = filter_sort_trends(_tl(), sort="posts")
    assert [t.vuln.vulner_id for t in desc.rows] == ["B", "A", "C"]
    asc = filter_sort_trends(_tl(), sort="posts", descending=False)
    assert [t.vuln.vulner_id for t in asc.rows] == ["C", "A", "B"]


def test_sort_by_score_puts_none_last_when_desc():
    out = filter_sort_trends(_tl(), sort="score")
    assert [t.vuln.vulner_id for t in out.rows] == ["A", "B", "C"]


def test_sort_by_score_puts_none_first_when_asc():
    out = filter_sort_trends(_tl(), sort="score", descending=False)
    assert [t.vuln.vulner_id for t in out.rows] == ["C", "B", "A"]


def test_limit_truncates_after_sort():
    out = filter_sort_trends(_tl(), sort="posts", limit=1)
    assert [t.vuln.vulner_id for t in out.rows] == ["B"]
    assert out.count == 1


def test_rebuilds_raw_from_kept_rows():
    out = filter_sort_trends(_tl(), min_posts=10, sort="posts")
    assert out.raw["count"] == 2
    assert [r["vulnerability"]["vulner_id"] for r in out.raw["rows"]] == ["B", "A"]


def test_no_filters_keeps_all():
    out = filter_sort_trends(_tl())
    assert out.count == 3


from dbugs_cli.models import VulnDetail
from dbugs_cli.transform import filter_references


def _detail():
    return VulnDetail.from_dict({
        "vulner_id": "PT-1", "cve_id": "CVE-1",
        "references": [
            {"ref_url": "https://a", "domain": "a", "source": "Note"},
            {"ref_url": "https://b", "domain": "b", "source": "Exploit"},
            {"ref_url": "https://c", "domain": "c", "source": "Vendor Advisory"},
        ],
    })


def test_filter_references_none_returns_unchanged():
    d = _detail()
    assert filter_references(d, source=None) is d
    assert filter_references(d, source=[]) is d


def test_filter_references_exact_case_insensitive():
    out = filter_references(_detail(), source=["exploit"])
    assert [r.source for r in out.references] == ["Exploit"]
    # exact, not substring: "vendor" must NOT match "Vendor Advisory"
    assert filter_references(_detail(), source=["vendor"]).references == []


def test_filter_references_multiple_sources():
    out = filter_references(_detail(), source=["Note", "Vendor Advisory"])
    assert {r.source for r in out.references} == {"Note", "Vendor Advisory"}


def test_filter_references_narrows_raw():
    out = filter_references(_detail(), source=["Exploit"])
    assert [r["source"] for r in out.raw["references"]] == ["Exploit"]
    # untouched payload keys survive
    assert out.raw["vulner_id"] == "PT-1"
