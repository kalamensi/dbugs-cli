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
