import json
from pathlib import Path

from rich.console import Console

from dbugs_cli import formatters
from dbugs_cli.models import (
    NewsList,
    Stats,
    TrendList,
    VulnDetail,
    VulnList,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _fx(name):
    return json.loads((FIXTURES / name).read_text())


def _text(renderable) -> str:
    console = Console(width=200, force_terminal=False)
    with console.capture() as cap:
        console.print(renderable)
    return cap.get()


def test_severity_style_maps_known_levels():
    assert formatters.severity_style("CRITICAL") == "bold red"
    assert formatters.severity_style("LOW") == "green"
    assert formatters.severity_style(None) == "dim"


def test_render_stats_contains_totals():
    out = _text(formatters.render_stats(Stats.from_dict(_fx("stats.json"))))
    assert "392506" in out or "392,506" in out


def test_render_vuln_list_shows_ids_and_severity():
    out = _text(formatters.render_vuln_list(VulnList.from_dict(_fx("vuln_list.json"))))
    assert "PT-2026-61063" in out
    assert "CRITICAL" in out


def test_render_vuln_detail_shows_references():
    out = _text(formatters.render_vuln_detail(VulnDetail.from_dict(_fx("vuln_detail.json"))))
    assert "vuldb.com" in out
    assert "CWE-79" in out


def test_render_trends_shows_posts_count():
    out = _text(formatters.render_trends(TrendList.from_dict(_fx("trending.json"))))
    assert "PT-2026-53941" in out
    row_line = next(line for line in out.splitlines() if "PT-2026-53941" in line)
    cells = [c.strip() for c in row_line.split("│") if c.strip()]
    # Last populated cell in the row is the Posts column; must be the
    # fixture's posts_count (5), not a coincidental "5" from the CVE id or date.
    assert cells[-1] == "5"


def test_render_posts_shows_text():
    out = _text(formatters.render_posts({"count": 1, "rows": [
        {"url": "https://x", "text": "hello world", "published": "2026-07-18"}]}))
    assert "hello world" in out


def test_render_news_list_shows_title():
    out = _text(formatters.render_news_list(NewsList.from_dict(_fx("news_list.json"))))
    assert "Critical bug in Widget" in out


def test_render_researcher_shows_name():
    out = _text(formatters.render_researcher(
        {"researcher": {"name": "alice", "vulner_count": 12}, "author_count": 3,
         "critical_severity": 1, "high_severity": 2, "medium_severity": 0,
         "low_severity": 0, "null_severity": 0, "x_link": None,
         "github_link": None, "linkedin_link": None}))
    assert "alice" in out
