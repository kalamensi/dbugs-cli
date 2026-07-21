import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from dbugs_cli.cli import app
from dbugs_cli.client import DbugsAPIError
from dbugs_cli.models import NewsList, Stats, TrendList, VulnDetail, VulnList

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def _fx(name):
    return json.loads((FIXTURES / name).read_text())


def test_stats_command_renders_table():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.stats.return_value = Stats.from_dict(_fx("stats.json"))
        result = runner.invoke(app, ["stats"])
    assert result.exit_code == 0
    assert "392,506" in result.stdout


def test_vulns_command_json_flag_emits_raw():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.search_vulns.return_value = VulnList.from_dict(_fx("vuln_list.json"))
        result = runner.invoke(app, ["--json", "vulns", "--fts", "apache"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["count"] == 392506


def test_vulns_command_passes_filters_to_client():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.search_vulns.return_value = VulnList.from_dict(_fx("vuln_list.json"))
        runner.invoke(app, [
            "vulns", "--vendor", "microsoft", "--vendor", "apple",
            "--severity", "CRITICAL", "--min-score", "9", "--has-exploit",
            "--sort", "score", "--limit", "5",
        ])
        kwargs = mock_cls.return_value.search_vulns.call_args.kwargs
    assert kwargs["vendor"] == ["microsoft", "apple"]
    assert kwargs["severity"] == ["CRITICAL"]
    assert kwargs["score_from"] == 9.0
    assert kwargs["has_exploit"] is True
    assert kwargs["sort"] == "max_score"
    assert kwargs["limit"] == 5


def test_api_error_prints_to_stderr_and_exits_nonzero():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.stats.side_effect = DbugsAPIError(500, "boom")
        result = runner.invoke(app, ["stats"])
    assert result.exit_code == 1
    assert "boom" in result.stderr


def test_api_error_json_mode_emits_error_object():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.stats.side_effect = DbugsAPIError(500, "boom")
        result = runner.invoke(app, ["--json", "stats"])
    assert result.exit_code == 1
    assert json.loads(result.stdout) == {"error": "dbugs API error 500: boom"}


def test_unexpected_exception_is_caught_without_traceback():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.stats.side_effect = RuntimeError("kaboom")
        result = runner.invoke(app, ["stats"])
    assert result.exit_code == 1
    assert "kaboom" in result.stderr
    assert "Traceback" not in result.stderr


def test_invalid_sort_exits_nonzero():
    with patch("dbugs_cli.cli.DbugsClient"):
        result = runner.invoke(app, ["vulns", "--sort", "bogus"])
    assert result.exit_code != 0


def test_news_command_forwards_filters():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.news.return_value = NewsList.from_dict(_fx("news_list.json"))
        runner.invoke(app, [
            "news", "--fts", "wordpress", "--product", "Wordpress",
            "--vendor", "Microsoft", "--cve", "CVE-2026-63030",
            "--category", "cve", "--since", "2026-07-01", "--until", "2026-07-20",
            "--limit", "5",
        ])
        kwargs = mock_cls.return_value.news.call_args.kwargs
    assert kwargs["fts"] == "wordpress"
    assert kwargs["product"] == ["Wordpress"]
    assert kwargs["vendor"] == ["Microsoft"]
    assert kwargs["cve_id"] == ["CVE-2026-63030"]
    assert kwargs["category"] == ["cve"]
    assert kwargs["published_from"] == "2026-07-01"
    assert kwargs["published_to"] == "2026-07-20"
    assert kwargs["limit"] == 5


def _trends_fixture():
    return TrendList.from_dict({"count": 2, "rows": [
        {"lvl": 1, "posts_count": 5, "vulnerability": {"vulner_id": "A", "cve_id": "CVE-A",
            "score": 9.8, "severity": "CRITICAL"}},
        {"lvl": 2, "posts_count": 99, "vulnerability": {"vulner_id": "B", "cve_id": "CVE-B",
            "score": 4.0, "severity": "MEDIUM"}},
    ]})


def test_trends_command_applies_filter():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.trends.return_value = _trends_fixture()
        result = runner.invoke(app, ["trends", "--min-score", "9"])
    assert result.exit_code == 0
    # only row A (score 9.8) survives min-score 9; render_trends title shows the count
    assert "Trending vulnerabilities (1)" in result.stdout
    assert "CVE-A" in result.stdout
    assert "CVE-B" not in result.stdout


def test_trends_command_json_reflects_filter():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.trends.return_value = _trends_fixture()
        result = runner.invoke(app, ["--json", "trends", "--min-posts", "10"])
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["rows"][0]["vulnerability"]["vulner_id"] == "B"


def test_trends_command_valid_sort_exits_zero():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.trends.return_value = _trends_fixture()
        result = runner.invoke(app, ["trends", "--sort", "posts"])
    assert result.exit_code == 0


def test_trends_command_invalid_sort_exits_nonzero():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.trends.return_value = _trends_fixture()
        result = runner.invoke(app, ["trends", "--sort", "bogus"])
    assert result.exit_code != 0


def test_suggest_products_with_pattern():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.suggest_products.return_value = ["Wordpress"]
        result = runner.invoke(app, ["suggest", "products", "word"])
    assert result.exit_code == 0
    assert "Wordpress" in result.stdout
    assert mock_cls.return_value.suggest_products.call_args.args == ("word",)


def test_suggest_vendors_json():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.suggest_vendors.return_value = ["Microsoft", "Google"]
        result = runner.invoke(app, ["--json", "suggest", "vendors"])
    assert json.loads(result.stdout) == ["Microsoft", "Google"]


def test_suggest_invalid_field_errors():
    with patch("dbugs_cli.cli.DbugsClient"):
        result = runner.invoke(app, ["suggest", "bogus"])
    assert result.exit_code != 0


def test_vulns_export_jsonl_writes_all_pages(tmp_path):
    page1 = {"count": 3, "rows": [{"vulner_id": "A"}, {"vulner_id": "B"}]}
    page2 = {"count": 3, "rows": [{"vulner_id": "C"}]}
    out = tmp_path / "out.jsonl"
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.search_vulns.side_effect = [
            VulnList.from_dict(page1),
            VulnList.from_dict(page2),
        ]
        result = runner.invoke(app, ["vulns", "--fts", "x", "--export", str(out)])
    assert result.exit_code == 0
    assert result.stdout == ""  # normal table/json output suppressed
    lines = out.read_text().splitlines()
    assert [json.loads(l)["vulner_id"] for l in lines] == ["A", "B", "C"]


def test_vulns_export_json_format_and_batch(tmp_path):
    out = tmp_path / "data.json"
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.search_vulns.return_value = VulnList.from_dict(
            {"count": 1, "rows": [{"vulner_id": "A"}]}
        )
        result = runner.invoke(
            app, ["vulns", "--vendor", "microsoft", "--export", str(out)]
        )
        kwargs = mock_cls.return_value.search_vulns.call_args.kwargs
    assert result.exit_code == 0
    assert json.loads(out.read_text()) == {"count": 1, "rows": [{"vulner_id": "A"}]}
    assert kwargs["limit"] == 100  # export.BATCH, not the --limit default of 20
    assert kwargs["vendor"] == ["microsoft"]


def test_vulns_export_format_override(tmp_path):
    out = tmp_path / "data.json"  # extension says json...
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.search_vulns.return_value = VulnList.from_dict(
            {"count": 1, "rows": [{"vulner_id": "A"}]}
        )
        result = runner.invoke(
            app, ["vulns", "--export", str(out), "--format", "jsonl"]
        )
    assert result.exit_code == 0
    # ...but --format jsonl wins: one bare object per line, no {"count"} wrapper.
    assert json.loads(out.read_text().splitlines()[0]) == {"vulner_id": "A"}


def test_vulns_format_without_export_errors():
    # BadParameter is caught by the shared `command` error boundary (cli.py),
    # which re-raises typer.Exit(1) rather than propagating click's usual
    # exit code 2 -- matches the convention used by test_invalid_sort_exits_nonzero.
    result = runner.invoke(app, ["vulns", "--format", "jsonl"])
    assert result.exit_code != 0


def test_news_export_passes_filters_and_writes(tmp_path):
    out = tmp_path / "news.jsonl"
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.news.return_value = NewsList.from_dict(
            {"count": 1, "rows": [{"slug": "s1"}]}
        )
        result = runner.invoke(
            app, ["news", "--product", "Wordpress", "--export", str(out)]
        )
        kwargs = mock_cls.return_value.news.call_args.kwargs
    assert result.exit_code == 0
    assert json.loads(out.read_text().splitlines()[0])["slug"] == "s1"
    assert kwargs["product"] == ["Wordpress"]
    assert kwargs["limit"] == 100


def _detail_fixture():
    return VulnDetail.from_dict({
        "vulner_id": "PT-2026-1", "cve_id": "CVE-2026-1",
        "max_score": 9.8, "max_severity": "CRITICAL",
        "references": [
            {"ref_url": "https://note", "domain": "note.io", "source": "Note"},
            {"ref_url": "https://exp", "domain": "exp.io", "source": "Exploit"},
            {"ref_url": "https://adv", "domain": "adv.io", "source": "Vendor Advisory"},
        ],
    })


def test_vuln_source_filter_narrows_table():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.get_vuln.return_value = _detail_fixture()
        result = runner.invoke(app, ["vuln", "CVE-2026-1", "--source", "exploit"])
    assert result.exit_code == 0
    assert "exp.io" in result.stdout
    assert "note.io" not in result.stdout
    assert "adv.io" not in result.stdout


def test_vuln_source_filter_narrows_json():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.get_vuln.return_value = _detail_fixture()
        result = runner.invoke(
            app, ["--json", "vuln", "CVE-2026-1", "--source", "Vendor Advisory"]
        )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [r["source"] for r in payload["references"]] == ["Vendor Advisory"]
    assert payload["vulner_id"] == "PT-2026-1"


def test_vuln_without_source_shows_all_references():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.get_vuln.return_value = _detail_fixture()
        result = runner.invoke(app, ["vuln", "CVE-2026-1"])
    assert result.exit_code == 0
    assert "note.io" in result.stdout and "exp.io" in result.stdout
