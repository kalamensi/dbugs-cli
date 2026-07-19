import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from dbugs_cli.cli import app
from dbugs_cli.client import DbugsAPIError
from dbugs_cli.models import Stats, VulnList

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
