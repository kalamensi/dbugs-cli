import io
import json as _json
import pytest
import typer

from rich.console import Console

from dbugs_cli.export import resolve_format, run_export


def test_resolve_format_infers_jsonl_from_extension():
    assert resolve_format("out.jsonl", None) == "jsonl"


def test_resolve_format_infers_json_for_other_extensions():
    assert resolve_format("out.json", None) == "json"
    assert resolve_format("out.txt", None) == "json"
    assert resolve_format("out", None) == "json"


def test_resolve_format_extension_is_case_insensitive():
    assert resolve_format("OUT.JSONL", None) == "jsonl"


def test_resolve_format_override_wins_over_extension():
    assert resolve_format("out.json", "jsonl") == "jsonl"
    assert resolve_format("out.jsonl", "json") == "json"


def test_resolve_format_invalid_override_raises():
    with pytest.raises(typer.BadParameter):
        resolve_format("out.json", "csv")


def _console():
    return Console(file=io.StringIO(), force_terminal=False)


def _pager(count, pages):
    """fetch_page(page) -> (count, pages[page-1]) or (count, []) past the end."""
    def fetch(page):
        rows = pages[page - 1] if page - 1 < len(pages) else []
        return count, rows
    return fetch


def test_run_export_jsonl_writes_one_object_per_line(tmp_path):
    path = tmp_path / "out.jsonl"
    pages = [[{"id": 1}, {"id": 2}], [{"id": 3}]]
    total = run_export(_pager(3, pages), str(path), "jsonl", _console())
    assert total == 3
    lines = path.read_text().splitlines()
    assert len(lines) == 3
    assert [_json.loads(l)["id"] for l in lines] == [1, 2, 3]


def test_run_export_paginates_until_count(tmp_path):
    path = tmp_path / "out.jsonl"
    pages = [
        [{"id": i} for i in range(100)],
        [{"id": i} for i in range(100, 200)],
        [{"id": i} for i in range(200, 250)],
    ]
    total = run_export(_pager(250, pages), str(path), "jsonl", _console())
    assert total == 250
    assert len(path.read_text().splitlines()) == 250


def test_run_export_json_writes_single_document(tmp_path):
    path = tmp_path / "out.json"
    pages = [[{"id": 1}, {"id": 2}], [{"id": 3}]]
    total = run_export(_pager(3, pages), str(path), "json", _console())
    assert total == 3
    doc = _json.loads(path.read_text())
    assert doc["count"] == 3
    assert [r["id"] for r in doc["rows"]] == [1, 2, 3]


def test_run_export_stops_on_empty_page_despite_count(tmp_path):
    # API reports count=100 but page 2 is empty -> must stop, not loop forever.
    path = tmp_path / "out.jsonl"
    pages = [[{"id": 1}]]
    total = run_export(_pager(100, pages), str(path), "jsonl", _console())
    assert total == 1
    assert len(path.read_text().splitlines()) == 1


def test_run_export_empty_result_json(tmp_path):
    path = tmp_path / "out.json"
    total = run_export(_pager(0, []), str(path), "json", _console())
    assert total == 0
    assert _json.loads(path.read_text()) == {"count": 0, "rows": []}


def test_run_export_returns_total(tmp_path):
    path = tmp_path / "out.jsonl"
    total = run_export(_pager(2, [[{"id": 1}, {"id": 2}]]), str(path), "jsonl", _console())
    assert total == 2
