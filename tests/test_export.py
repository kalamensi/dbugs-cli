import pytest
import typer

from dbugs_cli.export import resolve_format


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
