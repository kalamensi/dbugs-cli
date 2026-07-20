"""Full-result export: auto-paginate a filtered query to a JSON/JSONL file.

Kept separate from cli.py and client.py so pagination and serialization stay
independently testable. Row objects written are the exact raw API dicts.
"""
from __future__ import annotations

import json
from typing import Callable

import typer
from rich.console import Console

BATCH = 100


def resolve_format(path: str, override: str | None) -> str:
    """Return 'json' or 'jsonl'. An explicit override wins; otherwise infer
    from the path's extension ('.jsonl' -> jsonl, anything else -> json)."""
    if override is not None:
        if override not in ("json", "jsonl"):
            raise typer.BadParameter("--format must be 'json' or 'jsonl'")
        return override
    return "jsonl" if path.lower().endswith(".jsonl") else "json"
