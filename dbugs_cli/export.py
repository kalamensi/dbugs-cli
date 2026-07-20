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


def run_export(
    fetch_page: Callable[[int], "tuple[int, list[dict]]"],
    path: str,
    fmt: str,
    err_console: Console,
) -> int:
    """Auto-paginate via fetch_page and write every row to `path`.

    fetch_page(page) returns (count, rows) where count is the API's total and
    rows is that page's raw row dicts. Loops from page 1 until the collected
    total reaches count, or until a page returns no rows (guards against an
    inconsistent count causing an infinite loop). Returns rows written.
    """
    collected = 0
    count = 0
    page = 1
    with open(path, "w", encoding="utf-8") as fh:
        json_rows: list | None = [] if fmt == "json" else None
        while True:
            count, rows = fetch_page(page)
            if not rows:
                break
            if fmt == "jsonl":
                for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            else:
                json_rows.extend(rows)
            collected += len(rows)
            err_console.print(f"Exported {collected}/{count} rows")
            if collected >= count:
                break
            page += 1
        if fmt == "json":
            fh.write(json.dumps({"count": count, "rows": json_rows}, ensure_ascii=False))
    err_console.print(f"Exported {collected}/{count} rows → {path}")
    return collected
