# Full-result Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--export PATH` flag to `dbugs vulns` and `dbugs news` that auto-paginates a filtered query and writes the entire result set to a JSON or JSONL file.

**Architecture:** A new pure module `dbugs_cli/export.py` owns format resolution and the pagination-and-write loop, decoupled from HTTP via a `fetch_page(page) -> (count, rows)` closure supplied by each command. `cli.py` builds that closure from the command's existing filter flags and delegates to `export.run_export`, skipping normal stdout output.

**Tech Stack:** Python 3.13, Typer, Rich, httpx (client, untouched here); pytest + `unittest.mock.patch` + Typer `CliRunner` for tests.

## Global Constraints

- Every module starts with `from __future__ import annotations` (repo convention).
- Tests must not hit the network — mock `dbugs_cli.cli.DbugsClient` or pass a fake `fetch_page`. (Live tests live in `test_live.py`, out of scope here.)
- Rows written are the **exact raw API dicts** (`result.raw.get("rows", [])`), matching `--json` fidelity.
- Internal pagination batch size is fixed: `export.BATCH = 100`.
- When `--export` is set, `--limit`/`--page` are ignored and normal stdout (table or `--json`) is suppressed; progress goes to stderr (`state.err_console`).
- Format inference: `.jsonl` (case-insensitive) → `jsonl`, anything else → `json`; `--format` overrides.

---

### Task 1: `resolve_format` in new `export.py`

**Files:**
- Create: `dbugs_cli/export.py`
- Test: `tests/test_export.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `BATCH = 100` (module constant); `resolve_format(path: str, override: str | None) -> str` returning `"json"` or `"jsonl"`, raising `typer.BadParameter` on an invalid override.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_export.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_export.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'dbugs_cli.export'`.

- [ ] **Step 3: Write minimal implementation**

Create `dbugs_cli/export.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_export.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add dbugs_cli/export.py tests/test_export.py
git commit -m "feat: add export.resolve_format for full-result export"
```

---

### Task 2: `run_export` pagination-and-write loop

**Files:**
- Modify: `dbugs_cli/export.py`
- Test: `tests/test_export.py`

**Interfaces:**
- Consumes: `resolve_format`, `BATCH` from Task 1.
- Produces: `run_export(fetch_page: Callable[[int], tuple[int, list[dict]]], path: str, fmt: str, err_console: Console) -> int` — pages via `fetch_page(page)` starting at 1, writes to `path` (`jsonl` = one object per line, streamed; `json` = single `{"count", "rows"}` document), returns total rows written. Stops when collected reaches `count` **or** a page returns no rows.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_export.py`:

```python
import io
import json as _json

from rich.console import Console

from dbugs_cli.export import run_export


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_export.py -v`
Expected: FAIL — `ImportError: cannot import name 'run_export'`.

- [ ] **Step 3: Write minimal implementation**

Append to `dbugs_cli/export.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_export.py -v`
Expected: PASS (11 passed total in this file).

- [ ] **Step 5: Commit**

```bash
git add dbugs_cli/export.py tests/test_export.py
git commit -m "feat: add export.run_export auto-pagination writer"
```

---

### Task 3: Wire `--export`/`--format` into `vulns` and `news`

**Files:**
- Modify: `dbugs_cli/cli.py` (import line ~13; `vulns` command ~105-147; `news` command ~203-232)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `export.BATCH`, `export.resolve_format`, `export.run_export` from Tasks 1-2.
- Produces: no new public symbols; adds `--export`/`--format` options to two commands.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py` (imports `json`, `patch`, `runner`, `VulnList`, `NewsList` already exist at the top of the file):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -k export -v`
Expected: FAIL — `--export` is not a known option (exit code 2 / usage error), so assertions fail.

- [ ] **Step 3a: Add the import**

In `dbugs_cli/cli.py`, change:

```python
from dbugs_cli import formatters, transform
```

to:

```python
from dbugs_cli import export, formatters, transform
```

- [ ] **Step 3b: Add options + export branch to `vulns`**

In the `vulns` command, add these two options at the end of the parameter list (immediately after the `page` option):

```python
    export_path: str = typer.Option(None, "--export", help="Write the full filtered result set to this file (auto-paginates; ignores --limit/--page)."),
    export_format: str = typer.Option(None, "--format", help="Export format: json or jsonl (default inferred from --export file extension)."),
```

Then, inside the function body, immediately after the `sort_field is None` validation block (before the `result = state.client.search_vulns(...)` call), insert:

```python
    if export_path:
        fmt = export.resolve_format(export_path, export_format)
        sev = [s.upper() for s in severity] if severity else None

        def fetch_page(page_num: int):
            result = state.client.search_vulns(
                fts=fts,
                vendor=vendor or None,
                product=product or None,
                researcher=researcher or None,
                severity=sev,
                score_from=min_score,
                score_to=max_score,
                has_exploit=True if has_exploit else None,
                has_fix=True if has_fix else None,
                created_from=since,
                created_to=until,
                sort=sort_field,
                descending=not ascending,
                limit=export.BATCH,
                page=page_num,
            )
            return result.count, result.raw.get("rows", [])

        export.run_export(fetch_page, export_path, fmt, state.err_console)
        return
```

- [ ] **Step 3c: Add options + export branch to `news`**

In the `news` command, add the same two options at the end of the parameter list (after the `page` option):

```python
    export_path: str = typer.Option(None, "--export", help="Write the full filtered result set to this file (auto-paginates; ignores --limit/--page)."),
    export_format: str = typer.Option(None, "--format", help="Export format: json or jsonl (default inferred from --export file extension)."),
```

Then, inside the function body, immediately after `state: AppState = ctx.obj` (before the `result = state.client.news(...)` call), insert:

```python
    if export_path:
        fmt = export.resolve_format(export_path, export_format)

        def fetch_page(page_num: int):
            result = state.client.news(
                fts=fts,
                product=product or None,
                vendor=vendor or None,
                researcher=researcher or None,
                cve_id=cve or None,
                category=category or None,
                published_from=since,
                published_to=until,
                limit=export.BATCH,
                page=page_num,
            )
            return result.count, result.raw.get("rows", [])

        export.run_export(fetch_page, export_path, fmt, state.err_console)
        return
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -k export -v`
Expected: PASS (4 passed).
Then run the full suite: `pytest`
Expected: all pass (no regressions).

- [ ] **Step 5: Commit**

```bash
git add dbugs_cli/cli.py tests/test_cli.py
git commit -m "feat: wire --export/--format into vulns and news commands"
```

---

### Task 4: Document export in README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: the behavior built in Tasks 1-3.
- Produces: user-facing docs (no code symbols).

- [ ] **Step 1: Add an example to the Usage block**

In `README.md`, in the fenced usage block under `## Usage`, add these two lines immediately after the `dbugs vulns --min-score 9 --since 2026-07-01` line:

```bash
dbugs vulns --vendor microsoft --export vulns.jsonl   # all matches -> JSONL
dbugs news --product Wordpress --export news.json      # all matches -> JSON
```

- [ ] **Step 2: Add an "Exporting full results" section**

In `README.md`, immediately after the `### Filtering trends` section (before `## Global options`), add:

```markdown
### Exporting full results

`dbugs vulns` and `dbugs news` accept `--export PATH` to write the **entire**
filtered result set to a file, auto-paginating through every page (the API's
own paging cap no longer applies). While exporting, `--limit`/`--page` are
ignored and normal table/`--json` output is suppressed; progress is printed to
stderr.

The format is inferred from the file extension — `.jsonl` writes one JSON
object per line (streamed, best for large results), any other extension writes
a single `{"count": N, "rows": [...]}` document. Override with
`--format json|jsonl`.

    dbugs vulns --vendor microsoft --severity CRITICAL --export out.jsonl
    dbugs news --product Wordpress --export news.json --format jsonl
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document --export/--format for vulns and news"
```

---

## Self-Review

**Spec coverage:**
- Interface (`--export`, `--format`, extension inference, override) → Tasks 1 & 3. ✓
- Scope vulns + news only → Task 3. ✓
- `--limit`/`--page` ignored, stdout suppressed, progress to stderr → Task 3 (`limit=export.BATCH`, early `return`, `err_console`); asserted in `test_vulns_export_jsonl_writes_all_pages` / `test_vulns_export_json_format_and_batch`. ✓
- `export.py` with `resolve_format` + `run_export` → Tasks 1 & 2. ✓
- jsonl streaming / json single-document / raw-dict fidelity → Task 2 impl + `result.raw.get("rows", [])` in Task 3. ✓
- Safety guard on 0-row page → Task 2 `test_run_export_stops_on_empty_page_despite_count`. ✓
- Empty result → Task 2 `test_run_export_empty_result_json`. ✓
- Error handling via existing `@command` boundary → unchanged; the export branch runs inside the wrapped body, so `DbugsAPIError` propagates as today. ✓
- Docs → Task 4. ✓

**Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows full code. ✓

**Type consistency:** `fetch_page(page) -> (count, rows)`, `run_export(fetch_page, path, fmt, err_console) -> int`, `resolve_format(path, override) -> str`, and `export.BATCH` are named identically across Tasks 1-3. The CLI option variable is `export_path` (not `export`) to avoid shadowing the imported `export` module. ✓
