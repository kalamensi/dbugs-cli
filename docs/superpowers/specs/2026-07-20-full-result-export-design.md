# Full-result export for `vulns` and `news`

**Date:** 2026-07-20
**Status:** Approved for implementation

## Problem

`dbugs vulns` and `dbugs news` return paginated results (`{count, rows}`) capped
by `--limit`/`--page`. Users who want the *entire* filtered result set must
manually walk every page. We want a single flag that auto-paginates a filtered
query and writes the full result to a JSON or JSONL file.

## Scope

- Applies to **`vulns`** and **`news`** only (the two paginated search
  endpoints). `trends`, `researcher`, and detail commands are out of scope.
- Read-only; no changes to the HTTP client's request-building beyond what the
  existing methods already support.

## Interface

Two new options on both `vulns` and `news`:

| Option | Meaning |
|--------|---------|
| `--export PATH` | Enable full export to `PATH`. Overwrites `PATH` if it exists. |
| `--format json\|jsonl` | Override the format. If omitted, inferred from the extension: `.jsonl` → jsonl, anything else → json. |

Behavior when `--export` is set:

- All existing filter flags (`--fts`, `--vendor`, `--product`, `--severity`,
  `--min-score`, `--since`, …) apply to the paged requests exactly as they do
  today.
- `--limit` and `--page` are **ignored** (the loop uses a fixed internal batch
  size and fetches everything).
- Normal stdout output (table or `--json`) is **suppressed**. Progress is
  written to **stderr** so stdout stays clean.

Examples:

```bash
dbugs vulns --vendor microsoft --severity CRITICAL --export out.jsonl
dbugs vulns --min-score 9 --export out.json
dbugs news --product Wordpress --export news.txt --format jsonl
```

## Formats

- **jsonl** — one raw API row object per line. Stream-friendly; written
  incrementally as pages arrive. Best for large result sets.
- **json** — a single document `{"count": N, "rows": [...]}`, mirroring the API
  response shape. Buffered in memory and written once at the end.

Row objects are the exact raw API dicts (`result.raw["rows"]`), same fidelity as
today's `--json` output.

## New module: `dbugs_cli/export.py`

Keeps pagination/serialization out of `cli.py` and `client.py`. Two pure,
independently-testable functions.

### `resolve_format(path, override) -> str`

```
resolve_format(path: str, override: str | None) -> "json" | "jsonl"
```

- If `override` is given, it must be `"json"` or `"jsonl"` (else raise
  `typer.BadParameter`).
- Otherwise infer from `path`: extension `.jsonl` (case-insensitive) → `"jsonl"`;
  anything else → `"json"`.

### `run_export(fetch_page, path, fmt, err_console) -> int`

```
run_export(
    fetch_page: Callable[[int], tuple[int, list[dict]]],
    path: str,
    fmt: str,                # "json" | "jsonl"
    err_console: rich.console.Console,
) -> int                     # total rows written
```

- `fetch_page(page)` is supplied by the command. It calls the client with a
  fixed batch size (`BATCH = 100`) and the command's filters, returning
  `(count, raw_rows)` where `count` is the API's total and `raw_rows` is that
  page's raw row dicts.
- **Loop:** start at page 1, accumulate rows until `len(collected) >= count`.
  Increment the page number each iteration.
- **Safety guard:** if a page returns 0 rows, stop even when
  `len(collected) < count` — prevents an infinite loop on an inconsistent
  `count`.
- **Writing:**
  - `jsonl`: open the file once; write `json.dumps(row) + "\n"` per row as pages
    arrive (incremental).
  - `json`: accumulate all rows, then write `json.dumps({"count": count,
    "rows": rows})` once.
- **Progress:** after each page, print `Exported {collected}/{count} rows` to
  `err_console`; on completion print `Exported {total}/{count} rows → {path}`.
- Returns the total number of rows written.

Empty result (`count == 0`): jsonl → empty file; json → `{"count": 0,
"rows": []}`. No error.

## CLI wiring (`cli.py`)

In both `vulns` and `news`:

The module is imported as `from dbugs_cli import export`, so the CLI option's
Python variable is named `export_path` (flag text stays `--export`) to avoid
shadowing the module inside the function body.

1. Add `export_path: str = typer.Option(None, "--export", ...)` and
   `export_format: str = typer.Option(None, "--format", ...)`.
2. After building filter arguments, if `export_path` is set:
   - `fmt = export.resolve_format(export_path, export_format)`
   - define `fetch_page(page)` closure that calls
     `state.client.search_vulns(...)` / `state.client.news(...)` with
     `limit=export.BATCH, page=page` and the command's filters, returning
     `(result.count, result.raw.get("rows", []))`.
   - `export.run_export(fetch_page, export_path, fmt, state.err_console)`
   - `return` (skip the normal `_emit`).
3. Otherwise behave exactly as today.

## Error handling

A failed page raises `DbugsAPIError`, caught by the existing `@command`
boundary (prints to stderr, exits 1). Because jsonl streams incrementally, a
mid-run failure leaves a partial `.jsonl` file; json writes nothing until the
end, so a failure leaves no/empty file. This is acceptable and documented.

## Testing (TDD)

Unit tests for `export.py` (no network):

- `resolve_format`: `.jsonl` → jsonl; `.json`/`.txt`/no-ext → json;
  case-insensitive extension; valid override wins over extension; invalid
  override raises `typer.BadParameter`.
- `run_export` with a fake `fetch_page`:
  - Multi-page: e.g. count=250, batch=100 → 3 pages, 250 rows written.
  - jsonl output: correct line count, each line parses to the right dict.
  - json output: single document with `count` and full `rows`.
  - Safety guard: `fetch_page` reports count=100 but returns an empty second
    page → stops, no infinite loop.
  - Empty result: count=0 → empty jsonl / `{"count":0,"rows":[]}` json.
  - Returns correct total.

CLI integration tests (mocked client, Typer `CliRunner`):

- `dbugs vulns --fts x --export <tmp>.jsonl` writes the file and produces no
  stdout; filters are passed through to the client.
- Format inference and `--format` override reach `run_export`.

## Docs

Update `README.md`: document `--export`/`--format` on `vulns`/`news`, with an
example, and note that `--limit`/`--page` are ignored during export.
