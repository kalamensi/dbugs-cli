# dbugs CLI — Feature Expansion Design

**Date:** 2026-07-20
**Status:** Approved (design), pending implementation plan
**Builds on:** `2026-07-19-dbugs-cli-design.md`

## Purpose

Extend the existing `dbugs` CLI with search/filter across more entities and
round out "full features": server-side **news filters**, client-side **trends
filter/sort**, and **autocomplete helpers** (`suggest`) for discovering valid
news filter values.

Out of scope (explicit): researchers list/search (deferred by user); vulns
already has complete filtering.

## Verified API additions (live-probed 2026-07-20)

All use the same base/headers/no-auth as the base design.

### News filters — `POST /news/`
Body accepts these optional keys (all confirmed accepted; unknown keys → 422):
- `product: list[str]` (confirmed: `["Wordpress"]` → count 3)
- `vendor: list[str]` (confirmed: `["Microsoft"]` → count 41)
- `researcher: list[str]` (accepted)
- `cve_id: list[str]` (accepted; MUST be a list — a bare string → 422 `list_type`)
- `category: list[str]` (accepted)
- `fts: str` (confirmed: `"wordpress"` → count 5)
- `published_from: str`, `published_to: str` (ISO date; confirmed → count 43)
- plus existing `limit`, `page`, `locale`
Returns `{count, rows[]}` (existing `NewsList` shape). `search_pattern` and
`vulner` are NOT valid keys.

### Autocomplete helpers — `GET`, return a bare JSON array `list[str]`
- `GET /news/products?search_pattern=<p>` → matching product names
- `GET /news/vendors?search_pattern=<p>` → matching vendor names
- `GET /news/products/popular` → popular products (no params)
- `GET /news/vendors/popular` → popular vendors (no params)
Confirmed: `news/products?search_pattern=word` → `["Wordpress","Microsoft Word",...]`;
`news/products/popular` → `["Windows","Android","Linux",...]`.

### Trends — `GET /trending?locale=`
Returns a **fixed set of 30** trends with **no server-side filter/sort
parameters**. Any filtering/sorting is therefore client-side over the returned
rows. (Confirmed: no query params other than `locale` are honored.)

## Design

### 1. News filters (extend `client.news()` + `dbugs news` command)

`DbugsClient.news()` gains optional params and builds the POST body dropping
`None` values (identical pattern to `search_vulns`):

```
news(self, *, limit=20, page=1, fts=None, product=None, vendor=None,
     researcher=None, cve_id=None, category=None,
     published_from=None, published_to=None, locale=None) -> NewsList
```

`dbugs news` flags: `--fts`, `--product` (repeatable), `--vendor` (repeatable),
`--researcher` (repeatable), `--cve` (repeatable → `cve_id`), `--category`
(repeatable), `--since` (→ `published_from`), `--until` (→ `published_to`),
plus existing `--limit`/`--page`. `render_news_list` and `--json` unchanged.

### 2. Trends filter/sort (new `transform.py` + extend `dbugs trends`)

New pure module `dbugs_cli/transform.py`:
```
filter_sort_trends(tl: TrendList, *, min_score=None, severity=None,
                   min_posts=None, sort=None, descending=True,
                   limit=None) -> TrendList
```
- Filters rows by `min_score` (keep `vuln.score >= min_score`; rows with
  `score is None` are dropped only when `min_score` is set), `severity` (case-
  insensitive membership on `vuln.severity`), `min_posts` (`posts_count >=`).
- `sort` ∈ {`score`, `posts`}: sorts by `vuln.score` (None treated as -inf) or
  `posts_count`; `descending` controls direction.
- `limit` truncates after filter+sort.
- Returns a new `TrendList` whose `count` = number of rows AFTER filtering,
  `rows` = the filtered/sorted/truncated list, and `raw` = a rebuilt
  `{"count": <filtered len>, "rows": [<each kept row's raw>]}`. Rebuilding
  `raw` from the kept rows keeps `--json` consistent with the displayed result
  (see below). With no filters passed, this reproduces the full 30-row payload.

`dbugs trends` flags: `--min-score FLOAT`, `--severity` (repeatable),
`--min-posts INT`, `--sort [score|posts]`, `--asc`, `--limit INT`. The command
calls `client.trends()`, passes the result through `filter_sort_trends`, then
renders. Because `filter_sort_trends` rebuilds `raw` from the kept rows, both
the human table AND `--json` reflect the same filtered/sorted/truncated set —
so `dbugs --json trends --min-score 9` yields filtered JSON, useful for scripting.

### 3. Autocomplete helpers (new client methods + `dbugs suggest` command)

New `DbugsClient` methods returning `list[str]`:
```
suggest_products(self, pattern: str | None = None) -> list[str]
suggest_vendors(self, pattern: str | None = None) -> list[str]
```
Each: if `pattern` is given → `GET news/{products|vendors}?search_pattern=<p>`;
else → `GET news/{products|vendors}/popular`.

New formatter `render_suggestions(items: list[str], title: str) -> RenderableType`
rendering the strings as Rich `Columns` (or a simple bulleted/numbered list).

New command `dbugs suggest FIELD [PATTERN]` where `FIELD` is a required argument
constrained to `products` | `vendors` (via a `str` Enum → invalid value gives a
Typer usage error). Calls the matching client method; `--json` emits the raw
list, else `render_suggestions`.

## Data flow / layering

Unchanged from the base design. `httpx` stays only in `client.py`.
`transform.py` is pure (operates on models, no I/O). `filter_sort_trends` sits
between client and formatter in the `trends` command path.

## Error handling

Unchanged: `DbugsAPIError` → CLI `@command` boundary (red one-liner to stderr /
`{"error": …}` under `--json`, exit 1). Invalid `--sort`/`FIELD` values → Typer
usage error (exit 2). No tracebacks.

## Testing

- **client**: `news()` builds a body with only the provided filters (None
  dropped), `cve_id` sent as a list; `suggest_products/vendors` hit the correct
  path with/without `search_pattern` and return the parsed list. respx mocks +
  fixtures.
- **transform**: `filter_sort_trends` unit tests — min_score/severity/min_posts
  filtering, score/posts sort (asc+desc), None-score handling, limit, and that
  `count` reflects the filtered length and `raw` is rebuilt from the kept rows
  (`{"count", "rows"}` matching the filtered set).
- **formatters**: `render_suggestions` renders each item.
- **cli**: `news` forwards all filter flags to the client; `trends` applies
  filter/sort flags and `--json` still emits the raw payload; `suggest`
  dispatches to the right method and rejects invalid `FIELD`.
- **live** (opt-in `DBUGS_LIVE=1`): news filtered by `product=["Wordpress"]`
  returns rows; `suggest_products("word")` returns a non-empty list.

## Non-goals (YAGNI)

- No researchers list/search command.
- No `news/categories` command (endpoint not exposed at a usable path).
- No caching of suggestion lists.
- No server-side trends filtering (the API does not support it).
