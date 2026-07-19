# dbugs CLI — Design

**Date:** 2026-07-19
**Status:** Approved (design), pending implementation plan

## Purpose

Turn the web service at https://dbugs.ptsecurity.com/ into a command-line tool
for querying its vulnerability data: vulnerabilities (search + detail), trends,
references, news, researchers, and global stats.

## Service reverse-engineering (verified)

The site is a Next.js frontend backed by a **FastAPI JSON API** rooted at
`https://dbugs.ptsecurity.com/v1`. Findings confirmed via live probing:

- **No authentication / API key** is required.
- The site sits behind **QRATOR** anti-bot. A bare request gets `403 Forbidden`.
  Sending a browser-like `User-Agent` (and `Referer: https://dbugs.ptsecurity.com/`)
  is sufficient to get `200 OK`. This is the only "trick" the client needs.
- Backend is FastAPI/Pydantic: invalid bodies return
  `{"details": [...], "reason": "Validation error"}` with HTTP 422; unknown
  body keys are rejected (`extra_forbidden`). OpenAPI docs are **not** exposed.

### Confirmed endpoints

| Method | Path | Notes |
|---|---|---|
| `GET`  | `/stats` | `{total_vulnerabilities, new_this_week, authors}` |
| `POST` | `/vulnerabilities` | Search/list. Body: `{limit, page, layer, fts, sorts, locale, ...filters}`. Returns `{count, rows[]}`. |
| `GET`  | `/vulnerabilities/{id}` | Query: `fts`, `locale`. Full detail incl. `references`, `related_news`, `cvss`, `cwe_ids`, `impacts`, `researchers`, `duplicates`. |
| `GET`  | `/trending` | Query: `locale`. Returns `{count, rows[]}`; 30 trending vulns with `posts_count`, `last_tweets`, `vulnerability`. |
| `GET`  | `/trending/{id}/posts` | Query: `limit`, `page`. Social posts for a trend. |
| `POST` | `/news/` | Body: `{limit, page, locale, ...filters}`. |
| `GET`  | `/news/{id}` | Query: `locale`. |
| `GET`  | `/researchers/{name}` | Query: `limit`, `page`, `locale`. |

### Vulnerability search body (from decompiled `getVulnerabilitiesList`)

```
POST /vulnerabilities
{
  "limit": <int>,
  "layer": "catalog" | "full",     // "catalog" = list rows, "full" = richer
  "page": <int>,
  "fts": "<free text>",            // full-text search; confirmed working
  "sorts": [ ... ],                // array; exact item shape TBD (see below)
  "locale": "en",
  // filters spread directly into the body (NOT nested under "filter"):
  "vendor": ["microsoft", ...],    // confirmed accepted
  "product": [...],
  "researcher": [...],
  "has_exploits": true,            // confirmed accepted
  "has_fix": true,
  "severity": [...],
  "base_vector_v2": ...,           // CVSS vector object, serialized by helper
  "base_vector_v3": ...
}
```

Vulnerability row keys (layer `catalog`): `vulner_id`, `cve_id`, `max_score`,
`max_score_2`, `max_score_3`, `max_severity`, `max_severity_2`, `max_severity_3`,
`created`, `updated`, `has_fix`, `has_exploits`, `vendors`, `products`,
`metrics_2`, `metrics_3`, `priority_vendor`, `priority_product`, `related_ids`,
`researchers`.

Vulnerability detail adds: `cwe_ids`, `impacts`, `cvss`, `references`,
`locales`, `duplicates`, `related_news`, `priority_locale`, `priority_sub_locale`.

### To confirm during implementation (transport already proven)

1. Exact `sorts` array **item shape** — `{"field": "max_score", "order": "desc"}`
   was rejected (`order` is `extra_forbidden`); the correct key needs a quick probe.
2. Precise body keys for **score-range** and **date-range** filters.

These are contained unknowns resolved by a `curl` probe against the live API;
they do not change the architecture.

## Architecture

A small Python package. Each module has one responsibility and is testable in
isolation.

```
dbugs_cli/
  __init__.py
  __main__.py     # entry point -> cli.app()
  client.py       # DbugsClient: thin wrapper over /v1 (httpx)
  models.py       # dataclasses: Vuln, VulnDetail, Trend, TrendPost, News, Researcher, Stats
  formatters.py   # models -> Rich tables/panels; severity coloring
  cli.py          # Typer app: commands, flags, --json handling, error boundary
```

### `client.py`

- Owns the QRATOR bypass: sets `User-Agent` (desktop Chrome UA string) and
  `Referer` headers on every request via a shared `httpx.Client`.
- Holds the base URL (`https://dbugs.ptsecurity.com/v1`), a configurable timeout,
  and a default locale.
- One method per endpoint: `stats()`, `search_vulns(...)`, `get_vuln(id, fts=None)`,
  `trends()`, `trend_posts(id, limit, page)`, `news(...)`, `get_news(id)`,
  `researcher(name, limit, page)`.
- Returns parsed dataclasses (or raw dicts where structure is open-ended).
- Raises a typed `DbugsAPIError(status, reason, details)` on non-2xx, surfacing
  the FastAPI validation `reason`/`details` when present.
- No other module imports `httpx` — HTTP is fully encapsulated here.

### `models.py`

Plain dataclasses matching the confirmed response shapes, with a `from_dict`
classmethod each. Tolerant of missing/extra keys (forward-compatible with API
changes). Unknown-but-useful blobs (e.g. full `cvss`) kept as dicts.

### `formatters.py`

Pure functions: `(model) -> rich.Renderable`. No I/O, no network. Includes a
severity→color map (critical=red, high=orange/red, medium=yellow, low=green).
Tested by rendering to a string and asserting on content.

### `cli.py`

- Typer app with the commands below.
- Global options: `--json` (raw API JSON to stdout), `--locale` (default `en`),
  `--timeout`.
- Single error boundary: catches `DbugsAPIError` and `httpx` transport errors,
  prints a clean red one-liner to **stderr**, exits non-zero. Under `--json`,
  emits `{"error": "..."}` instead. No tracebacks leak to users.

## Commands

| Command | Endpoint | Key flags |
|---|---|---|
| `dbugs stats` | `GET /stats` | — |
| `dbugs vulns` | `POST /vulnerabilities` | `--fts`, `--vendor`, `--product`, `--researcher`, `--severity`, `--min-score`, `--max-score`, `--has-exploit`, `--has-fix`, `--since`, `--until`, `--sort`, `--limit`, `--page` |
| `dbugs vuln <id>` | `GET /vulnerabilities/{id}` | `--fts` (highlight term) |
| `dbugs trends` | `GET /trending` | — |
| `dbugs trend <id>` | `GET /trending/{id}/posts` | `--limit`, `--page` |
| `dbugs news` | `POST /news/` | `--limit`, `--page` |
| `dbugs news <id>` | `GET /news/{id}` | — |
| `dbugs researcher <name>` | `GET /researchers/{name}` | `--limit`, `--page` |

`dbugs vuln <id>` renders references and related news as dedicated sections —
this is the "references" surface the user asked for.

Every command honors the global `--json` flag for machine-readable output.

## Data flow

```
user -> cli.py (parse flags)
     -> client.py (build request, add QRATOR headers, call /v1)
     -> models.py (parse response)
     -> formatters.py (Rich renderable)   [default]
        OR json.dumps(raw)                 [--json]
     -> stdout
errors anywhere -> cli error boundary -> stderr + non-zero exit
```

## Error handling

- Non-2xx from API -> `DbugsAPIError` -> red one-liner incl. API `reason`.
- Network/timeout (`httpx.TransportError`) -> "Could not reach dbugs API: ..."
- Invalid user input (bad date, bad score) -> Typer validation message.
- `--json` mode: all errors serialized as `{"error": "..."}`, still non-zero exit.

## Testing

- **pytest + respx** to mock `httpx`:
  - `client.py`: asserts correct method, path, body/params, and QRATOR headers;
    parses saved real fixtures; maps 422 -> `DbugsAPIError`.
  - `formatters.py`: model -> rendered string assertions incl. severity colors.
  - `cli.py`: Typer `CliRunner` smoke tests for each command, `--json` output,
    and the error boundary (mocked failure -> stderr + exit code).
- **Fixtures**: real captured responses (stats, vuln list, vuln detail, trending)
  stored under `tests/fixtures/`.
- **Live tests**: a small opt-in set gated behind an env var
  (e.g. `DBUGS_LIVE=1`), hitting the real API to catch upstream drift.

## Distribution

- `pyproject.toml` (PEP 621) with dependencies `httpx`, `typer`, `rich`.
- `[project.scripts]` `dbugs = "dbugs_cli.__main__:main"`.
- Install via `pipx install .`; dev via `pip install -e ".[dev]"`.

## Non-goals (YAGNI)

- No auth/token handling (API needs none).
- No local caching / database.
- No write operations (API is read-only for our purposes).
- No news media/blob download, `news/products|vendors|researchers` autocomplete
  helpers, or trend graph rendering in v1 — can be added later if wanted.
