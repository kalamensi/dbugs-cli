# dbugs CLI — complete command & flag reference

Every command accepts the **global** options below (placed *before* the
subcommand) and its own local options. All commands are read-only.

## Global options (before the subcommand)

| Option | Default | Meaning |
| --- | --- | --- |
| `--json` | off | Emit the raw API JSON payload untouched (pipe to `jq`). |
| `--locale` | `en` | Response locale. |
| `--timeout` | `30` | HTTP timeout in seconds. |

```bash
dbugs --json vulns --fts apache      # global --json BEFORE the subcommand
```

## `stats` — global database totals

No options. Fields: `total_vulnerabilities`, `new_this_week`, `authors`.

## `vulns` — search / list vulnerabilities (server-side filters)

| Option | Repeatable | Notes |
| --- | --- | --- |
| `--fts TEXT` | no | Full-text search. |
| `--vendor TEXT` | yes | Filter by vendor. Discover values with `suggest vendors`. |
| `--product TEXT` | yes | Filter by product. Discover values with `suggest products`. |
| `--researcher TEXT` | yes | Filter by researcher. |
| `--severity TEXT` | yes | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` (case-insensitive). |
| `--min-score FLOAT` | no | Minimum CVSS score. |
| `--max-score FLOAT` | no | Maximum CVSS score. |
| `--has-exploit` | flag | Only vulns with a known exploit. |
| `--has-fix` | flag | Only vulns with a fix available. |
| `--since YYYY-MM-DD` | no | Created on/after this date. |
| `--until YYYY-MM-DD` | no | Created on/before this date. |
| `--sort NAME` | no | `score` (default) / `created` / `updated` / `severity`. |
| `--asc` | flag | Sort ascending (default is descending). |
| `--limit INT` | no | Rows per page (default 20). |
| `--page INT` | no | Page number (default 1). |
| `--export PATH` | no | Write the **full** filtered set to a file; auto-paginates; ignores `--limit`/`--page`. |
| `--format json\|jsonl` | no | Export format; requires `--export`; else inferred from extension. |

Note: the user-facing `--sort score` maps to the API field `max_score`;
`created`/`updated`/`severity` map 1:1.

## `vuln <id>` — full detail for one vulnerability

Argument: `<id>` is a PT id (e.g. `PT-2026-61063`) or a CVE id.

| Option | Repeatable | Notes |
| --- | --- | --- |
| `--fts TEXT` | no | Highlight term. |
| `--source TEXT` | yes | Keep only references whose source matches, exact & case-insensitive. Common: `Exploit`, `Note`, `Vendor Advisory` (quote multi-word). Filters both table and `--json`. |

Detail payload includes: the vuln core fields, `cwe_ids`, `impacts`, `cvss`,
`references[]` (each with `ref_url`, `domain`, `source`, `stars`, `forks`),
`related_news`, `duplicates`, `researchers`.

## `trends` — trending vulnerabilities (filtered CLIENT-side)

The `/trending` endpoint returns a fixed ~30 rows with **no** server
filter/sort params. All of these are applied locally after fetching:

| Option | Notes |
| --- | --- |
| `--min-score FLOAT` | Keep trends with score ≥ this. |
| `--severity TEXT` (repeatable) | CRITICAL/HIGH/MEDIUM/LOW. |
| `--min-posts INT` | Keep trends with at least this many social posts. |
| `--sort score\|posts` | Sort key. |
| `--asc` | Ascending (default descending). |
| `--limit INT` | Keep only first N after filter/sort. |

Each trend row has `posts_count`, `lvl`, and a nested `vulnerability`.

## `trend <id>` — social-media posts driving a trend

Argument: vuln id. Options: `--limit` (default 5), `--page` (default 1).

## `news` — list / filter security news (server-side filters)

| Option | Repeatable | Notes |
| --- | --- | --- |
| `--fts TEXT` | no | Full-text search. |
| `--product TEXT` | yes | Filter by product. |
| `--vendor TEXT` | yes | Filter by vendor. |
| `--researcher TEXT` | yes | Filter by researcher. |
| `--cve TEXT` | yes | Filter by CVE id. |
| `--category TEXT` | yes | Filter by category. |
| `--since YYYY-MM-DD` | no | Published on/after. |
| `--until YYYY-MM-DD` | no | Published on/before. |
| `--limit INT` / `--page INT` | no | Paging (defaults 20 / 1). |
| `--export PATH` / `--format` | no | Full-set export (same semantics as `vulns`). |

News item fields: `title`, `summary`, `slug`, `category`, `published`,
`cve_ids`, `vendors`, `products`.

## `news-item <slug>` — one article

Argument: the news `slug` (obtain it from a `news` row).

## `suggest products|vendors [PATTERN]` — discover valid filter values

- `suggest products word` → product names matching "word".
- `suggest vendors` → popular vendors (omit the pattern for the popular list).

Use this FIRST whenever a `--product`/`--vendor` value is uncertain: the
filters match the API's canonical names, so guessing often returns nothing.

## `researcher <name>` — researcher profile & stats

Argument: researcher name. Options: `--limit` (default 20), `--page`.

## Raw JSON field names (for `--json` + `jq`)

Vulnerability rows use: `vulner_id`, `cve_id`, `max_score`, `max_severity`,
`created`, `updated`, `has_fix`, `has_exploits`, `vendors`, `products`,
`researchers`. List payloads wrap rows as `{"count": N, "rows": [...]}`.

```bash
dbugs --json vulns --fts apache | jq '.rows[] | {id: .vulner_id, score: .max_score}'
dbugs --json vuln PT-2026-61063 --source Exploit | jq '.references[].ref_url'
```

## Errors

The CLI never prints a traceback. On failure it exits 1 and prints
`Error: dbugs API error <status>: <reason>` to stderr (or `{"error": "..."}`
under `--json`). A 403 usually means the anti-bot layer rejected the request.
