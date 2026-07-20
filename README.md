# dbugs CLI

A command-line client for the [dbugs](https://dbugs.ptsecurity.com/) vulnerability
database by Positive Technologies. Query vulnerabilities, trends, references,
news, and researchers from your terminal.

## Install

```bash
pipx install .
# or, for development:
pip install -e ".[dev]"
```

## Usage

```bash
dbugs stats                                   # database totals
dbugs vulns --fts apache --limit 10           # full-text search
dbugs vulns --vendor microsoft --severity CRITICAL --has-exploit --sort score
dbugs vulns --min-score 9 --since 2026-07-01  # score + date filters
dbugs vulns --vendor microsoft --export vulns.jsonl   # all matches -> JSONL
dbugs news --product Wordpress --export news.json      # all matches -> JSON
dbugs vuln PT-2026-61063                       # full detail incl. references
dbugs news                                      # latest security news
dbugs news --product Wordpress --vendor Microsoft --fts rce
dbugs news --cve CVE-2026-63030 --since 2026-07-01
dbugs trends                                    # all 30 trending vulnerabilities
dbugs trends --min-score 9 --severity CRITICAL --sort posts --limit 10
dbugs suggest products word                     # discover valid --product values
dbugs suggest vendors                           # popular vendors (no pattern)
dbugs trend PT-2026-53941                       # social posts behind a trend
dbugs news-item <slug>                          # one article
dbugs researcher <name>                         # researcher profile

# Machine-readable output for any command:
dbugs --json vulns --fts apache | jq '.rows[].vulner_id'
```

### Filtering news

`dbugs news` supports server-side filters: `--fts`, `--product`, `--vendor`,
`--researcher`, `--cve`, `--category` (all repeatable except `--fts`), and
`--since`/`--until` (published date range). Use `dbugs suggest products|vendors
[PATTERN]` to discover valid product/vendor values.

### Filtering trends

The service returns a fixed set of 30 trending vulnerabilities. `dbugs trends`
filters and sorts them locally: `--min-score`, `--severity`, `--min-posts`,
`--sort score|posts`, `--asc`, `--limit`. Under `--json` the filtered set is
emitted.

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

## Global options

- `--json` — emit raw API JSON instead of tables.
- `--locale en` — response locale.
- `--timeout 30` — HTTP timeout in seconds.

## Notes

The service sits behind anti-bot protection; the client sends the required
browser headers automatically. No API key or login is needed. The tool is
read-only.

## Development

```bash
pytest                 # unit tests (network mocked)
DBUGS_LIVE=1 pytest    # also run tests against the live API
```
