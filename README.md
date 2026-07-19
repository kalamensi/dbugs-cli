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
dbugs vuln PT-2026-61063                       # full detail incl. references
dbugs trends                                   # trending vulnerabilities
dbugs trend PT-2026-53941                       # social posts behind a trend
dbugs news                                      # security news feed
dbugs news-item <slug>                          # one article
dbugs researcher <name>                         # researcher profile

# Machine-readable output for any command:
dbugs --json vulns --fts apache | jq '.rows[].vulner_id'
```

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
