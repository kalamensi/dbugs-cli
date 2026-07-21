---
name: Querying the dbugs vulnerability database
description: This skill should be used when the user asks about vulnerabilities, CVEs, exploits, security advisories, or security news and wants live data — e.g. "latest critical WordPress vulns", "is CVE-2026-63030 exploited", "what's trending in security this week", "vulns by researcher X", "recent Microsoft advisories", "who researched this CVE". Maps natural-language security questions to the read-only `dbugs` CLI (dbugs.ptsecurity.com) and its commands, filters, and JSON output.
version: 0.1.0
---

# Querying the dbugs vulnerability database

## Purpose

Answer natural-language questions about vulnerabilities, exploits, and
security news by driving the read-only `dbugs` command-line client, which
queries the dbugs.ptsecurity.com database (Positive Technologies). Translate
the user's intent into the right command and flags, run it, and summarize the
result. No API key or login is required.

This skill is the foundation for the `triage` and `report` skills in this
plugin — both build on the command knowledge documented here.

## Prerequisites

`dbugs` must be installed and on `PATH`. Verify once per session before the
first query:

```bash
dbugs --help >/dev/null 2>&1 && echo OK || echo MISSING
```

If `MISSING`, tell the user to install it (`pipx install .` from the
dbugs-cli repo, or `pip install -e ".[dev]"`). If the project uses a
virtualenv, the binary may be at `.venv/bin/dbugs` — use that path instead of
bare `dbugs`.

## Command map

Pick the command from the user's intent:

| The user wants… | Command |
| --- | --- |
| Database totals ("how many vulns are there") | `dbugs stats` |
| To find/list vulnerabilities by any filter | `dbugs vulns [filters]` |
| Everything about one CVE / PT id | `dbugs vuln <id>` |
| What's trending / hot right now | `dbugs trends [filters]` |
| Social-media posts behind a trend | `dbugs trend <id>` |
| Security news / articles | `dbugs news [filters]` |
| One news article | `dbugs news-item <slug>` |
| Valid `--product` / `--vendor` names | `dbugs suggest products\|vendors [pattern]` |
| A researcher's profile & output | `dbugs researcher <name>` |

The full flag reference for every command lives in
**`references/commands.md`** — consult it whenever unsure about a flag name,
whether an option is repeatable, or the raw JSON field names. Load it before
constructing any non-trivial `vulns`/`news` query.

## How to answer a query

1. **Choose the command** from the table above.
2. **Map filters** from the user's words to flags. Common mappings:
   - "critical" / "high" → `--severity CRITICAL` (repeatable).
   - "score above 9", "CVSS ≥ 9" → `--min-score 9`.
   - "with a public exploit", "exploitable" → `--has-exploit`.
   - "patched", "has a fix" → `--has-fix`.
   - "since July", "this week", a date → `--since YYYY-MM-DD` (and
     `--until`). Resolve relative dates against today's date.
   - "about apache", free text → `--fts apache`.
   - "most severe first" → `--sort score` (default); "newest" →
     `--sort created`.
3. **Resolve vendor/product names first.** The `--vendor`/`--product` filters
   match the API's canonical names, so a guess often returns zero rows. When a
   value is uncertain, run `dbugs suggest products <pattern>` (or `vendors`)
   and use a returned value. Mention the chosen canonical name to the user.
4. **Run the command**, keeping `--limit` modest (10–20) for interactive
   answers unless the user asks for more.
5. **Summarize** the table output in prose: lead with the count and the most
   important rows (highest score, exploited, unpatched). Cite ids
   (`PT-…`/`CVE-…`) so the user can drill in with `dbugs vuln <id>` or the
   `/dbugs:triage` command.

## When to use --json

Default to the human-readable table and summarize it. Use the global `--json`
flag (placed **before** the subcommand) only when:

- The user asks for raw/machine output, or
- Post-processing with `jq` is needed (extract a field, count, reshape).

```bash
dbugs --json vulns --vendor microsoft --severity CRITICAL | jq '.rows[].vulner_id'
```

Raw field names differ from the table headers — see the JSON section of
`references/commands.md` (`vulner_id`, `max_score`, `max_severity`, …).

## Key behaviors to respect

- **Trends are fixed and filtered client-side.** `dbugs trends` fetches ~30
  rows and applies `--min-score`/`--severity`/`--min-posts`/`--sort`/`--limit`
  locally. Do not expect server-side trend filtering or large result sets.
- **Full export ≠ interactive listing.** `--limit`/`--page` page through
  results for display. To pull an *entire* result set, use `--export` (see the
  `report` skill / `/dbugs:report`), which auto-paginates and ignores
  `--limit`/`--page`.
- **Errors are clean.** A non-zero exit prints `Error: …` to stderr (never a
  traceback). A 403 means the anti-bot layer rejected the request — report it
  plainly; it is not a bug in the query.
- **Read-only.** No command mutates anything; safe to run freely.

## Additional resources

- **`references/commands.md`** — exhaustive per-command flag tables, repeatable
  flags, export semantics, raw JSON field names, and `jq` examples.
