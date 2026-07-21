---
name: dbugs report
description: This skill should be used when the user runs "/dbugs:report", or asks to "export all matching vulns", "pull every WordPress advisory", "build a report of critical Microsoft vulns this month", "dump the full result set to a file", "give me a rollup/summary of vulns matching X". Drives the dbugs CLI --export flow to fetch a COMPLETE filtered result set (auto-paginated JSON/JSONL), then summarizes it into a report or table.
argument-hint: [natural-language query, e.g. "critical microsoft vulns since 2026-07-01"]
allowed-tools: Bash, Read, Write
version: 0.1.0
---

# dbugs report

## Purpose

Produce a report over the **entire** set of vulnerabilities or news items
matching a filter — not just the first page. Use the `dbugs` CLI `--export`
flow, which auto-paginates through every result (bypassing the interactive
`--limit`/`--page` cap) and writes them to a file, then read that file back
and summarize it.

This skill builds on the `query` skill for filter mapping; consult
`../query/references/commands.md` for the full flag reference.

## When to export vs. list

- **Interactive listing** (`dbugs vulns …` without `--export`) is for a quick
  look at the top N — use the `query` skill for that.
- **Export** (this skill) is for completeness: reporting, counting, feeding
  another tool, or any "all of them" request. Only `vulns` and `news` support
  `--export`.

## Workflow

1. **Confirm the CLI is available** (`dbugs --help >/dev/null 2>&1`). Use
   `.venv/bin/dbugs` if the project uses a virtualenv.

2. **Build the filter** from the user's request, exactly as in the `query`
   skill (severity, score, dates, vendor/product, fts, …). Resolve uncertain
   `--vendor`/`--product` values with `dbugs suggest …` first — an export with
   a wrong product name silently yields zero rows.

3. **Choose an output path and format.** Write exports to the scratchpad
   unless the user names a location. Format is inferred from the extension:
   - `.jsonl` → one JSON object per line, streamed. Best for large sets.
   - any other extension → a single `{"count": N, "rows": [...]}` document.
   Override with `--format json|jsonl` when needed.

4. **Run the export.** `--export` ignores `--limit`/`--page` and prints
   progress (`Exported X/Y rows`) to stderr:
   ```bash
   dbugs vulns --vendor microsoft --severity CRITICAL --since 2026-07-01 \
     --export /path/to/out.jsonl
   ```
   ```bash
   dbugs news --product Wordpress --since 2026-07-01 --export /path/to/news.json
   ```

5. **Read the file back and summarize.** For `.json`, read the document and
   use its `count`. For `.jsonl`, count lines and stream-parse. Summaries
   should include: total count, the breakdown that matters (by severity,
   vendor, exploited vs. not, has-fix vs. not), and the standout rows
   (highest score, exploited-and-unpatched). Prefer `jq` for aggregates over
   large files rather than loading everything into context:
   ```bash
   jq -s 'group_by(.max_severity) | map({sev: .[0].max_severity, n: length})' out.jsonl
   jq -s 'map(select(.has_exploits and (.has_fix|not))) | length' out.jsonl
   ```

6. **Report.** Present the rollup as prose plus a small table, name the export
   file path so the user keeps the full data, and show the exact command used.

## Notes

- The written `count` for `.json` reflects rows actually written, which can be
  slightly under the API's reported total if a zero-row page stops the export
  early — treat it as the authoritative on-disk count.
- Large exports can be slow (100 rows/request). For quick answers prefer the
  `query` skill; reserve export for genuine full-set needs.
- Rows are the exact raw API dicts — field names are `vulner_id`, `max_score`,
  `max_severity`, `has_exploits`, `has_fix`, etc. (see the `query` skill's
  reference).
