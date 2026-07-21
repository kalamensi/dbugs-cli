# Filter `vuln` references by source

**Date:** 2026-07-21
**Status:** Approved

## Problem

`dbugs vuln <id>` fetches a vulnerability's full detail and renders every
reference in a single table. There is no way to narrow those references to a
particular kind of source (e.g. `Exploit`, `Note`, `Vendor Advisory`), so users
scanning for, say, exploit links have to read the whole table.

The dbugs API returns references embedded in the vulnerability detail payload
(`GET /vulnerabilities/{id}` → `references: [{ref_url, domain, source, stars,
forks, is_deleted}]`). There is **no** standalone references endpoint and no
server-side reference filter, so filtering must happen client-side over the
already-fetched result.

## Goal

Add a repeatable `--source` option to the `vuln` command that keeps only the
references whose `source` matches one of the given values, case-insensitively
and exactly. The filter applies to both the rendered table and `--json` output.

Non-goals: a standalone `references` command; substring/fuzzy source matching;
filtering any other section of the detail; sorting references.

## Design

### Layering

This is a client-side filter over an already-fetched result, so it lives in
`transform.py` alongside `filter_sort_trends` — **not** in `client.py`. HTTP
stays confined to `client.py`; `formatters.py` stays I/O-free.

Data flow: `cli → client.get_vuln → transform.filter_references → formatters`.

### `transform.filter_references`

```python
def filter_references(d: VulnDetail, *, source: list[str] | None = None) -> VulnDetail:
    if not source:
        return d
    wanted = {s.casefold() for s in source}
    refs = [r for r in d.references if (r.source or "").casefold() in wanted]
    raw = {**d.raw, "references": [r.raw for r in refs]}
    return VulnDetail(
        vuln=d.vuln,
        cwe_ids=d.cwe_ids,
        impacts=d.impacts,
        cvss=d.cvss,
        references=refs,
        related_news=d.related_news,
        duplicates=d.duplicates,
        researchers=d.researchers,
        raw=raw,
    )
```

- Matching is case-insensitive and exact via `str.casefold()` on both sides.
- `.raw` shape is preserved: only the `references` array is narrowed, so
  `--json` remains the exact API payload except for the filter the user asked
  for. This honors the project's `.raw` convention while keeping the filter
  consistent across output modes.
- When `source` is `None` or empty, the detail is returned unchanged.

### CLI wiring (`cli.py`, `vuln` command)

```python
source: list[str] = typer.Option(
    None, "--source",
    help="Filter references by source, e.g. Exploit, Note, 'Vendor Advisory' "
         "(repeatable, case-insensitive)."),
...
result = state.client.get_vuln(vuln_id, fts=fts)
result = transform.filter_references(result, source=source or None)
_emit(state, result, formatters.render_vuln_detail(result))
```

No changes to `client.py`, `models.py`, or `formatters.py`.

## Edge cases

- **No `--source`** → unchanged detail (full references).
- **`--source` matches nothing** → the references section simply does not
  render (existing `if d.references` guard in `render_vuln_detail`); `--json`
  gets `"references": []`. No special "0 matched" messaging — consistent with
  the current behavior when a vuln has no references.
- **Multi-word sources** (e.g. `Vendor Advisory`) must be quoted on the command
  line: `--source "Vendor Advisory"`. Documented in the help text.

## Testing

- `tests/test_transform.py`
  - filters references case-insensitively (`exploit` matches `Exploit`);
  - narrows `.raw["references"]` to the matching entries;
  - returns the detail unchanged when `source` is `None` or empty.
- `tests/test_cli.py` (HTTP mocked with `respx`)
  - `vuln <id> --source Exploit` narrows the rendered references table;
  - `vuln <id> --source Exploit --json` narrows the payload's `references`
    array while leaving the rest of the payload intact.

## Docs

- `README.md`: add `--source` to the `vuln` command reference.
