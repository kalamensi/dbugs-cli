# Filter `vuln` references by source — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a repeatable `--source` option to the `dbugs vuln <id>` command that narrows the fetched references to those whose `source` matches (exact, case-insensitive), in both table and `--json` output.

**Architecture:** Client-side filter over an already-fetched `VulnDetail`. A new pure function `transform.filter_references` narrows both the `references` list and the `.raw["references"]` array; `cli.py` wires the option and calls the transform between `client.get_vuln` and `_emit`. No changes to `client.py`, `models.py`, or `formatters.py`.

**Tech Stack:** Python ≥3.10, Typer, Rich, pytest (HTTP mocked via `respx`, but these tests mock the client directly with `unittest.mock.patch`).

## Global Constraints

- Python ≥3.10; runtime deps limited to `httpx`, `typer`, `rich`.
- Strict one-way layering: `cli → client → models`, then `cli → transform`/`formatters`. No HTTP outside `client.py`; no I/O in `formatters.py`. Client-side filtering belongs in `transform.py`.
- **`.raw` convention:** every model keeps its source dict in `.raw`; `--json` emits `.raw`. A filter must narrow `.raw` consistently so `--json` reflects it while keeping the payload shape intact.
- Output goes through the `_emit(state, result, renderable)` helper.
- Matching is exact and case-insensitive via `str.casefold()`.

---

### Task 1: `transform.filter_references`

**Files:**
- Modify: `dbugs_cli/transform.py` (add function + import `VulnDetail`)
- Test: `tests/test_transform.py`

**Interfaces:**
- Consumes: `dbugs_cli.models.VulnDetail`, `dbugs_cli.models.Reference` (each `Reference` has `.source: str | None` and `.raw: dict`; `VulnDetail` has `.vuln, .cwe_ids, .impacts, .cvss, .references, .related_news, .duplicates, .researchers, .raw`).
- Produces: `filter_references(d: VulnDetail, *, source: list[str] | None = None) -> VulnDetail` — returns `d` unchanged when `source` is falsy; otherwise a new `VulnDetail` whose `references` and `.raw["references"]` contain only entries whose `source` casefold-matches one of `source`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_transform.py`:

```python
from dbugs_cli.models import VulnDetail
from dbugs_cli.transform import filter_references


def _detail():
    return VulnDetail.from_dict({
        "vulner_id": "PT-1", "cve_id": "CVE-1",
        "references": [
            {"ref_url": "https://a", "domain": "a", "source": "Note"},
            {"ref_url": "https://b", "domain": "b", "source": "Exploit"},
            {"ref_url": "https://c", "domain": "c", "source": "Vendor Advisory"},
        ],
    })


def test_filter_references_none_returns_unchanged():
    d = _detail()
    assert filter_references(d, source=None) is d
    assert filter_references(d, source=[]) is d


def test_filter_references_exact_case_insensitive():
    out = filter_references(_detail(), source=["exploit"])
    assert [r.source for r in out.references] == ["Exploit"]
    # exact, not substring: "vendor" must NOT match "Vendor Advisory"
    assert filter_references(_detail(), source=["vendor"]).references == []


def test_filter_references_multiple_sources():
    out = filter_references(_detail(), source=["Note", "Vendor Advisory"])
    assert {r.source for r in out.references} == {"Note", "Vendor Advisory"}


def test_filter_references_narrows_raw():
    out = filter_references(_detail(), source=["Exploit"])
    assert [r["source"] for r in out.raw["references"]] == ["Exploit"]
    # untouched payload keys survive
    assert out.raw["vulner_id"] == "PT-1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_transform.py -k filter_references -v`
Expected: FAIL — `ImportError: cannot import name 'filter_references'`.

- [ ] **Step 3: Implement the function**

In `dbugs_cli/transform.py`, extend the import line and add the function:

```python
from dbugs_cli.models import TrendList, VulnDetail
```

```python
def filter_references(
    d: VulnDetail,
    *,
    source: list[str] | None = None,
) -> VulnDetail:
    """Keep only references whose source matches (exact, case-insensitive).

    Returns the detail unchanged when no source filter is given. Narrows both
    the parsed `references` list and `.raw["references"]` so `--json` reflects
    the filter while keeping the rest of the payload intact.
    """
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_transform.py -k filter_references -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add dbugs_cli/transform.py tests/test_transform.py
git commit -m "feat: add transform.filter_references for source filtering"
```

---

### Task 2: Wire `--source` into the `vuln` command

**Files:**
- Modify: `dbugs_cli/cli.py` (the `vuln` command, ~lines 183-193)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `transform.filter_references` (Task 1); `state.client.get_vuln(vuln_id, fts=...) -> VulnDetail`; `formatters.render_vuln_detail`; `_emit`.
- Produces: `dbugs vuln <id> [--source S ...]` — CLI behavior only; nothing downstream consumes it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
from dbugs_cli.models import VulnDetail


def _detail_fixture():
    return VulnDetail.from_dict({
        "vulner_id": "PT-2026-1", "cve_id": "CVE-2026-1",
        "max_score": 9.8, "max_severity": "CRITICAL",
        "references": [
            {"ref_url": "https://note", "domain": "note.io", "source": "Note"},
            {"ref_url": "https://exp", "domain": "exp.io", "source": "Exploit"},
            {"ref_url": "https://adv", "domain": "adv.io", "source": "Vendor Advisory"},
        ],
    })


def test_vuln_source_filter_narrows_table():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.get_vuln.return_value = _detail_fixture()
        result = runner.invoke(app, ["vuln", "CVE-2026-1", "--source", "exploit"])
    assert result.exit_code == 0
    assert "exp.io" in result.stdout
    assert "note.io" not in result.stdout
    assert "adv.io" not in result.stdout


def test_vuln_source_filter_narrows_json():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.get_vuln.return_value = _detail_fixture()
        result = runner.invoke(
            app, ["--json", "vuln", "CVE-2026-1", "--source", "Vendor Advisory"]
        )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [r["source"] for r in payload["references"]] == ["Vendor Advisory"]
    assert payload["vulner_id"] == "PT-2026-1"


def test_vuln_without_source_shows_all_references():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.get_vuln.return_value = _detail_fixture()
        result = runner.invoke(app, ["vuln", "CVE-2026-1"])
    assert result.exit_code == 0
    assert "note.io" in result.stdout and "exp.io" in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -k "vuln_source or vuln_without_source" -v`
Expected: FAIL — the filter tests fail because `--source` is not a known option (exit code 2) / all references still render.

- [ ] **Step 3: Add the option and wire the transform**

In `dbugs_cli/cli.py`, the `vuln` command currently reads:

```python
def vuln(
    ctx: typer.Context,
    vuln_id: str = typer.Argument(..., help="Vulnerability id, e.g. PT-2026-61063 or CVE id."),
    fts: str = typer.Option(None, "--fts", help="Highlight term."),
):
    """Show full detail for one vulnerability (incl. references)."""
    state: AppState = ctx.obj
    result = state.client.get_vuln(vuln_id, fts=fts)
    _emit(state, result, formatters.render_vuln_detail(result))
```

Replace it with:

```python
def vuln(
    ctx: typer.Context,
    vuln_id: str = typer.Argument(..., help="Vulnerability id, e.g. PT-2026-61063 or CVE id."),
    fts: str = typer.Option(None, "--fts", help="Highlight term."),
    source: list[str] = typer.Option(
        None, "--source",
        help="Filter references by source, e.g. Exploit, Note, 'Vendor Advisory' "
             "(repeatable, case-insensitive).",
    ),
):
    """Show full detail for one vulnerability (incl. references)."""
    state: AppState = ctx.obj
    result = state.client.get_vuln(vuln_id, fts=fts)
    result = transform.filter_references(result, source=source or None)
    _emit(state, result, formatters.render_vuln_detail(result))
```

(`transform` is already imported at the top of `cli.py`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -k "vuln_source or vuln_without_source" -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full suite**

Run: `pytest -q`
Expected: all tests pass (no regressions).

- [ ] **Step 6: Commit**

```bash
git add dbugs_cli/cli.py tests/test_cli.py
git commit -m "feat: add --source reference filter to vuln command"
```

---

### Task 3: Document `--source` in the README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing. Docs only.
- Produces: nothing.

- [ ] **Step 1: Add a usage example**

In `README.md`, in the `## Usage` fenced block, immediately after the line:

```
dbugs vuln PT-2026-61063                       # full detail incl. references
```

add:

```
dbugs vuln PT-2026-61063 --source Exploit --source Note   # filter references by source
```

- [ ] **Step 2: Add an explanatory subsection**

After the `### Filtering trends` subsection (before `### Exporting full results`), add:

```markdown
### Filtering vulnerability references

`dbugs vuln <id>` accepts `--source` (repeatable) to keep only references
whose source matches — exact, case-insensitive. Common sources are `Exploit`,
`Note`, and `Vendor Advisory` (quote multi-word values). The filter applies to
both the table and `--json` output.

```bash
dbugs vuln PT-2026-61063 --source Exploit
dbugs --json vuln PT-2026-61063 --source "Vendor Advisory" | jq '.references'
```
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document --source reference filter for vuln"
```

---

## Notes for the implementer

- Run tests with `pytest` from the repo root; the package is installed editable (`pip install -e ".[dev]"`).
- Do not touch `client.py`, `models.py`, or `formatters.py` — the feature is entirely a `transform` + `cli` change.
- The `render_vuln_detail` formatter already guards the references block with `if d.references:`, so an empty filtered list correctly renders no references section — no formatter change needed.
