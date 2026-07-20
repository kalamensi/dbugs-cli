# dbugs CLI Feature Expansion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add server-side news filters, client-side trends filter/sort, and news autocomplete (`suggest`) helpers to the existing `dbugs` CLI.

**Architecture:** Extend the existing layered package (client → models → formatters → cli). Add one new pure module `transform.py` for client-side trend filtering. `httpx` stays confined to `client.py`.

**Tech Stack:** Python 3.10+, httpx, Typer, Rich, pytest + respx. Virtualenv already at `.venv`; run tests with `.venv/bin/pytest`.

## Global Constraints

- Python 3.10+ (`from __future__ import annotations`, `X | None`, builtin generics).
- Base/headers/no-auth unchanged; `httpx` only in `client.py`.
- Build request bodies dropping `None` values (never send nulls — API returns 422 on unexpected keys/shapes).
- News filter body keys (verified): `product`, `vendor`, `researcher`, `cve_id`, `category` (all `list[str]`), `fts` (str), `published_from`/`published_to` (ISO date str). `cve_id` MUST be a list.
- Suggest endpoints return a bare JSON `list[str]`: `GET news/products?search_pattern=`, `GET news/vendors?search_pattern=`, `GET news/products/popular`, `GET news/vendors/popular`.
- Trends server returns a fixed 30 rows with no filter params → filtering/sorting is client-side.
- `TrendVuln` uses `.score`/`.severity` (NOT `max_*`).
- All commands keep the existing `--json` convention via `_emit` (emits `result.raw` for models).

## Existing code (reference — do not rewrite, only extend)

- `dbugs_cli/client.py:183` current `news`: `def news(self, limit=20, page=1, locale=None) -> NewsList` → `POST "news/"`.
- `dbugs_cli/client.py:173` `trends(self, locale=None) -> TrendList` → `GET "trending"`. Leave unchanged.
- `dbugs_cli/cli.py` `news` command (flags `--limit`/`--page`) and `trends` command (no flags). `_emit(state, result, renderable)` emits `result.raw` under `--json` else the renderable. `@command` decorator is the error boundary. `SORT_FIELDS` dict exists for vulns.
- `dbugs_cli/formatters.py`: `render_news_list(nl)`, `render_trends(tl)`, `render_stats`, helpers `_score`/`_sev_text`. `Panel`, `Table`, `Text`, `Group` already imported from rich.
- `dbugs_cli/models.py`: `TrendList(count, rows, raw)`, `Trend(lvl, posts_count, vuln, raw)`, `TrendVuln(..., score, severity, ...)`, `NewsList`.

---

### Task 1: Client — news filters + suggest methods

**Files:**
- Modify: `dbugs_cli/client.py` (replace `news`; add `suggest_products`, `suggest_vendors`)
- Test: `tests/test_client.py` (append)

**Interfaces:**
- Consumes: `_request` (existing), `NewsList` (existing import).
- Produces:
  - `DbugsClient.news(self, *, limit=20, page=1, fts=None, product=None, vendor=None, researcher=None, cve_id=None, category=None, published_from=None, published_to=None, locale=None) -> NewsList`
  - `DbugsClient.suggest_products(self, pattern: str | None = None) -> list[str]`
  - `DbugsClient.suggest_vendors(self, pattern: str | None = None) -> list[str]`

- [ ] **Step 1: Write the failing tests** — append to `tests/test_client.py`

```python
@respx.mock
def test_news_builds_filtered_body_and_drops_none():
    route = respx.post(f"{DEFAULT_BASE_URL}news/").mock(
        return_value=httpx.Response(200, json=_fx("news_list.json"))
    )
    nl = DbugsClient().news(
        fts="wordpress", product=["Wordpress"], vendor=["Microsoft"],
        cve_id=["CVE-2026-63030"], category=["cve"],
        published_from="2026-07-01", published_to="2026-07-20",
        limit=5, page=2,
    )
    assert nl.rows[0].slug == "critical-widget"
    body = json.loads(route.calls.last.request.content)
    assert body["fts"] == "wordpress"
    assert body["product"] == ["Wordpress"]
    assert body["vendor"] == ["Microsoft"]
    assert body["cve_id"] == ["CVE-2026-63030"]
    assert body["category"] == ["cve"]
    assert body["published_from"] == "2026-07-01"
    assert body["published_to"] == "2026-07-20"
    assert body["limit"] == 5 and body["page"] == 2
    assert "researcher" not in body  # None dropped


@respx.mock
def test_suggest_products_with_pattern_hits_search_path():
    route = respx.get(f"{DEFAULT_BASE_URL}news/products").mock(
        return_value=httpx.Response(200, json=["Wordpress", "Microsoft Word"])
    )
    result = DbugsClient().suggest_products("word")
    assert result == ["Wordpress", "Microsoft Word"]
    assert dict(route.calls.last.request.url.params) == {"search_pattern": "word"}


@respx.mock
def test_suggest_products_without_pattern_hits_popular():
    respx.get(f"{DEFAULT_BASE_URL}news/products/popular").mock(
        return_value=httpx.Response(200, json=["Windows", "Android"])
    )
    assert DbugsClient().suggest_products() == ["Windows", "Android"]


@respx.mock
def test_suggest_vendors_paths():
    respx.get(f"{DEFAULT_BASE_URL}news/vendors").mock(
        return_value=httpx.Response(200, json=["Microsoft"])
    )
    respx.get(f"{DEFAULT_BASE_URL}news/vendors/popular").mock(
        return_value=httpx.Response(200, json=["Google"])
    )
    assert DbugsClient().suggest_vendors("micro") == ["Microsoft"]
    assert DbugsClient().suggest_vendors() == ["Google"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_client.py -k "news_builds or suggest" -v`
Expected: FAIL — `TypeError` (news got unexpected kwarg) / `AttributeError` (no `suggest_products`).

- [ ] **Step 3: Replace `news` and add suggest methods in `dbugs_cli/client.py`**

Replace the existing `news` method (currently at `dbugs_cli/client.py:183`) with:
```python
    def news(
        self,
        *,
        limit: int = 20,
        page: int = 1,
        fts: str | None = None,
        product: list[str] | None = None,
        vendor: list[str] | None = None,
        researcher: list[str] | None = None,
        cve_id: list[str] | None = None,
        category: list[str] | None = None,
        published_from: str | None = None,
        published_to: str | None = None,
        locale: str | None = None,
    ) -> NewsList:
        body: dict = {"limit": limit, "page": page, "locale": locale or self.locale}
        optional = {
            "fts": fts,
            "product": list(product) if product else None,
            "vendor": list(vendor) if vendor else None,
            "researcher": list(researcher) if researcher else None,
            "cve_id": list(cve_id) if cve_id else None,
            "category": list(category) if category else None,
            "published_from": published_from,
            "published_to": published_to,
        }
        body.update({k: v for k, v in optional.items() if v is not None})
        return NewsList.from_dict(self._request("POST", "news/", json_body=body))

    def suggest_products(self, pattern: str | None = None) -> list[str]:
        if pattern:
            return self._request("GET", "news/products", params={"search_pattern": pattern})
        return self._request("GET", "news/products/popular")

    def suggest_vendors(self, pattern: str | None = None) -> list[str]:
        if pattern:
            return self._request("GET", "news/vendors", params={"search_pattern": pattern})
        return self._request("GET", "news/vendors/popular")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_client.py -v`
Expected: PASS (existing + 4 new). The existing `test_news_returns_newslist` calls `.news(limit=5)` (keyword) so it still works.

- [ ] **Step 5: Commit**

```bash
git add dbugs_cli/client.py tests/test_client.py
git commit -m "feat: add news filters + suggest client methods"
```

---

### Task 2: transform.py — client-side trends filter/sort

**Files:**
- Create: `dbugs_cli/transform.py`
- Test: `tests/test_transform.py`

**Interfaces:**
- Consumes: `TrendList`, `Trend` (from `dbugs_cli.models`).
- Produces: `filter_sort_trends(tl: TrendList, *, min_score: float | None = None, severity: list[str] | None = None, min_posts: int | None = None, sort: str | None = None, descending: bool = True, limit: int | None = None) -> TrendList`

- [ ] **Step 1: Write the failing test** in `tests/test_transform.py`

```python
from dbugs_cli.models import TrendList
from dbugs_cli.transform import filter_sort_trends


def _tl():
    return TrendList.from_dict({"count": 3, "rows": [
        {"lvl": 1, "posts_count": 10, "vulnerability": {"vulner_id": "A", "cve_id": "CVE-A",
            "score": 9.8, "severity": "CRITICAL"}},
        {"lvl": 2, "posts_count": 50, "vulnerability": {"vulner_id": "B", "cve_id": "CVE-B",
            "score": 5.0, "severity": "MEDIUM"}},
        {"lvl": 3, "posts_count": 2, "vulnerability": {"vulner_id": "C", "cve_id": "CVE-C",
            "score": None, "severity": None}},
    ]})


def test_min_score_filters_and_drops_none_scores():
    out = filter_sort_trends(_tl(), min_score=9.0)
    assert [t.vuln.vulner_id for t in out.rows] == ["A"]
    assert out.count == 1


def test_severity_filter_case_insensitive():
    out = filter_sort_trends(_tl(), severity=["critical", "medium"])
    assert {t.vuln.vulner_id for t in out.rows} == {"A", "B"}


def test_min_posts_filter():
    out = filter_sort_trends(_tl(), min_posts=10)
    assert {t.vuln.vulner_id for t in out.rows} == {"A", "B"}


def test_sort_by_posts_desc_and_asc():
    desc = filter_sort_trends(_tl(), sort="posts")
    assert [t.vuln.vulner_id for t in desc.rows] == ["B", "A", "C"]
    asc = filter_sort_trends(_tl(), sort="posts", descending=False)
    assert [t.vuln.vulner_id for t in asc.rows] == ["C", "A", "B"]


def test_sort_by_score_puts_none_last_when_desc():
    out = filter_sort_trends(_tl(), sort="score")
    assert [t.vuln.vulner_id for t in out.rows] == ["A", "B", "C"]


def test_limit_truncates_after_sort():
    out = filter_sort_trends(_tl(), sort="posts", limit=1)
    assert [t.vuln.vulner_id for t in out.rows] == ["B"]
    assert out.count == 1


def test_rebuilds_raw_from_kept_rows():
    out = filter_sort_trends(_tl(), min_posts=10, sort="posts")
    assert out.raw["count"] == 2
    assert [r["vulnerability"]["vulner_id"] for r in out.raw["rows"]] == ["B", "A"]


def test_no_filters_keeps_all():
    out = filter_sort_trends(_tl())
    assert out.count == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_transform.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'dbugs_cli.transform'`.

- [ ] **Step 3: Write `dbugs_cli/transform.py`**

```python
"""Client-side transforms over API results.

The dbugs trending endpoint returns a fixed set of rows with no server-side
filter or sort parameters, so any filtering/sorting happens here, over the
already-fetched rows.
"""
from __future__ import annotations

from dbugs_cli.models import TrendList


def filter_sort_trends(
    tl: TrendList,
    *,
    min_score: float | None = None,
    severity: list[str] | None = None,
    min_posts: int | None = None,
    sort: str | None = None,
    descending: bool = True,
    limit: int | None = None,
) -> TrendList:
    rows = list(tl.rows)

    if min_score is not None:
        rows = [t for t in rows if t.vuln.score is not None and t.vuln.score >= min_score]
    if severity:
        wanted = {s.upper() for s in severity}
        rows = [t for t in rows if (t.vuln.severity or "").upper() in wanted]
    if min_posts is not None:
        rows = [t for t in rows if t.posts_count >= min_posts]

    if sort == "score":
        rows.sort(
            key=lambda t: t.vuln.score if t.vuln.score is not None else float("-inf"),
            reverse=descending,
        )
    elif sort == "posts":
        rows.sort(key=lambda t: t.posts_count, reverse=descending)

    if limit is not None:
        rows = rows[:limit]

    raw = {"count": len(rows), "rows": [t.raw for t in rows]}
    return TrendList(count=len(rows), rows=rows, raw=raw)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_transform.py -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add dbugs_cli/transform.py tests/test_transform.py
git commit -m "feat: add client-side trends filter/sort transform"
```

---

### Task 3: CLI wiring — news flags, trends flags, suggest command + formatter

**Files:**
- Modify: `dbugs_cli/formatters.py` (add `render_suggestions`; import `Columns`)
- Modify: `dbugs_cli/cli.py` (extend `news`, extend `trends`, add `suggest` + `SuggestField` enum, import `transform`)
- Test: `tests/test_formatters.py` (append), `tests/test_cli.py` (append)

**Interfaces:**
- Consumes: `client.news(...)`, `client.suggest_products/suggest_vendors` (Task 1); `transform.filter_sort_trends` (Task 2); existing `render_news_list`, `render_trends`.
- Produces: `formatters.render_suggestions(items: list[str], title: str) -> RenderableType`; CLI commands `news` (with filter flags), `trends` (with filter/sort flags), `suggest FIELD [PATTERN]`.

- [ ] **Step 1: Write the failing formatter test** — append to `tests/test_formatters.py`

```python
def test_render_suggestions_lists_items():
    out = _text(formatters.render_suggestions(["Windows", "Android", "Linux"], "Products"))
    assert "Windows" in out and "Android" in out and "Linux" in out


def test_render_suggestions_empty():
    out = _text(formatters.render_suggestions([], "Products"))
    assert "no matches" in out.lower()
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/pytest tests/test_formatters.py -k suggestions -v`
Expected: FAIL — `AttributeError: module 'dbugs_cli.formatters' has no attribute 'render_suggestions'`.

- [ ] **Step 3: Add `render_suggestions` to `dbugs_cli/formatters.py`**

Add `Columns` to the rich imports. The existing import line is:
```python
from rich.console import Group, RenderableType
```
Add a new import line beneath the other rich imports:
```python
from rich.columns import Columns
```
Then append this function to the file:
```python
def render_suggestions(items: list[str], title: str) -> RenderableType:
    if not items:
        return Panel(Text("(no matches)", style="dim"), title=title, expand=False)
    body = Columns([Text(f"• {item}") for item in items], equal=True, padding=(0, 2))
    return Panel(body, title=f"{title} ({len(items)})", expand=False)
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/pytest tests/test_formatters.py -k suggestions -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Write the failing CLI tests** — append to `tests/test_cli.py`

```python
from dbugs_cli.models import NewsList, TrendList


def test_news_command_forwards_filters():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.news.return_value = NewsList.from_dict(_fx("news_list.json"))
        runner.invoke(app, [
            "news", "--fts", "wordpress", "--product", "Wordpress",
            "--vendor", "Microsoft", "--cve", "CVE-2026-63030",
            "--category", "cve", "--since", "2026-07-01", "--until", "2026-07-20",
            "--limit", "5",
        ])
        kwargs = mock_cls.return_value.news.call_args.kwargs
    assert kwargs["fts"] == "wordpress"
    assert kwargs["product"] == ["Wordpress"]
    assert kwargs["vendor"] == ["Microsoft"]
    assert kwargs["cve_id"] == ["CVE-2026-63030"]
    assert kwargs["category"] == ["cve"]
    assert kwargs["published_from"] == "2026-07-01"
    assert kwargs["published_to"] == "2026-07-20"
    assert kwargs["limit"] == 5


def _trends_fixture():
    return TrendList.from_dict({"count": 2, "rows": [
        {"lvl": 1, "posts_count": 5, "vulnerability": {"vulner_id": "A", "cve_id": "CVE-A",
            "score": 9.8, "severity": "CRITICAL"}},
        {"lvl": 2, "posts_count": 99, "vulnerability": {"vulner_id": "B", "cve_id": "CVE-B",
            "score": 4.0, "severity": "MEDIUM"}},
    ]})


def test_trends_command_applies_filter():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.trends.return_value = _trends_fixture()
        result = runner.invoke(app, ["trends", "--min-score", "9"])
    assert result.exit_code == 0
    # only row A (score 9.8) survives min-score 9; render_trends title shows the count
    assert "Trending vulnerabilities (1)" in result.stdout
    assert "CVE-A" in result.stdout
    assert "CVE-B" not in result.stdout


def test_trends_command_json_reflects_filter():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.trends.return_value = _trends_fixture()
        result = runner.invoke(app, ["--json", "trends", "--min-posts", "10"])
    payload = json.loads(result.stdout)
    assert payload["count"] == 1
    assert payload["rows"][0]["vulnerability"]["vulner_id"] == "B"


def test_suggest_products_with_pattern():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.suggest_products.return_value = ["Wordpress"]
        result = runner.invoke(app, ["suggest", "products", "word"])
    assert result.exit_code == 0
    assert "Wordpress" in result.stdout
    assert mock_cls.return_value.suggest_products.call_args.args == ("word",)


def test_suggest_vendors_json():
    with patch("dbugs_cli.cli.DbugsClient") as mock_cls:
        mock_cls.return_value.suggest_vendors.return_value = ["Microsoft", "Google"]
        result = runner.invoke(app, ["--json", "suggest", "vendors"])
    assert json.loads(result.stdout) == ["Microsoft", "Google"]


def test_suggest_invalid_field_errors():
    with patch("dbugs_cli.cli.DbugsClient"):
        result = runner.invoke(app, ["suggest", "bogus"])
    assert result.exit_code != 0
```

- [ ] **Step 6: Run to verify fail**

Run: `.venv/bin/pytest tests/test_cli.py -k "news_command_forwards or trends_command or suggest" -v`
Expected: FAIL (news has no such flags yet / no `suggest` command).

- [ ] **Step 7: Edit `dbugs_cli/cli.py`**

Add imports near the top (after existing imports):
```python
from enum import Enum

from dbugs_cli import transform
```

Add the enum near `SORT_FIELDS`:
```python
class SuggestField(str, Enum):
    products = "products"
    vendors = "vendors"
```

Replace the existing `news` command with:
```python
@app.command()
@command
def news(
    ctx: typer.Context,
    fts: str = typer.Option(None, "--fts", help="Full-text search."),
    product: list[str] = typer.Option(None, "--product", help="Filter by product (repeatable)."),
    vendor: list[str] = typer.Option(None, "--vendor", help="Filter by vendor (repeatable)."),
    researcher: list[str] = typer.Option(None, "--researcher", help="Filter by researcher (repeatable)."),
    cve: list[str] = typer.Option(None, "--cve", help="Filter by CVE id (repeatable)."),
    category: list[str] = typer.Option(None, "--category", help="Filter by category (repeatable)."),
    since: str = typer.Option(None, "--since", help="Published on/after YYYY-MM-DD."),
    until: str = typer.Option(None, "--until", help="Published on/before YYYY-MM-DD."),
    limit: int = typer.Option(20, "--limit", help="Items per page."),
    page: int = typer.Option(1, "--page", help="Page number."),
):
    """List / filter security news."""
    state: AppState = ctx.obj
    result = state.client.news(
        fts=fts,
        product=product or None,
        vendor=vendor or None,
        researcher=researcher or None,
        cve_id=cve or None,
        category=category or None,
        published_from=since,
        published_to=until,
        limit=limit,
        page=page,
    )
    _emit(state, result, formatters.render_news_list(result))
```

Replace the existing `trends` command with:
```python
@app.command()
@command
def trends(
    ctx: typer.Context,
    min_score: float = typer.Option(None, "--min-score", help="Keep trends with score >= this."),
    severity: list[str] = typer.Option(None, "--severity", help="CRITICAL/HIGH/MEDIUM/LOW (repeatable)."),
    min_posts: int = typer.Option(None, "--min-posts", help="Keep trends with at least this many posts."),
    sort: str = typer.Option(None, "--sort", help="score|posts."),
    ascending: bool = typer.Option(False, "--asc", help="Sort ascending (default descending)."),
    limit: int = typer.Option(None, "--limit", help="Keep only the first N after filter/sort."),
):
    """List trending vulnerabilities (filter/sort applied client-side)."""
    state: AppState = ctx.obj
    if sort is not None and sort not in ("score", "posts"):
        raise typer.BadParameter("--sort must be 'score' or 'posts'")
    result = state.client.trends()
    result = transform.filter_sort_trends(
        result,
        min_score=min_score,
        severity=[s.upper() for s in severity] if severity else None,
        min_posts=min_posts,
        sort=sort,
        descending=not ascending,
        limit=limit,
    )
    _emit(state, result, formatters.render_trends(result))
```

Add a new `suggest` command (place after the `news-item` command):
```python
@app.command()
@command
def suggest(
    ctx: typer.Context,
    field: SuggestField = typer.Argument(..., help="What to suggest: products or vendors."),
    pattern: str = typer.Argument(None, help="Optional search text; omit for the popular list."),
):
    """Suggest valid news --product / --vendor filter values."""
    state: AppState = ctx.obj
    if field is SuggestField.products:
        result = state.client.suggest_products(pattern)
        title = "Products"
    else:
        result = state.client.suggest_vendors(pattern)
        title = "Vendors"
    _emit(state, result, formatters.render_suggestions(result, title))
```

Note: `_emit` already handles `list[str]` correctly — a list has no `.raw` attribute, so under `--json` it emits the list itself; otherwise it prints the `render_suggestions` renderable.

- [ ] **Step 8: Run to verify pass**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: PASS (existing + new).

- [ ] **Step 9: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS (all green, live tests skipped).

- [ ] **Step 10: Live smoke test**

Run:
```bash
.venv/bin/dbugs news --product Wordpress --limit 3
.venv/bin/dbugs trends --min-score 9 --sort posts --limit 5
.venv/bin/dbugs suggest products word
.venv/bin/dbugs suggest vendors
```
Expected: a filtered news table, a filtered+sorted trends table (≤5 CRITICAL-ish rows), a product suggestion list containing "Wordpress"-like entries, and a popular vendors list.

- [ ] **Step 11: Commit**

```bash
git add dbugs_cli/formatters.py dbugs_cli/cli.py tests/test_formatters.py tests/test_cli.py
git commit -m "feat: wire news filters, trends filter/sort, and suggest command"
```

---

### Task 4: Docs + opt-in live tests

**Files:**
- Modify: `README.md`
- Modify: `tests/test_live.py` (append)

**Interfaces:**
- Consumes: `DbugsClient.news`, `suggest_products` (Task 1).
- Produces: updated usage docs; live tests for the new features.

- [ ] **Step 1: Append live tests** to `tests/test_live.py`

```python
def test_live_news_filtered_by_product(client):
    nl = client.news(product=["Wordpress"], limit=3)
    assert nl.count >= 0
    assert len(nl.rows) <= 3


def test_live_suggest_products(client):
    items = client.suggest_products("word")
    assert isinstance(items, list)
    assert any("word" in s.lower() for s in items)


def test_live_suggest_popular(client):
    items = client.suggest_vendors()
    assert isinstance(items, list) and len(items) > 0
```

- [ ] **Step 2: Run live tests to verify they pass**

Run: `DBUGS_LIVE=1 .venv/bin/pytest tests/test_live.py -v`
Expected: PASS (7 total — 4 existing + 3 new).

- [ ] **Step 3: Verify default skip**

Run: `.venv/bin/pytest tests/test_live.py -v`
Expected: 7 skipped.

- [ ] **Step 4: Update `README.md`**

Under the Usage section, update the `news` example and add the trends-filter and suggest examples. Replace the existing `dbugs news` usage line and add lines so the Usage block includes:
```bash
dbugs news                                      # latest security news
dbugs news --product Wordpress --vendor Microsoft --fts rce
dbugs news --cve CVE-2026-63030 --since 2026-07-01
dbugs trends                                    # all 30 trending vulnerabilities
dbugs trends --min-score 9 --severity CRITICAL --sort posts --limit 10
dbugs suggest products word                     # discover valid --product values
dbugs suggest vendors                           # popular vendors (no pattern)
```
Add a short subsection after the Usage block:
```markdown
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
```

- [ ] **Step 5: Commit**

```bash
git add README.md tests/test_live.py
git commit -m "docs: document news filters, trends filtering, suggest; add live tests"
```

---

## Self-Review

**1. Spec coverage:**
- News server-side filters (product/vendor/researcher/cve_id/category/fts/published_from/to) → Task 1 (client) + Task 3 (CLI flags). ✓
- Trends client-side filter/sort via pure `transform.py`, rebuilt `raw` so `--json` reflects filter → Task 2 + Task 3. ✓
- `suggest` command + `suggest_products/vendors` client methods + `render_suggestions` → Tasks 1/3. ✓
- `--json` parity, error boundary, no-tracebacks preserved (reuses existing `_emit`/`@command`). ✓
- Testing (client body/paths, transform units, formatter, CLI forwarding + json + invalid field, live) → Tasks 1–4. ✓
- Non-goals honored: no researchers search, no categories command, no caching, no server-side trends filtering. ✓

**2. Placeholder scan:** No TBD/TODO/"handle edge cases". Every code step shows complete code; every command has expected output. All new API keys were live-verified.

**3. Type consistency:** `news(cve_id=...)` client param ← CLI `--cve` maps to `cve_id=cve or None` (consistent in Task 1 test, Task 3 CLI, and Task 4 live test). `filter_sort_trends` signature identical across Task 2 definition, its tests, and the Task 3 `trends` call. `suggest_products/suggest_vendors(pattern)` positional arg matches the Task 3 CLI call (`call_args.args == ("word",)`) and Task 1 tests. `render_suggestions(items, title)` matches formatter test and CLI call. `TrendList(count, rows, raw)` constructor used in transform matches `models.py`.
