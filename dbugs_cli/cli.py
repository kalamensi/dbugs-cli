"""Typer CLI for the dbugs vulnerability database."""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from functools import wraps
from typing import Callable

import typer
from rich.console import Console

from dbugs_cli import export, formatters, transform
from dbugs_cli.client import DbugsAPIError, DbugsClient

app = typer.Typer(
    add_completion=False,
    help="Query the dbugs.ptsecurity.com vulnerability database.",
    no_args_is_help=True,
)

# Map user-facing sort names to API `sorts[].field` values.
SORT_FIELDS = {
    "score": "max_score",
    "created": "created",
    "updated": "updated",
    "severity": "severity",
}


class SuggestField(str, Enum):
    products = "products"
    vendors = "vendors"


class TrendSort(str, Enum):
    score = "score"
    posts = "posts"


@dataclass
class AppState:
    client: DbugsClient
    json_output: bool
    console: Console
    err_console: Console


@app.callback()
def main(
    ctx: typer.Context,
    json_output: bool = typer.Option(False, "--json", help="Emit raw API JSON."),
    locale: str = typer.Option("en", "--locale", help="Response locale."),
    timeout: float = typer.Option(30.0, "--timeout", help="HTTP timeout (seconds)."),
):
    ctx.obj = AppState(
        client=DbugsClient(locale=locale, timeout=timeout),
        json_output=json_output,
        console=Console(),
        err_console=Console(stderr=True),
    )


def command(fn: Callable) -> Callable:
    """Wrap a command body with the shared API error boundary."""

    @wraps(fn)
    def wrapper(ctx: typer.Context, *args, **kwargs):
        state: AppState = ctx.obj
        try:
            return fn(ctx, *args, **kwargs)
        except DbugsAPIError as exc:
            if state.json_output:
                state.console.print_json(data={"error": str(exc)})
            else:
                state.err_console.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)
        except Exception as exc:  # noqa: BLE001 - last-resort guard so users never see a traceback
            if state.json_output:
                state.console.print_json(data={"error": str(exc)})
            else:
                state.err_console.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(1)

    return wrapper


def _emit(state: AppState, result, renderable) -> None:
    if state.json_output:
        raw = result.raw if hasattr(result, "raw") else result
        state.console.print_json(json.dumps(raw))
    else:
        state.console.print(renderable)


@app.command()
@command
def stats(ctx: typer.Context):
    """Show global database statistics."""
    state: AppState = ctx.obj
    result = state.client.stats()
    _emit(state, result, formatters.render_stats(result))


@app.command()
@command
def vulns(
    ctx: typer.Context,
    fts: str = typer.Option(None, "--fts", help="Full-text search."),
    vendor: list[str] = typer.Option(None, "--vendor", help="Filter by vendor (repeatable)."),
    product: list[str] = typer.Option(None, "--product", help="Filter by product (repeatable)."),
    researcher: list[str] = typer.Option(None, "--researcher", help="Filter by researcher (repeatable)."),
    severity: list[str] = typer.Option(None, "--severity", help="CRITICAL/HIGH/MEDIUM/LOW (repeatable)."),
    min_score: float = typer.Option(None, "--min-score", help="Minimum CVSS score."),
    max_score: float = typer.Option(None, "--max-score", help="Maximum CVSS score."),
    has_exploit: bool = typer.Option(False, "--has-exploit", help="Only vulns with known exploits."),
    has_fix: bool = typer.Option(False, "--has-fix", help="Only vulns with a fix."),
    since: str = typer.Option(None, "--since", help="Created on/after YYYY-MM-DD."),
    until: str = typer.Option(None, "--until", help="Created on/before YYYY-MM-DD."),
    sort: str = typer.Option("score", "--sort", help="score|created|updated|severity."),
    ascending: bool = typer.Option(False, "--asc", help="Sort ascending (default descending)."),
    limit: int = typer.Option(20, "--limit", help="Rows per page."),
    page: int = typer.Option(1, "--page", help="Page number."),
    export_path: str = typer.Option(None, "--export", help="Write the full filtered result set to this file (auto-paginates; ignores --limit/--page)."),
    export_format: str = typer.Option(None, "--format", help="Export format: json or jsonl (default inferred from --export file extension)."),
):
    """Search / list vulnerabilities."""
    state: AppState = ctx.obj
    sort_field = SORT_FIELDS.get(sort)
    if sort_field is None:
        raise typer.BadParameter(f"--sort must be one of {', '.join(SORT_FIELDS)}")

    if export_format and not export_path:
        raise typer.BadParameter("--format requires --export")

    if export_path:
        fmt = export.resolve_format(export_path, export_format)
        sev = [s.upper() for s in severity] if severity else None

        def fetch_page(page_num: int):
            result = state.client.search_vulns(
                fts=fts,
                vendor=vendor or None,
                product=product or None,
                researcher=researcher or None,
                severity=sev,
                score_from=min_score,
                score_to=max_score,
                has_exploit=True if has_exploit else None,
                has_fix=True if has_fix else None,
                created_from=since,
                created_to=until,
                sort=sort_field,
                descending=not ascending,
                limit=export.BATCH,
                page=page_num,
            )
            return result.count, result.raw.get("rows", [])

        export.run_export(fetch_page, export_path, fmt, state.err_console)
        return

    result = state.client.search_vulns(
        fts=fts,
        vendor=vendor or None,
        product=product or None,
        researcher=researcher or None,
        severity=[s.upper() for s in severity] if severity else None,
        score_from=min_score,
        score_to=max_score,
        has_exploit=True if has_exploit else None,
        has_fix=True if has_fix else None,
        created_from=since,
        created_to=until,
        sort=sort_field,
        descending=not ascending,
        limit=limit,
        page=page,
    )
    _emit(state, result, formatters.render_vuln_list(result))


@app.command()
@command
def vuln(
    ctx: typer.Context,
    vuln_id: str = typer.Argument(..., help="Vulnerability id, e.g. PT-2026-61063 or CVE id."),
    fts: str = typer.Option(None, "--fts", help="Highlight term."),
):
    """Show full detail for one vulnerability (incl. references)."""
    state: AppState = ctx.obj
    result = state.client.get_vuln(vuln_id, fts=fts)
    _emit(state, result, formatters.render_vuln_detail(result))


@app.command()
@command
def trends(
    ctx: typer.Context,
    min_score: float = typer.Option(None, "--min-score", help="Keep trends with score >= this."),
    severity: list[str] = typer.Option(None, "--severity", help="CRITICAL/HIGH/MEDIUM/LOW (repeatable)."),
    min_posts: int = typer.Option(None, "--min-posts", help="Keep trends with at least this many posts."),
    sort: TrendSort = typer.Option(None, "--sort", help="score|posts."),
    ascending: bool = typer.Option(False, "--asc", help="Sort ascending (default descending)."),
    limit: int = typer.Option(None, "--limit", help="Keep only the first N after filter/sort."),
):
    """List trending vulnerabilities (filter/sort applied client-side)."""
    state: AppState = ctx.obj
    result = state.client.trends()
    result = transform.filter_sort_trends(
        result,
        min_score=min_score,
        severity=[s.upper() for s in severity] if severity else None,
        min_posts=min_posts,
        sort=sort.value if sort else None,
        descending=not ascending,
        limit=limit,
    )
    _emit(state, result, formatters.render_trends(result))


@app.command()
@command
def trend(
    ctx: typer.Context,
    vuln_id: str = typer.Argument(..., help="Vulnerability id of the trend."),
    limit: int = typer.Option(5, "--limit", help="Posts per page."),
    page: int = typer.Option(1, "--page", help="Page number."),
):
    """Show social-media posts driving a vulnerability's trend."""
    state: AppState = ctx.obj
    result = state.client.trend_posts(vuln_id, limit=limit, page=page)
    _emit(state, result, formatters.render_posts(result))


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
    export_path: str = typer.Option(None, "--export", help="Write the full filtered result set to this file (auto-paginates; ignores --limit/--page)."),
    export_format: str = typer.Option(None, "--format", help="Export format: json or jsonl (default inferred from --export file extension)."),
):
    """List / filter security news."""
    state: AppState = ctx.obj

    if export_format and not export_path:
        raise typer.BadParameter("--format requires --export")

    if export_path:
        fmt = export.resolve_format(export_path, export_format)

        def fetch_page(page_num: int):
            result = state.client.news(
                fts=fts,
                product=product or None,
                vendor=vendor or None,
                researcher=researcher or None,
                cve_id=cve or None,
                category=category or None,
                published_from=since,
                published_to=until,
                limit=export.BATCH,
                page=page_num,
            )
            return result.count, result.raw.get("rows", [])

        export.run_export(fetch_page, export_path, fmt, state.err_console)
        return

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


@app.command(name="news-item")
@command
def news_item(
    ctx: typer.Context,
    slug: str = typer.Argument(..., help="News slug."),
):
    """Show one news article."""
    state: AppState = ctx.obj
    result = state.client.get_news(slug)
    _emit(state, result, formatters.render_news_item(result))


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


@app.command()
@command
def researcher(
    ctx: typer.Context,
    name: str = typer.Argument(..., help="Researcher name."),
    limit: int = typer.Option(20, "--limit", help="Vulns per page."),
    page: int = typer.Option(1, "--page", help="Page number."),
):
    """Show a researcher's profile and stats."""
    state: AppState = ctx.obj
    result = state.client.researcher(name, limit=limit, page=page)
    _emit(state, result, formatters.render_researcher(result))
