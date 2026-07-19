"""Typer CLI for the dbugs vulnerability database."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from functools import wraps
from typing import Callable

import typer
from rich.console import Console

from dbugs_cli import formatters
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
):
    """Search / list vulnerabilities."""
    state: AppState = ctx.obj
    sort_field = SORT_FIELDS.get(sort)
    if sort_field is None:
        raise typer.BadParameter(f"--sort must be one of {', '.join(SORT_FIELDS)}")
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
def trends(ctx: typer.Context):
    """List trending vulnerabilities."""
    state: AppState = ctx.obj
    result = state.client.trends()
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
    limit: int = typer.Option(20, "--limit", help="Items per page."),
    page: int = typer.Option(1, "--page", help="Page number."),
):
    """List security news."""
    state: AppState = ctx.obj
    result = state.client.news(limit=limit, page=page)
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
