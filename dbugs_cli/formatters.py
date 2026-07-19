"""Render dbugs models as Rich renderables. Pure functions, no I/O."""
from __future__ import annotations

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from dbugs_cli.models import (
    NewsItem,
    NewsList,
    Stats,
    TrendList,
    VulnDetail,
    VulnList,
)

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def severity_style(severity: str | None) -> str:
    if not severity:
        return "dim"
    return SEVERITY_COLORS.get(severity.upper(), "dim")


def _sev_text(severity: str | None) -> Text:
    label = severity or "-"
    return Text(label, style=severity_style(severity))


def _score(value) -> str:
    return "-" if value is None else f"{value}"


def _flags(has_fix: bool, has_exploits: bool) -> str:
    parts = []
    if has_exploits:
        parts.append("[red]exploit[/red]")
    if has_fix:
        parts.append("[green]fix[/green]")
    return " ".join(parts) or "-"


def render_stats(s: Stats) -> RenderableType:
    table = Table(show_header=False, box=None)
    table.add_row("Total vulnerabilities", f"[bold]{s.total_vulnerabilities:,}[/bold]")
    table.add_row("New this week", f"[bold]{s.new_this_week:,}[/bold]")
    table.add_row("Researchers", f"[bold]{s.authors:,}[/bold]")
    return Panel(table, title="dbugs stats", expand=False)


def render_vuln_list(vl: VulnList) -> RenderableType:
    table = Table(title=f"Vulnerabilities ({vl.count:,} total)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("CVE", no_wrap=True)
    table.add_column("Score", justify="right")
    table.add_column("Severity")
    table.add_column("Flags")
    table.add_column("Vendors")
    table.add_column("Updated", no_wrap=True)
    for v in vl.rows:
        table.add_row(
            v.vulner_id or "-",
            v.cve_id or "-",
            _score(v.max_score),
            _sev_text(v.max_severity),
            _flags(v.has_fix, v.has_exploits),
            ", ".join(map(str, v.vendors[:3])) or "-",
            v.updated or "-",
        )
    return table


def render_vuln_detail(d: VulnDetail) -> RenderableType:
    v = d.vuln
    header = Table(show_header=False, box=None)
    header.add_row("ID", v.vulner_id or "-")
    header.add_row("CVE", v.cve_id or "-")
    header.add_row("Score", _score(v.max_score))
    header.add_row("Severity", _sev_text(v.max_severity))
    header.add_row("CWE", ", ".join(map(str, d.cwe_ids)) or "-")
    header.add_row("Impacts", ", ".join(map(str, d.impacts)) or "-")
    header.add_row("Vendors", ", ".join(map(str, v.vendors)) or "-")
    header.add_row("Products", ", ".join(map(str, v.products)) or "-")
    header.add_row("Created / Updated", f"{v.created or '-'}  /  {v.updated or '-'}")

    blocks: list[RenderableType] = [Panel(header, title=v.vulner_id or "vulnerability")]

    if d.references:
        ref_table = Table(title="References", show_lines=False)
        ref_table.add_column("Source")
        ref_table.add_column("Domain", style="cyan")
        ref_table.add_column("URL")
        for r in d.references:
            ref_table.add_row(r.source or "-", r.domain or "-", r.ref_url or "-")
        blocks.append(ref_table)

    if d.researchers:
        who = Table(title="Researchers")
        who.add_column("Name")
        who.add_column("Rank", justify="right")
        who.add_column("Vulns", justify="right")
        for r in d.researchers:
            who.add_row(
                str(r.get("name", "-")),
                str(r.get("place", "-")),
                str(r.get("vulner_count", "-")),
            )
        blocks.append(who)

    if d.related_news:
        news = Table(title="Related news")
        news.add_column("Title")
        news.add_column("Published")
        for n in d.related_news:
            news.add_row(str(n.get("title", "-")), str(n.get("published", "-")))
        blocks.append(news)

    return Group(*blocks)


def render_trends(tl: TrendList) -> RenderableType:
    table = Table(title=f"Trending vulnerabilities ({tl.count})")
    table.add_column("#", justify="right")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("CVE", no_wrap=True)
    table.add_column("Score", justify="right")
    table.add_column("Severity")
    table.add_column("Posts", justify="right")
    for i, t in enumerate(tl.rows, start=1):
        table.add_row(
            str(i),
            t.vuln.vulner_id or "-",
            t.vuln.cve_id or "-",
            _score(t.vuln.score),
            _sev_text(t.vuln.severity),
            str(t.posts_count),
        )
    return table


def render_posts(posts: dict) -> RenderableType:
    rows = posts.get("rows", []) if isinstance(posts, dict) else []
    table = Table(title=f"Social posts ({posts.get('count', len(rows))})")
    table.add_column("Published", no_wrap=True)
    table.add_column("Text")
    table.add_column("URL", style="cyan")
    for p in rows:
        table.add_row(
            str(p.get("published", "-")),
            str(p.get("text", "-")),
            str(p.get("url", "-")),
        )
    return table


def render_news_list(nl: NewsList) -> RenderableType:
    table = Table(title=f"News ({nl.count})")
    table.add_column("Published", no_wrap=True)
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Slug", style="cyan")
    for n in nl.rows:
        table.add_row(
            n.published or "-",
            n.category or "-",
            n.title or "-",
            n.slug or "-",
        )
    return table


def render_news_item(item: NewsItem) -> RenderableType:
    body = item.raw.get("body") or item.summary or ""
    meta = Table(show_header=False, box=None)
    meta.add_row("Published", item.published or "-")
    meta.add_row("Category", item.category or "-")
    meta.add_row("CVEs", ", ".join(map(str, item.cve_ids)) or "-")
    meta.add_row("Vendors", ", ".join(map(str, item.vendors)) or "-")
    return Panel(Group(meta, Text(""), Text(str(body))), title=item.title or "news")


def render_researcher(data: dict) -> RenderableType:
    prof = data.get("researcher") or {}
    table = Table(show_header=False, box=None)
    table.add_row("Name", str(prof.get("name", "-")))
    table.add_row("Vulnerabilities", str(data.get("author_count", "-")))
    table.add_row("Critical", str(data.get("critical_severity", "-")))
    table.add_row("High", str(data.get("high_severity", "-")))
    table.add_row("Medium", str(data.get("medium_severity", "-")))
    table.add_row("Low", str(data.get("low_severity", "-")))
    for label, key in [("X", "x_link"), ("GitHub", "github_link"),
                       ("LinkedIn", "linkedin_link")]:
        if data.get(key):
            table.add_row(label, str(data[key]))
    return Panel(table, title=str(prof.get("name", "researcher")), expand=False)
