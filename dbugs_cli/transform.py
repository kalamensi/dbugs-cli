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
