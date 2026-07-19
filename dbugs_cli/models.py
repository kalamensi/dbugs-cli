"""Dataclasses parsed from dbugs API responses.

Every model keeps the source dict in `.raw` so the CLI can emit exact API
JSON under --json. Parsing is tolerant of missing keys for forward
compatibility.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Stats:
    total_vulnerabilities: int
    new_this_week: int
    authors: int
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "Stats":
        return cls(
            total_vulnerabilities=data.get("total_vulnerabilities", 0),
            new_this_week=data.get("new_this_week", 0),
            authors=data.get("authors", 0),
            raw=data,
        )


@dataclass
class Vuln:
    vulner_id: str | None
    cve_id: str | None
    max_score: float | None
    max_severity: str | None
    created: str | None
    updated: str | None
    has_fix: bool
    has_exploits: bool
    vendors: list = field(default_factory=list)
    products: list = field(default_factory=list)
    researchers: list = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Vuln":
        return cls(
            vulner_id=data.get("vulner_id"),
            cve_id=data.get("cve_id"),
            max_score=data.get("max_score"),
            max_severity=data.get("max_severity"),
            created=data.get("created"),
            updated=data.get("updated"),
            has_fix=bool(data.get("has_fix")),
            has_exploits=bool(data.get("has_exploits")),
            vendors=data.get("vendors") or [],
            products=data.get("products") or [],
            researchers=data.get("researchers") or [],
            raw=data,
        )


@dataclass
class VulnList:
    count: int
    rows: list[Vuln]
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "VulnList":
        return cls(
            count=data.get("count", 0),
            rows=[Vuln.from_dict(r) for r in data.get("rows", [])],
            raw=data,
        )


@dataclass
class Reference:
    ref_url: str | None
    domain: str | None
    source: str | None
    stars: int | None
    forks: int | None
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "Reference":
        return cls(
            ref_url=data.get("ref_url"),
            domain=data.get("domain"),
            source=data.get("source"),
            stars=data.get("stars"),
            forks=data.get("forks"),
            raw=data,
        )


@dataclass
class VulnDetail:
    vuln: Vuln
    cwe_ids: list
    impacts: list
    cvss: dict
    references: list[Reference]
    related_news: list
    duplicates: list
    researchers: list
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "VulnDetail":
        return cls(
            vuln=Vuln.from_dict(data),
            cwe_ids=data.get("cwe_ids") or [],
            impacts=data.get("impacts") or [],
            cvss=data.get("cvss") or {},
            references=[Reference.from_dict(r) for r in data.get("references", [])],
            related_news=data.get("related_news") or [],
            duplicates=data.get("duplicates") or [],
            researchers=data.get("researchers") or [],
            raw=data,
        )


@dataclass
class TrendVuln:
    vulner_id: str | None
    cve_id: str | None
    score: float | None
    severity: str | None
    created: str | None
    updated: str | None
    has_fix: bool
    has_exploits: bool
    vendors: list
    products: list
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "TrendVuln":
        return cls(
            vulner_id=data.get("vulner_id"),
            cve_id=data.get("cve_id"),
            score=data.get("score"),
            severity=data.get("severity"),
            created=data.get("created"),
            updated=data.get("updated"),
            has_fix=bool(data.get("has_fix")),
            has_exploits=bool(data.get("has_exploits")),
            vendors=data.get("vendors") or [],
            products=data.get("products") or [],
            raw=data,
        )


@dataclass
class Trend:
    lvl: int | None
    posts_count: int
    vuln: TrendVuln
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "Trend":
        return cls(
            lvl=data.get("lvl"),
            posts_count=data.get("posts_count", 0),
            vuln=TrendVuln.from_dict(data.get("vulnerability") or {}),
            raw=data,
        )


@dataclass
class TrendList:
    count: int
    rows: list[Trend]
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "TrendList":
        return cls(
            count=data.get("count", 0),
            rows=[Trend.from_dict(r) for r in data.get("rows", [])],
            raw=data,
        )


@dataclass
class NewsItem:
    title: str | None
    summary: str | None
    slug: str | None
    category: str | None
    published: str | None
    cve_ids: list
    vendors: list
    products: list
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "NewsItem":
        return cls(
            title=data.get("title"),
            summary=data.get("summary"),
            slug=data.get("slug"),
            category=data.get("category"),
            published=data.get("published"),
            cve_ids=data.get("cve_ids") or [],
            vendors=data.get("vendors") or [],
            products=data.get("products") or [],
            raw=data,
        )


@dataclass
class NewsList:
    count: int
    rows: list[NewsItem]
    raw: dict

    @classmethod
    def from_dict(cls, data: dict) -> "NewsList":
        return cls(
            count=data.get("count", 0),
            rows=[NewsItem.from_dict(r) for r in data.get("rows", [])],
            raw=data,
        )
