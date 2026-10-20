"""Validated Markdown help content packaged with the server."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

import yaml
from markdown_it import MarkdownIt

from .models import UserRole


_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*$")
_LINK = re.compile(r"\[[^]]+\]\(([^)]+)\)")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}$")
_PUBLIC_FORBIDDEN = re.compile(
    r"(?:[A-Z]:\\|(?:\d{1,3}\.){3}\d{1,3}|BEGIN [A-Z ]*PRIVATE KEY|Bearer\s+[A-Za-z0-9._-]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class HelpArticle:
    slug: str
    title: str
    summary: str
    audience: str
    roles: frozenset[UserRole]
    order: int
    markdown: str
    category: str = "general"
    section: str = ""
    keywords: tuple[str, ...] = ()
    related_slugs: tuple[str, ...] = ()
    process_steps: tuple[dict, ...] = ()
    source_refs: tuple[dict, ...] = ()
    last_reviewed: str = ""
    visibility: str = "public"
    source_file: str = ""

    def metadata(self) -> dict:
        return {
            "slug": self.slug,
            "title": self.title,
            "summary": self.summary,
            "audience": self.audience,
            "roles": sorted(role.value for role in self.roles),
            "order": self.order,
            "category": self.category,
            "section": self.section,
            "keywords": list(self.keywords),
            "related_slugs": list(self.related_slugs),
            "process_steps": list(self.process_steps),
            "source_refs": list(self.source_refs),
            "last_reviewed": self.last_reviewed or None,
            "visibility": self.visibility,
            "access": "allowed",
        }

    def payload(self) -> dict:
        renderer = MarkdownIt("commonmark", {"html": False, "linkify": True})
        return {**self.metadata(), "html": renderer.render(self.markdown)}


class HelpCatalog:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path(str(files("research_compute_network").joinpath("help_content")))
        self._articles = self._load()

    def list_public(self) -> list[dict]:
        return [article.metadata() for article in self._ordered() if article.audience == "public"]

    def list_for_roles(self, roles: frozenset[UserRole]) -> list[dict]:
        return [
            article.metadata()
            for article in self._ordered()
            if article.audience == "protected" and self._can_read(article, roles)
        ]

    def list_role_catalog(self, roles: frozenset[UserRole]) -> list[dict]:
        """Return safe role entries, including locked titles but never content."""
        entries = []
        for article in self._ordered():
            if article.audience != "protected":
                continue
            allowed = self._can_read(article, roles)
            item = article.metadata() if allowed else {
                "slug": article.slug,
                "title": article.title,
                "summary": article.summary,
                "audience": article.audience,
                "category": article.category,
                "section": article.section,
                "order": article.order,
            }
            item["access"] = "allowed" if allowed else "locked"
            item["required_roles"] = sorted(role.value for role in article.roles)
            entries.append(item)
        return entries

    def public(self, slug: str) -> dict | None:
        article = self._articles.get(slug)
        return article.payload() if article and article.audience == "public" else None

    def protected(self, slug: str, roles: frozenset[UserRole]) -> dict | None:
        article = self._articles.get(slug)
        if not article or article.audience != "protected" or not self._can_read(article, roles):
            return None
        return article.payload()

    def _ordered(self) -> list[HelpArticle]:
        return sorted(self._articles.values(), key=lambda article: (article.order, article.title))

    @staticmethod
    def _can_read(article: HelpArticle, roles: frozenset[UserRole]) -> bool:
        return UserRole.ADMIN in roles or bool(article.roles & roles)

    def _load(self) -> dict[str, HelpArticle]:
        articles: dict[str, HelpArticle] = {}
        for path in sorted(self.root.rglob("*.md")):
            article = self._parse(path)
            if article.slug in articles:
                raise ValueError(f"duplicate help slug: {article.slug}")
            articles[article.slug] = article
        self._validate_links(articles)
        self._validate_related(articles)
        return articles

    @staticmethod
    def _parse(path: Path) -> HelpArticle:
        text = path.read_text(encoding="utf-8")
        parts = text.split("---", 2)
        if len(parts) != 3 or parts[0].strip():
            raise ValueError(f"help article requires YAML frontmatter: {path}")
        metadata = yaml.safe_load(parts[1])
        if not isinstance(metadata, dict):
            raise ValueError(f"help frontmatter must be a mapping: {path}")
        slug = str(metadata.get("slug", ""))
        audience = str(metadata.get("audience", ""))
        if not _SLUG.fullmatch(slug) or audience not in {"public", "protected"}:
            raise ValueError(f"invalid help metadata: {path}")
        roles = frozenset(UserRole(value) for value in metadata.get("roles", []))
        if audience == "public" and roles:
            raise ValueError(f"public help cannot declare roles: {path}")
        markdown = parts[2].strip() + "\n"
        if audience == "public" and _PUBLIC_FORBIDDEN.search(markdown):
            raise ValueError(f"public help contains sensitive-looking content: {path}")
        visibility = str(metadata.get("visibility", audience))
        if visibility not in {"public", "protected", "internal", "historical"}:
            raise ValueError(f"invalid help visibility: {path}")
        last_reviewed = str(metadata.get("last_reviewed", ""))
        if last_reviewed and not _DATE.fullmatch(last_reviewed):
            raise ValueError(f"invalid help review date: {path}")
        process_steps = tuple(
            item if isinstance(item, dict) else {"label": str(item)}
            for item in metadata.get("process_steps", [])
        )
        for step in process_steps:
            if not str(step.get("label", "")).strip() or not str(step.get("detail", "")).strip():
                raise ValueError(f"help process step requires label and detail: {path}")
        source_refs = tuple(
            item if isinstance(item, dict) else {"document": str(item)}
            for item in metadata.get("source_refs", [])
        ) or ({"document": path.name, "section": str(metadata["title"]), "kind": "help"},)
        for reference in source_refs:
            document = str(reference.get("document", ""))
            if not document or Path(document).is_absolute() or ".." in Path(document).parts:
                raise ValueError(f"invalid help source reference: {path}")
            if not str(reference.get("section", "")).strip():
                raise ValueError(f"help source reference requires a section: {path}")
        return HelpArticle(
            slug=slug,
            title=str(metadata["title"]),
            summary=str(metadata["summary"]),
            audience=audience,
            roles=roles,
            order=int(metadata.get("order", 100)),
            markdown=markdown,
            category=str(metadata.get("category", "general")),
            section=str(metadata.get("section", "")),
            keywords=tuple(str(item) for item in metadata.get("keywords", [])),
            related_slugs=tuple(str(item) for item in metadata.get("related_slugs", [])),
            process_steps=process_steps,
            source_refs=source_refs,
            last_reviewed=last_reviewed,
            visibility=visibility,
            source_file=path.name,
        )

    @staticmethod
    def _validate_links(articles: dict[str, HelpArticle]) -> None:
        for article in articles.values():
            for target in _LINK.findall(article.markdown):
                if target.startswith("/help/") and target.removeprefix("/help/") not in articles:
                    raise ValueError(f"broken help link in {article.slug}: {target}")

    @staticmethod
    def _validate_related(articles: dict[str, HelpArticle]) -> None:
        for article in articles.values():
            for slug in article.related_slugs:
                if slug not in articles:
                    raise ValueError(f"unknown related help slug in {article.slug}: {slug}")
