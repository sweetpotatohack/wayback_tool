"""Shared finding deduplication for exports and API."""

from __future__ import annotations

import re

from app.models import Finding
from app.services.classifier import SEVERITY_RANK, canonical_url, classify_url, is_marketing_path


def _phone_digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")[:20]


def _email_value(item: Finding) -> str:
    raw = (item.masked_secret or item.title or "").strip().lower()
    if raw.startswith("email:"):
        raw = raw[6:].strip()
    return raw


def finding_dedupe_key(item: Finding) -> tuple:
    """Stable dedupe key — contacts and entropy by value, URLs by canonical path."""
    pattern = item.pattern or ""
    if pattern == "osint-phone":
        return ("osint-phone", _phone_digits(item.masked_secret or item.title))
    if pattern in {"osint-email", "osint-email-scope"}:
        return (pattern, _email_value(item))
    if pattern == "js-entropy":
        return ("js-entropy", (item.masked_secret or "")[:200])
    if item.category == "content-secret" and pattern in {
        "passwd-assign",
        "apikey-assign",
        "env-assign",
        "php-pass",
        "php-define",
    }:
        return (pattern, (item.masked_secret or "")[:200])
    if item.category == "exposed-mail" or item.pattern.startswith("mail-"):
        return ("exposed-mail", item.pattern, (item.title or item.evidence or "")[:160])
    if item.category == "auth-panel" or item.pattern.startswith("auth-"):
        return ("auth-panel", item.pattern, canonical_url(item.original_url))
    if item.pattern in {"robots", "sitemap"}:
        host = canonical_url(item.original_url).split("/")[0]
        return (item.pattern, host, item.pattern)
    return (canonical_url(item.original_url), pattern, item.source)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    best: dict[tuple, Finding] = {}
    for item in findings:
        if item.source == "path" and (
            is_marketing_path(item.original_url) or classify_url(item.original_url) is None
        ):
            if item.pattern in {"config-path", "kw-path", "kw-file", "named-config", "auth-file"}:
                continue
        key = finding_dedupe_key(item)
        prev = best.get(key)
        if not prev or SEVERITY_RANK.get(item.severity, 0) > SEVERITY_RANK.get(prev.severity, 0):
            best[key] = item
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(best.values(), key=lambda f: (order.get(f.severity, 9), f.original_url))
