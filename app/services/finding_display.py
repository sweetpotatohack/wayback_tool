"""User-facing labels for findings — hide internal BBOT/scanner plumbing."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.models import Finding

_BBOT_URL = re.compile(r"^bbot://", re.I)
_EMAIL_TITLE = re.compile(r"(?i)^email:\s*(.+)$")
_PORT_TITLE = re.compile(r"(?i)^port:\s*(.+)$")
_SUBDOMAIN_TITLE = re.compile(r"(?i)^subdomain:\s*(.+)$")
_SKIP_FINDING_CATS = frozenset({"bbot-screenshot"})
_SKIP_FINDING_PATTERNS = frozenset({"bbot-webscreenshot"})

_SOURCE_LABELS = {
    "bbot": "скан",
    "path": "архив",
    "dork": "dork",
    "live": "live",
    "live-crawl": "live",
    "robots": "robots",
    "archive": "архив",
    "recon": "recon",
}

_CATEGORY_LABELS = {
    "bbot-dns": "поддомен",
    "bbot-email": "email",
    "bbot-port": "порт",
    "bbot-shodan": "shodan",
    "bbot-finding": "находка",
    "bbot-vuln": "уязвимость",
    "bbot-bucket": "bucket",
    "bbot-code": "git",
    "bbot-tech": "технология",
    "exposed-mail": "почта",
    "exposed-service": "сервис",
    "exposed-db": "БД",
    "auth-panel": "авторизация",
    "backup": "бэкап",
    "keyword": "ключевое слово",
    "osint-email": "email",
    "osint-phone": "телефон",
}


def is_hidden_finding(f: Finding) -> bool:
    cat = (f.category or "").lower()
    pat = (f.pattern or "").lower()
    if cat in _SKIP_FINDING_CATS:
        return True
    if pat in _SKIP_FINDING_PATTERNS:
        return True
    if "webscreenshot" in (f.title or "").lower():
        return True
    return False


def _real_host(url: str) -> str:
    if not url or _BBOT_URL.match(url):
        return ""
    raw = url.strip()
    if " → " in raw:
        raw = raw.split(" → ", 1)[0]
    if not raw.startswith(("http://", "https://", "mailto:")):
        if "@" in raw and "." in raw.split("@", 1)[-1]:
            return raw
        if re.match(r"^[a-z0-9._-]+:\d{1,5}$", raw, re.I):
            return raw
        return ""
    if raw.startswith("mailto:"):
        return raw[7:].split("?")[0]
    try:
        host = urlparse(raw).netloc.lower().split("@")[-1].split(":")[0]
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    if host in {"bbot", "localhost"}:
        return ""
    return host


def display_source(source: str) -> str:
    return _SOURCE_LABELS.get((source or "").lower(), source or "")


def display_category(category: str) -> str:
    return _CATEGORY_LABELS.get((category or "").lower(), (category or "").replace("bbot-", ""))


def display_pattern(pattern: str) -> str:
    p = (pattern or "").strip()
    if not p:
        return ""
    if p.startswith("bbot-"):
        p = p[5:]
    return p.replace("_", "-")


def display_title(title: str) -> str:
    t = (title or "").strip()
    if t.upper().startswith("BBOT "):
        t = t[5:].strip()
    if ":" in t:
        head, rest = t.split(":", 1)
        if head.strip().upper() in {
            "WEBSCREENSHOT",
            "DNS_NAME",
            "EMAIL_ADDRESS",
            "OPEN_TCP_PORT",
            "URL",
            "FINDING",
            "VULNERABILITY",
            "TECHNOLOGY",
            "STORAGE_BUCKET",
            "CODE_REPOSITORY",
            "IP_ADDRESS",
        }:
            t = rest.strip()
    return t


def display_resource_url(f: Finding) -> tuple[str, str, str]:
    """Return (href, label, kind) where kind is http|mailto|text|empty."""
    title = display_title(f.title or "")
    raw = (f.original_url or "").strip()
    cat = (f.category or "").lower()

    if cat == "bbot-email" or title.lower().startswith("email:"):
        m = _EMAIL_TITLE.match(title)
        email = (m.group(1) if m else title.replace("Email:", "")).strip().lower()
        if "@" in email:
            return f"mailto:{email}", email, "mailto"

    if cat in {"bbot-port", "exposed-service", "exposed-mail", "exposed-db"} or title.lower().startswith("port:"):
        m = _PORT_TITLE.match(title)
        port_ref = (m.group(1) if m else title.replace("Port:", "")).strip()
        if not port_ref and raw and not _BBOT_URL.match(raw):
            port_ref = raw
        if re.match(r"^[a-z0-9._-]+:\d{1,5}$", port_ref, re.I):
            return "", port_ref, "text"

    if cat == "bbot-dns" or title.lower().startswith("subdomain:"):
        m = _SUBDOMAIN_TITLE.match(title)
        host = (m.group(1) if m else _real_host(raw)).strip().lower()
        if host and "." in host:
            href = f"https://{host}/"
            return href, href, "http"

    if raw.startswith(("http://", "https://")):
        return raw.split(" → ")[0], raw.split(" → ")[0], "http"

    if _BBOT_URL.match(raw):
        return "", title or "—", "text"

    if raw:
        return raw, raw, "http"
    return "", title or "—", "text"


def display_evidence(evidence: str, *, category: str = "") -> str:
    text = (evidence or "").strip()
    if not text:
        return ""
    if category == "bbot-email" and "@" in text and len(text) < 120:
        return text
    if "discovery_path" in text.lower() or "seeded with" in text.lower():
        return ""
    if "/media/bbot/" in text and "gowitness" in text:
        return ""
    return text[:500]


def display_meta_tags(f: Finding) -> str:
    parts: list[str] = []
    cat = display_category(f.category or "")
    if cat and not cat.startswith("bbot"):
        parts.append(cat)
    src = display_source(f.source or "")
    if src:
        parts.append(src)
    return " · ".join(parts)


def finding_preset_match(f: Finding, preset: str) -> bool:
    cat = (f.category or "").lower()
    title = (f.title or "").lower()
    pat = (f.pattern or "").lower()
    if preset == "ports":
        return (
            cat in {"bbot-port", "exposed-service", "exposed-mail", "exposed-db", "bbot-shodan"}
            or title.startswith("port:")
            or "open_tcp_port" in pat
            or pat.startswith("mail-")
            or "shodan" in cat
        )
    if preset == "subdomains":
        return cat == "bbot-dns" or title.startswith("subdomain:") or pat.endswith("dns_name")
    if preset == "emails":
        return cat in {"bbot-email", "osint-email"} or title.startswith("email:")
    return True
