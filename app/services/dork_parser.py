from __future__ import annotations

import re
from dataclasses import dataclass

from app import DATA_DIR
from app.services.dorks import DorkDef

GOOGLE_DORKS_FILE = DATA_DIR / "google_dorks.txt"

SKIP_MARKERS = (
    "googlebot",
    "johnny.ihackstuff.com",
    "sourceforge.net",
    "php.net",
    "microsoft.com",
    "w3.org",
)

HIGH_HINTS = (
    "password",
    "passwd",
    "credential",
    "secret",
    "api key",
    "apikey",
    "private key",
    ".env",
    "wp-config",
    "db_password",
    "mysql dump",
    "sql dump",
    "backup",
    "phpinfo",
    "htpasswd",
    ".git",
    "id_rsa",
    "aws",
    "service.pwd",
)

MEDIUM_HINTS = (
    "admin",
    "login",
    "config",
    "dump",
    "error",
    "debug",
    "phpmyadmin",
    "adminer",
    "install",
    "setup",
    "robots.txt",
    "crossdomain",
)


def _slug(text: str, n: int = 48) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:n] or "dork"


def _category(line: str) -> str:
    lower = line.lower()
    if any(x in lower for x in ("password", "passwd", "credential", "secret", "htpasswd", "api key", "private key")):
        return "secrets"
    if any(x in lower for x in ("backup", "dump", "sql", ".bak", "archive")):
        return "backup"
    if any(x in lower for x in ("config", "settings", "env", "ini", "yaml", "yml", "properties")):
        return "config"
    if any(x in lower for x in ("admin", "login", "panel", "administrator")):
        return "panels"
    if any(x in lower for x in ("phpinfo", "error", "debug", "server-status", "index of")):
        return "disclosure"
    if any(x in lower for x in (".git", "svn", "vcs")):
        return "vcs"
    if any(x in lower for x in ("api", "swagger", "graphql", "actuator")):
        return "api"
    return "misc"


def _severity(line: str, category: str) -> str:
    lower = line.lower()
    if category == "secrets" or any(x in lower for x in HIGH_HINTS[:12]):
        return "critical" if any(x in lower for x in ("password", "credential", "secret", ".env", "htpasswd", "id_rsa", "aws")) else "high"
    if category in {"backup", "config", "disclosure", "vcs"}:
        return "high"
    if category in {"panels", "api"}:
        return "medium"
    return "low"


def google_dork_to_cdx_filter(line: str) -> str | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    lower = raw.lower()
    if any(marker in lower for marker in SKIP_MARKERS):
        return None
    if lower.startswith("-site:") and "inurl:" not in lower and "filetype:" not in lower and "ext:" not in lower:
        return None

    tokens: list[str] = []

    for match in re.finditer(r"(?:filetype|ext):([a-z0-9._-]{1,12})", raw, re.I):
        ext = match.group(1).lstrip(".")
        if ext.isalnum() or ext in {"php", "phtml", "inc", "cfg", "conf"}:
            tokens.append(rf"\.{re.escape(ext)}(\?|$)")

    for match in re.finditer(r'''inurl:(?:"([^"]+)"|(\S+))''', raw, re.I):
        token = (match.group(1) or match.group(2) or "").strip()
        token = token.strip("*?")
        if len(token) >= 2 and token.lower() not in {"www", "http", "https"}:
            tokens.append(re.escape(token))

    if raw.startswith(("?", "/", "_")) and " " not in raw[:80]:
        tokens.append(re.escape(raw.split()[0][:60]))

    for match in re.finditer(r'"([^"]{3,80})"', raw):
        quote = match.group(1)
        if "/" in quote or ".php" in quote.lower() or "password" in quote.lower() or "index of" in quote.lower():
            chunk = quote.replace("Index of /", "").strip("/ ")
            if chunk:
                tokens.append(re.escape(chunk[:50]))

    if not tokens:
        if ".php" in lower or ".asp" in lower or ".jsp" in lower:
            path = raw.split()[0][:60]
            tokens.append(re.escape(path))

    if not tokens:
        return None

    joined = "|".join(tokens[:5])
    return f"original:(?i).*(?:{joined})"


def parse_google_dork_line(line: str, idx: int) -> DorkDef | None:
    raw = line.strip()
    if not raw:
        return None
    cdx = google_dork_to_cdx_filter(raw)
    if not cdx:
        return None
    title = raw if len(raw) <= 120 else raw[:117] + "..."
    category = _category(raw)
    severity = _severity(raw, category)
    return DorkDef(
        id=f"g{idx}",
        title=title,
        category=category,
        severity=severity,
        cdx_filter=cdx,
    )


def load_google_dorks(limit: int | None = None) -> tuple[list[DorkDef], dict[str, int]]:
    path = GOOGLE_DORKS_FILE
    if not path.exists():
        return [], {"total_lines": 0, "parsed": 0}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    total = len(lines)
    seen_filters: set[str] = set()
    out: list[DorkDef] = []
    for idx, line in enumerate(lines, start=1):
        item = parse_google_dork_line(line, idx)
        if not item or item.cdx_filter in seen_filters:
            continue
        seen_filters.add(item.cdx_filter)
        out.append(item)
        if limit and len(out) >= limit:
            break
    stats = {"total_lines": total, "parsed": len(seen_filters) if not limit else len(out)}
    return out, stats


def merged_dork_library(max_google: int = 400) -> tuple[tuple[DorkDef, ...], dict[str, int | str]]:
    from app.services.dorks import BUILTIN_DORK_LIBRARY

    _all, stats = load_google_dorks()
    google, _ = load_google_dorks(limit=max_google * 3)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    google.sort(key=lambda d: (rank.get(d.severity, 9), d.category, d.id))
    google = google[:max_google]

    seen: set[str] = set()
    merged: list[DorkDef] = []
    for item in (*BUILTIN_DORK_LIBRARY, *google):
        key = item.cdx_filter or item.path or item.id
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)

    stats["merged_total"] = len(merged)
    stats["builtin"] = len(BUILTIN_DORK_LIBRARY)
    stats["google_used"] = len(google)
    stats["google_in_scan"] = min(220, len([d for d in merged if d.cdx_filter]))
    stats["source_file"] = str(GOOGLE_DORKS_FILE)
    return tuple(merged), stats
