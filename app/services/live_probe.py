from __future__ import annotations

import asyncio
import hashlib
import re
from collections import Counter
from urllib.parse import urljoin, urlparse

import httpx

from app.services.live_content import bodies_match, host_key
from app.services.pentest_intel import AUTH_PROBE_PATHS, classify_auth_url, detect_login_form_html
from app.services.secrets import scan_text
from app.services.wayback import LEAK_PATHS, normalize_target

_SOFT404 = re.compile(
    r"(?i)(404|not\s+found|page not found|страниц[аы].*не найден|ошибка\s*404|error\s*404|file not found)"
)
_ENV_LINE = re.compile(r"(?m)^[A-Z_][A-Z0-9_]*\s*=")


def _body_hash(text: str) -> str:
    return hashlib.sha256(text[:12000].encode("utf-8", errors="ignore")).hexdigest()[:16]


def _looks_like_html(text: str) -> bool:
    head = text[:600].lstrip().lower()
    return head.startswith("<!doctype") or head.startswith("<html") or "<body" in head[:800].lower()


def _validate_path(path: str, text: str, *, secret_hits: list) -> tuple[bool, str]:
    if secret_hits:
        return True, secret_hits[0].evidence
    path_low = path.lower()
    stripped = text.strip()
    if not stripped:
        return False, "пустой ответ"
    if _looks_like_html(text):
        if _SOFT404.search(text[:12000]):
            return False, "HTML 404"
        if path_low.startswith("/.") or path_low.endswith((".sql", ".env", ".bak", ".properties", ".json")):
            return False, "HTML вместо файла"
    if path_low.endswith("/.git/head"):
        return stripped.startswith("ref:"), "ref: в .git/HEAD"
    if path_low.endswith("/.git/config"):
        return "[core]" in text or "[remote" in text, "секция git config"
    if ".env" in path_low:
        return bool(_ENV_LINE.search(text)), "KEY=value в .env"
    if path_low.endswith("/.htpasswd"):
        return (":" in stripped and not _looks_like_html(text)), "htpasswd формат"
    if path_low.endswith("wp-config.php"):
        return ("DB_" in text or "define(" in text) and not _looks_like_html(text), "PHP define/DB_"
    if path_low.endswith((".sql",)):
        low = text[:4000].lower()
        return (
            not _looks_like_html(text)
            and any(tok in low for tok in ("insert into", "create table", "mysqldump", "-- dump"))
        ), "SQL dump"
    if path_low.endswith((".json",)):
        return text.lstrip().startswith("{") and not _looks_like_html(text), "JSON объект"
    if path_low.endswith((".properties",)):
        return bool(re.search(r"(?m)^[a-z0-9_.-]+\s*=", text, re.I)) and not _looks_like_html(text), "properties"
    if path_low.endswith("web.config"):
        return "<configuration" in text.lower(), "web.config XML"
    if path_low.endswith("appsettings.json"):
        return text.lstrip().startswith("{") and "ConnectionStrings" in text, "appsettings"
    if path_low.endswith("phpinfo.php") or "phpinfo" in path_low:
        return "phpinfo()" in text.lower() or "PHP Version" in text, "phpinfo banner"
    return False, "нет сигнатуры содержимого"


async def probe_live_hosts(
    client: httpx.AsyncClient,
    hosts: list[str],
    *,
    include_subdomains: bool = False,
    max_paths: int = 24,
    concurrency: int = 6,
) -> list[dict]:
    """Check live site for known leak paths. Reports only verified bodies, not bare HTTP 200."""
    paths = list(LEAK_PATHS)[:max_paths]
    bases: list[str] = []
    for host in hosts:
        base = normalize_target(host)
        if not base:
            continue
        bases.append(f"https://{base}")
        if include_subdomains:
            bases.append(f"https://www.{base}")

    sem = asyncio.Semaphore(concurrency)
    raw: list[dict] = []
    home_bodies: dict[str, str] = {}

    async def _fetch_home(base: str) -> None:
        host = host_key(base)
        if host in home_bodies:
            return
        try:
            response = await client.get(f"{base.rstrip('/')}/", timeout=12.0, follow_redirects=True)
            if response.status_code == 200:
                text = response.text[:120000]
                if text.strip():
                    home_bodies[host] = text
        except httpx.HTTPError:
            return

    await asyncio.gather(*[_fetch_home(base) for base in bases], return_exceptions=True)

    async def _fetch(base: str, path: str) -> None:
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        async with sem:
            try:
                response = await client.get(url, timeout=12.0, follow_redirects=True)
            except httpx.HTTPError:
                return
            if response.status_code != 200:
                return
            ctype = (response.headers.get("content-type") or "").lower()
            text = response.text[:500000] if ctype.startswith("text") or "json" in ctype or "xml" in ctype else ""
            if not text and len(response.content) < 500000:
                try:
                    text = response.content[:500000].decode("utf-8", errors="replace")
                except Exception:
                    text = ""
            secret_hits = scan_text(text) if text else []
            home = home_bodies.get(host_key(url), "")
            if home and bodies_match(text, home):
                return
            ok, reason = _validate_path(path, text, secret_hits=secret_hits)
            if not ok:
                return
            raw.append(
                {
                    "url": url,
                    "path": path,
                    "status": str(response.status_code),
                    "severity": secret_hits[0].severity if secret_hits else "high",
                    "title": secret_hits[0].name if secret_hits else f"Live: {path}",
                    "evidence": secret_hits[0].evidence if secret_hits else f"HTTP 200 · {reason}",
                    "masked": secret_hits[0].masked if secret_hits else "",
                    "pattern": secret_hits[0].pattern if secret_hits else "live-verified",
                    "body_hash": _body_hash(text) if text else "",
                }
            )

    await asyncio.gather(*[_fetch(base, path) for base in bases for path in paths], return_exceptions=True)

    if not raw:
        return []

    hash_counts = Counter(row["body_hash"] for row in raw if row.get("body_hash"))
    if hash_counts:
        common_hash, common_n = hash_counts.most_common(1)[0]
        if common_n >= 3:
            raw = [row for row in raw if row.get("body_hash") != common_hash]

    out: list[dict] = []
    seen: set[str] = set()
    for row in raw:
        key = row["url"]
        if key in seen:
            continue
        seen.add(key)
        out.append({k: v for k, v in row.items() if k != "body_hash"})
    return out


async def probe_auth_pages(
    client: httpx.AsyncClient,
    hosts: list[str],
    *,
    include_subdomains: bool = False,
    concurrency: int = 8,
) -> list[dict]:
    """Probe common login/auth paths on live hosts."""
    paths = list(AUTH_PROBE_PATHS)
    bases: list[str] = []
    for host in hosts:
        base = normalize_target(host)
        if not base:
            continue
        bases.append(f"https://{base}")

    sem = asyncio.Semaphore(concurrency)
    out: list[dict] = []
    seen: set[str] = set()

    async def _fetch(base: str, path: str) -> None:
        url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
        async with sem:
            try:
                response = await client.get(url, timeout=12.0, follow_redirects=True)
            except httpx.HTTPError:
                return
            if response.status_code not in {200, 401, 403}:
                return
            ctype = (response.headers.get("content-type") or "").lower()
            text = response.text[:120000] if ctype.startswith("text") or "html" in ctype else ""
            if not text:
                return
            final = str(response.url)
            auth = classify_auth_url(final) or classify_auth_url(path)
            has_form = detect_login_form_html(text)
            if not auth and not has_form:
                return
            key = canonical_auth_key(final)
            if key in seen:
                return
            seen.add(key)
            title = auth.title if auth else f"Страница авторизации: {urlparse(final).path[:60]}"
            out.append(
                {
                    "url": final,
                    "path": path,
                    "status": str(response.status_code),
                    "severity": "medium",
                    "title": title,
                    "evidence": f"HTTP {response.status_code} · форма={'да' if has_form else 'URL'} · {path}",
                    "masked": "",
                    "pattern": "auth-login-live" if has_form else (auth.pattern if auth else "auth-login"),
                }
            )

    await asyncio.gather(*[_fetch(base, path) for base in bases for path in paths], return_exceptions=True)
    return out


def canonical_auth_key(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower().split("@")[-1]
    if host.startswith("www."):
        host = host[4:]
    path = (parsed.path or "/").rstrip("/").lower() or "/"
    return f"{host}{path}"
