from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from app.services.classifier import classify_url, is_script_or_data, worth_llm_extract
from app.services.js_intel import extract_js_endpoints, scan_js_secrets
from app.services.live_auth import LiveAuth
from app.services.osint import scan_osint
from app.services.secrets import scan_text
from app.services.wayback import LEAK_PATHS, extract_html_links, normalize_target

SKIP_EXT = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".bmp",
    ".mp4",
    ".webm",
    ".mp3",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".gz",
    ".7z",
    ".rar",
}

FETCH_EXT = {
    ".js",
    ".mjs",
    ".json",
    ".xml",
    ".txt",
    ".env",
    ".php",
    ".yml",
    ".yaml",
    ".conf",
    ".cfg",
    ".ini",
    ".sql",
    ".bak",
    ".html",
    ".htm",
    "",
}

TEXT_CT = ("text/", "application/json", "application/xml", "application/javascript", "application/x-javascript")

_SCRIPT_SRC = re.compile(r"""(?i)<script[^>]+src=["']([^"'#][^"']+)["']""")
_LINK_ASSET = re.compile(
    r"""(?i)<link[^>]+(?:href=["']([^"']+)["'][^>]+rel=["'](?:modulepreload|preload|stylesheet)["']|rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+)["'])"""
)
_WEBPACK_MAP = re.compile(r'(\d+):"([a-f0-9]{8,})"')
_CHUNK_FILE = re.compile(r"""["']?(?:/?static/)?(?:js/)?(\d+)\.([a-f0-9]{8,})\.chunk\.(?:js|css)["']?""")


class AsyncRateLimiter:
    def __init__(self, rps: float | None) -> None:
        self._min_interval = 1.0 / rps if rps and rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def acquire(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._next = max(time.monotonic(), now) + self._min_interval


@dataclass
class CrawledPage:
    url: str
    text: str
    content_type: str
    status: int
    depth: int
    requested_url: str = ""
    secret_hits: list = field(default_factory=list)
    osint_hits: list = field(default_factory=list)


@dataclass
class LiveCrawlResult:
    pages: list[CrawledPage]
    urls_seen: list[str]
    errors: list[str]
    auth_ok: bool
    home_bodies: dict[str, str] = field(default_factory=dict)
    js_fetched: int = 0
    api_probed: int = 0


def _scope_apexes(hosts: list[str]) -> set[str]:
    from app.services.wayback import apex_domain

    return {apex_domain(h) for h in hosts}


def _host_in_scope(url: str, hosts: list[str], *, include_subdomains: bool = True) -> bool:
    loc_host = urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
    if loc_host.startswith("www."):
        loc_host = loc_host[4:]
    if any(loc_host == h or loc_host.endswith("." + h) for h in hosts):
        return True
    if include_subdomains:
        for apex in _scope_apexes(hosts):
            if loc_host == apex or loc_host.endswith("." + apex):
                return True
    return False


def select_crawl_hosts(
    hosts: list[str],
    auth: LiveAuth,
    *,
    max_without_auth: int | None = None,
    max_with_auth: int | None = None,
) -> list[str]:
    """Return all unique targets — full live-crawl per host."""
    cleaned: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        base = normalize_target(host)
        if not base or base in seen:
            continue
        seen.add(base)
        cleaned.append(base)
    return cleaned


def _path_ext(url: str) -> str:
    path = urlparse(url).path.lower()
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return "." + path.rsplit(".", 1)[-1]


def _should_fetch(url: str) -> bool:
    ext = _path_ext(url)
    if ext in SKIP_EXT:
        return False
    if ext == ".css":
        return False
    if ext in FETCH_EXT or "/api/" in urlparse(url).path.lower():
        return True
    path = urlparse(url).path.lower()
    if any(tok in path for tok in ("/static/", "/assets/", "/js/", "/dist/", "/build/")):
        return ext in {".js", ".mjs", ".json", ".map", ""} or "chunk" in path
    return True


def _decode_body(response: httpx.Response, limit: int = 800_000) -> tuple[str, str]:
    ctype = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
    raw = response.content[:limit]
    if not raw:
        return "", ctype
    path = urlparse(str(response.url)).path.lower()
    is_js = path.endswith((".js", ".mjs")) or "javascript" in ctype
    is_json = path.endswith(".json") or "json" in ctype
    if not any(ctype.startswith(p) for p in TEXT_CT) and ctype not in {"", "application/octet-stream"}:
        if not is_js and not is_json:
            return "", ctype
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            return raw.decode(enc), ctype
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), ctype


def extract_spa_assets(html: str, js_blobs: list[str], base_url: str) -> list[str]:
    found: set[str] = set()
    blob = html or ""
    for match in _SCRIPT_SRC.finditer(blob[:800000]):
        found.add(urljoin(base_url, match.group(1).strip()))
    for match in _LINK_ASSET.finditer(blob[:800000]):
        href = match.group(1) or match.group(2) or ""
        if href:
            found.add(urljoin(base_url, href.strip()))
    for link in extract_html_links(blob, base_url, limit=200):
        ext = _path_ext(link)
        if ext in {".js", ".mjs", ".json", ".map"} or "/static/" in link:
            found.add(link)

    parsed = urlparse(base_url)
    static_js = f"{parsed.scheme}://{parsed.netloc}/static/js/"
    combined = blob + "\n".join(js_blobs)
    for match in _WEBPACK_MAP.finditer(combined[:600000]):
        found.add(f"{static_js}{match.group(1)}.{match.group(2)}.chunk.js")
    for match in _CHUNK_FILE.finditer(combined[:600000]):
        found.add(urljoin(base_url, f"/static/js/{match.group(1)}.{match.group(2)}.chunk.js"))
    return sorted(found)


def _scan_page_text(url: str, text: str) -> list:
    hits = list(scan_text(text))
    if url.lower().endswith((".js", ".mjs")) or "javascript" in url:
        hits.extend(scan_js_secrets(text, source_url=url))
    return hits


async def crawl_live_site(
    client: httpx.AsyncClient,
    hosts: list[str],
    *,
    auth: LiveAuth,
    include_subdomains: bool = True,
    max_pages: int = 120,
    max_depth: int = 4,
    concurrency: int = 8,
    extra_keywords: list[str] | None = None,
    extra_exts: list[str] | None = None,
    progress_cb: Callable[[int, int, str], None] | None = None,
    max_seconds: float | None = 600.0,
    enable_osint: bool = True,
    rps: float | None = 30.0,
) -> LiveCrawlResult:
    """BFS + SPA asset harvest on live site with optional auth."""
    deadline = time.monotonic() + max_seconds if max_seconds and max_seconds > 0 else None
    rate_limiter = AsyncRateLimiter(rps)
    multi_host = len(hosts) > 3
    schemes = ("https",) if multi_host else ("https", "http")
    api_paths = ("/api/", "/api/v1/", "/api/v2/", "/graphql", "/rest/", "/caps/")
    if multi_host:
        api_paths = ("/api/",)
    leak_n = 4 if multi_host else 12
    seeds: list[str] = []
    for host in hosts:
        base = normalize_target(host)
        if not base:
            continue
        for scheme in schemes:
            seeds.append(f"{scheme}://{base}/")
            for api in api_paths:
                seeds.append(f"{scheme}://{base}{api}")
            for path in LEAK_PATHS[:leak_n]:
                seeds.append(f"{scheme}://{base}{path}")

    priority: deque[str] = deque()
    queue: deque[tuple[str, int]] = deque()
    seen: set[str] = set()

    def _enqueue(url: str, depth: int, *, prio: bool = False) -> None:
        if not _host_in_scope(url, hosts, include_subdomains=include_subdomains) or not _should_fetch(url):
            return
        key = url.split("#")[0].rstrip("/").lower()
        if key in seen:
            return
        seen.add(key)
        if prio:
            priority.append(url)
        else:
            queue.append((url, depth))

    pages: list[CrawledPage] = []
    urls_seen: list[str] = []
    errors: list[str] = []
    home_bodies: dict[str, str] = {}
    auth_ok = True
    js_fetched = 0
    api_probed = 0
    sem = asyncio.Semaphore(concurrency)
    extra_kw = extra_keywords or []
    extra_ext = extra_exts or []
    main_js_blobs: list[str] = []

    async def _get(url: str) -> httpx.Response | None:
        headers = dict(auth.request_headers())
        headers.setdefault("Accept", "text/html,application/json,*/*;q=0.8")
        kwargs: dict = {"timeout": 12.0 if multi_host else 20.0, "follow_redirects": True, "headers": headers}
        basic = auth.basic_auth()
        if basic:
            kwargs["auth"] = httpx.BasicAuth(basic[0], basic[1])
        try:
            await rate_limiter.acquire()
            return await client.get(url, **kwargs)
        except httpx.HTTPError as exc:
            errors.append(f"{url}: {exc}")
            return None

    async def _load_homepage(host: str) -> None:
        key = normalize_target(host)
        if not key or key in home_bodies:
            return
        for scheme in schemes:
            resp = await _get(f"{scheme}://{key}/")
            if resp is None or resp.status_code >= 400:
                continue
            text, _ = _decode_body(resp)
            if text and len(text.strip()) > 80:
                home_bodies[key] = text
                return

    for host in hosts:
        await _load_homepage(host)

    for seed in seeds:
        _enqueue(seed, 0, prio=seed.endswith(".js"))

    async def _fetch(url: str, depth: int) -> CrawledPage | None:
        nonlocal auth_ok, js_fetched, api_probed
        async with sem:
            response = await _get(url)
        if response is None:
            return None
        if response.status_code in {401, 403}:
            if depth == 0 and not auth.active:
                auth_ok = False
            return None
        if response.status_code >= 400:
            return None
        text, ctype = _decode_body(response)
        if not text or len(text.strip()) < 4:
            return None
        final_url = str(response.url)
        if "/api/" in urlparse(final_url).path.lower():
            api_probed += 1
        if final_url.lower().endswith((".js", ".mjs")) or "/static/js/" in final_url.lower():
            js_fetched += 1
            if len(text) < 400000 and "main" in final_url.lower():
                main_js_blobs.append(text[:400000])
        hits = _scan_page_text(final_url, text)
        osint_hits = list(scan_osint(text, source_url=final_url, scope_hosts=hosts)) if enable_osint else []
        return CrawledPage(
            url=final_url,
            requested_url=url,
            text=text,
            content_type=ctype,
            status=response.status_code,
            depth=depth,
            secret_hits=hits,
            osint_hits=osint_hits,
        )

    while (priority or queue) and len(pages) < max_pages:
        if deadline and time.monotonic() >= deadline:
            errors.append("timeout")
            break
        if priority:
            url = priority.popleft()
            depth = 0
        else:
            url, depth = queue.popleft()
        key = url.split("#")[0].rstrip("/").lower()
        if key in {u.split("#")[0].rstrip("/").lower() for u in urls_seen}:
            continue
        page = await _fetch(url, depth)
        if not page:
            continue
        pages.append(page)
        urls_seen.append(page.url)
        if progress_cb:
            progress_cb(len(pages), max_pages, page.url)

        assets = extract_spa_assets(
            page.text if page.content_type.startswith("text/html") or "<html" in page.text[:300].lower() else "",
            main_js_blobs + ([page.text] if page.url.lower().endswith((".js", ".mjs")) else []),
            page.url,
        )
        for asset in assets:
            _enqueue(asset, depth + 1, prio=asset.lower().endswith((".js", ".mjs", ".json")))

        if depth >= max_depth:
            continue
        links = set(extract_html_links(page.text, page.url, limit=120))
        if is_script_or_data(page.url, page.content_type):
            for ep in extract_js_endpoints(page.text):
                links.add(urljoin(page.url, ep))
        for link in links:
            ext = _path_ext(link)
            is_asset = ext in {".js", ".mjs", ".json", ".xml", ".env", ".php", ".txt", ".yml", ".yaml", ".map"}
            klass = classify_url(link, extra_keywords=extra_kw, extra_exts=extra_ext)
            interesting = bool(klass) or is_asset
            if not interesting and depth > 0:
                if not re.search(r"(?i)(admin|login|api|config|backup|debug|install|setup|auth|panel|manage|caps)", link):
                    continue
            _enqueue(link, depth + 1, prio=is_asset)

    return LiveCrawlResult(
        pages=pages,
        urls_seen=urls_seen,
        errors=errors[:20],
        auth_ok=auth_ok,
        home_bodies=home_bodies,
        js_fetched=js_fetched,
        api_probed=api_probed,
    )


def pages_for_llm(pages: list[CrawledPage], limit: int = 32) -> list[tuple[str, str]]:
    ranked: list[tuple[int, CrawledPage]] = []
    for page in pages:
        score = len(page.secret_hits) * 5
        if worth_llm_extract(page.url, page.content_type):
            score += 4
        if classify_url(page.url):
            score += 3
        if page.url.lower().endswith((".env", ".json", ".js", ".mjs", ".php", ".xml", ".yml", ".yaml")):
            score += 3
        if "/static/js/" in page.url.lower():
            score += 2
        ranked.append((score, page))
    ranked.sort(key=lambda pair: -pair[0])
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for _, page in ranked:
        key = page.url.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append((page.url, page.text))
        if len(out) >= limit:
            break
    return out
