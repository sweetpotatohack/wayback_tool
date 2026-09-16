from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from urllib.parse import urljoin, unquote, urlparse

import httpx

from app.config import get_settings
from app.services.pentest_intel import auth_cdx_filter

CDX_ENDPOINT = "https://web.archive.org/cdx/search/cdx"
COMMONCRAWL_COLLINFO = "https://index.commoncrawl.org/collinfo.json"
COMMONCRAWL_INDEX = "CC-MAIN-2024-33"
WAYBACK_RAW = "https://web.archive.org/web/{timestamp}id_/{original}"
OFFLINE_MARKERS = (b"Temporarily Offline", b"Internet Archive: Temporarily Offline")

_cc_index_cache: str | None = None
_wayback_offline: bool | None = None


def reset_wayback_state() -> None:
    global _wayback_offline, _cc_index_cache
    _wayback_offline = None
    _cc_index_cache = None

SENSITIVE_QUERY = re.compile(
    r"(?i)[?&](password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth|session)=([^&\s]+)"
)
BASIC_AUTH = re.compile(r"^https?://([^/\s:@]+):([^/\s:@]+)@")


@dataclass
class Capture:
    original: str
    timestamp: str
    status: str
    mimetype: str
    digest: str
    length: str

    @property
    def archive_url(self) -> str:
        if not self.timestamp:
            return f"https://web.archive.org/web/*/{self.original}"
        return f"https://web.archive.org/web/{self.timestamp}/{self.original}"

    @property
    def raw_archive_url(self) -> str:
        return WAYBACK_RAW.format(timestamp=self.timestamp, original=self.original)


def normalize_target(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    host = parsed.netloc.lower().split("@")[-1]
    host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def parse_targets(blob: str) -> list[str]:
    seen: list[str] = []
    for line in re.split(r"[\s,;]+", blob):
        host = normalize_target(line)
        if host and host not in seen:
            seen.append(host)
    return seen


def apex_domain(host: str) -> str:
    """Registrable apex, e.g. tr1.sipaero.ru → sipaero.ru."""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def group_hosts_by_apex(hosts: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for host in hosts:
        groups.setdefault(apex_domain(host), []).append(host)
    return groups


def commoncrawl_host_pattern(host: str, include_subdomains: bool) -> str:
    """Use *.apex only for apex hosts; explicit subdomains are queried as-is."""
    if not include_subdomains:
        return host
    if host.count(".") <= 1:
        return f"*.{host}"
    return host


def extract_url_secrets(url: str) -> list[tuple[str, str, str]]:
    """Return (title, masked, evidence) for secrets embedded in the URL itself."""
    hits: list[tuple[str, str, str]] = []
    basic = BASIC_AUTH.match(url)
    if basic:
        user, password = basic.group(1), basic.group(2)
        hits.append(("Basic Auth в URL", f"{user}:{password}", url[:300]))
    for match in SENSITIVE_QUERY.finditer(url):
        key, value = match.group(1), match.group(2)
        hits.append((f"Секрет в query: {key}", store_secret(value), match.group(0)[:200]))
    return hits


def store_secret(value: str, *, limit: int = 4000) -> str:
    """Persist secret/contact value without masking."""
    if not value:
        return ""
    return value[:limit]


def mask_value(value: str, keep: int = 3) -> str:
    """Backward-compatible alias — values are stored in full."""
    return store_secret(value)


def is_archived_capture(capture: Capture) -> bool:
    ts = (capture.timestamp or "").strip()
    return len(ts) >= 8 and ts[:8].isdigit()


def replay_url(original: str, timestamp: str = "") -> str:
    ts = timestamp if is_archived_capture(Capture(original, timestamp, "200", "", "", "")) else "20240101000000"
    return f"https://web.archive.org/web/{ts}/{original}"


def _parse_cdx_payload(data: object) -> tuple[list[Capture], str | None]:
    if not isinstance(data, list) or not data:
        return [], None
    rows = data
    resume = None
    body = rows[1:] if rows and isinstance(rows[0], list) and rows[0] and rows[0][0] == "original" else rows
    if len(body) >= 2 and body[-2] == []:
        last = body[-1]
        resume = last[0] if isinstance(last, list) and last else (last if isinstance(last, str) else None)
        body = body[:-2]
    captures: list[Capture] = []
    for row in body:
        if not isinstance(row, list) or not row:
            continue
        original = row[0] if len(row) > 0 else ""
        timestamp = row[1] if len(row) > 1 else ""
        status = row[2] if len(row) > 2 else ""
        mimetype = row[3] if len(row) > 3 else ""
        digest = row[4] if len(row) > 4 else ""
        length = row[5] if len(row) > 5 else ""
        if original:
            captures.append(
                Capture(
                    original=original,
                    timestamp=str(timestamp),
                    status=str(status),
                    mimetype=str(mimetype),
                    digest=str(digest),
                    length=str(length),
                )
            )
    return captures, resume


async def latest_commoncrawl_index(client: httpx.AsyncClient) -> str:
    indexes = await list_commoncrawl_indexes(client, limit=1)
    return indexes[0] if indexes else COMMONCRAWL_INDEX


async def list_commoncrawl_indexes(client: httpx.AsyncClient, *, limit: int = 3) -> list[str]:
    global _cc_index_cache
    if _cc_index_cache and limit <= 1:
        return [_cc_index_cache]
    try:
        response = await client.get(COMMONCRAWL_COLLINFO, timeout=20.0)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list) and data:
            out: list[str] = []
            for row in data[:limit]:
                if isinstance(row, dict) and row.get("id"):
                    out.append(str(row["id"]))
            if out:
                _cc_index_cache = out[0]
                return out
    except Exception:
        pass
    return [COMMONCRAWL_INDEX]


def _response_offline(content: bytes, status: int) -> bool:
    """True only for a genuine global outage page on HTTP 200 — not 503 rate limits."""
    if status != 200:
        return False
    head = content[:8000]
    return any(marker in head for marker in OFFLINE_MARKERS)


async def probe_wayback(client: httpx.AsyncClient) -> str:
    """online | slow — never hard-offline (503 «Temporarily Offline» is usually rate limit)."""
    global _wayback_offline
    _wayback_offline = False
    for attempt in range(5):
        try:
            response = await client.get(
                CDX_ENDPOINT,
                params={"url": "example.com", "output": "json", "limit": 1},
                timeout=httpx.Timeout(22.0, connect=10.0),
            )
            if response.status_code == 200 and not _response_offline(response.content, response.status_code):
                return "online"
            if response.status_code in {429, 503, 502}:
                await asyncio.sleep(2.0 * (attempt + 1))
                continue
            await asyncio.sleep(1.0 * (attempt + 1))
        except httpx.TimeoutException:
            await asyncio.sleep(1.5 * (attempt + 1))
        except httpx.HTTPError:
            await asyncio.sleep(1.5 * (attempt + 1))
    return "slow"


async def _cdx_page(
    client: httpx.AsyncClient,
    params: dict[str, str | int] | list[tuple[str, str | int]],
    *,
    timeout: float = 35.0,
) -> tuple[list[Capture], str | None]:
    last_exc: Exception | None = None
    for attempt in range(5):
        try:
            response = await client.get(
                CDX_ENDPOINT,
                params=params,
                timeout=httpx.Timeout(timeout, connect=10.0),
            )
            if response.status_code in {429, 503, 502}:
                await asyncio.sleep(2.0 * (attempt + 1))
                continue
            if _response_offline(response.content, response.status_code):
                return [], None
            response.raise_for_status()
            if not response.content:
                return [], None
            try:
                payload = response.json()
            except ValueError:
                return [], None
            return _parse_cdx_payload(payload)
        except httpx.TimeoutException as exc:
            last_exc = exc
            await asyncio.sleep(1.5 * (attempt + 1))
            continue
        except Exception as exc:  # noqa: BLE001 — network retries
            last_exc = exc
            await asyncio.sleep(1.0 * (attempt + 1))
    if last_exc:
        return [], None
    return [], None


async def enumerate_cdx(
    client: httpx.AsyncClient,
    host: str,
    *,
    include_subdomains: bool = True,
    limit: int = 8000,
    extra_filter: str | None = None,
    url_pattern: str | None = None,
    date_from: str = "",
    date_to: str = "",
    status_200_only: bool = True,
) -> list[Capture]:
    query = url_pattern or host
    params: list[tuple[str, str | int]] = [
        ("url", query),
        ("output", "json"),
        ("fl", "original,timestamp,statuscode,mimetype,digest,length"),
        ("collapse", "urlkey"),
        ("limit", min(5000, limit)),
        ("showResumeKey", "true"),
    ]
    if status_200_only:
        params.append(("filter", "statuscode:200"))
    if date_from:
        params.append(("from", re.sub(r"\D", "", date_from)[:14]))
    if date_to:
        params.append(("to", re.sub(r"\D", "", date_to)[:14]))
    if not url_pattern:
        params.append(("matchType", "domain" if include_subdomains else "host"))
    if extra_filter:
        params.append(("filter", extra_filter))

    collected: list[Capture] = []
    resume: str | None = None
    seen: set[str] = set()

    while len(collected) < limit:
        page_params = list(params)
        if resume:
            page_params.append(("resumeKey", resume))
        captures, resume = await _cdx_page(client, page_params)
        if not captures:
            break
        added = 0
        for cap in captures:
            key = cap.original
            if key in seen:
                continue
            seen.add(key)
            collected.append(cap)
            added += 1
            if len(collected) >= limit:
                break
        if not resume or added == 0:
            break
        await asyncio.sleep(get_settings().wayback_delay_ms / 1000)
    return collected


def compile_url_patterns(blob: str) -> list[re.Pattern[str]]:
    """Regex filters like wayback-machine-scraper --allow / --deny."""
    out: list[re.Pattern[str]] = []
    for line in re.split(r"[\n,;]+", blob or ""):
        token = line.strip()
        if not token:
            continue
        try:
            out.append(re.compile(token, re.I))
        except re.error:
            continue
    return out


def url_passes_filters(url: str, allow: list[re.Pattern[str]], deny: list[re.Pattern[str]]) -> bool:
    if deny and any(p.search(url) for p in deny):
        return False
    if allow and not any(p.search(url) for p in allow):
        return False
    return True


_HREF_SRC = re.compile(
    r"""(?i)(?:href|src|action|data-url)\s*=\s*["']([^"'#][^"']{0,400})["']"""
)


def extract_html_links(html: str, base_url: str, limit: int = 120) -> list[str]:
    """Link crawl from archived HTML (scrapy-wayback-machine / libwayback idea)."""
    out: list[str] = []
    seen: set[str] = set()
    for match in _HREF_SRC.finditer(html[:600000]):
        ref = match.group(1).strip()
        if ref.startswith(("javascript:", "mailto:", "data:", "tel:", "#")):
            continue
        abs_url = urljoin(base_url, ref)
        parsed = urlparse(abs_url)
        if parsed.scheme not in {"http", "https"}:
            continue
        if abs_url not in seen:
            seen.add(abs_url)
            out.append(abs_url)
        if len(out) >= limit:
            break
    return out


async def enumerate_versions(
    client: httpx.AsyncClient,
    url: str,
    *,
    limit: int = 12,
    date_from: str = "",
    date_to: str = "",
    status_200_only: bool = True,
) -> list[Capture]:
    """All archived timestamps for one URL (waybackurls --get-versions / scrapy timemap)."""
    params: list[tuple[str, str | int]] = [
        ("url", url),
        ("output", "json"),
        ("fl", "original,timestamp,statuscode,mimetype,digest,length"),
        ("limit", min(limit, 50)),
    ]
    if status_200_only:
        params.append(("filter", "statuscode:200"))
    if date_from:
        params.append(("from", re.sub(r"\D", "", date_from)[:14]))
    if date_to:
        params.append(("to", re.sub(r"\D", "", date_to)[:14]))
    captures, _ = await _cdx_page(client, params)
    return captures


async def _commoncrawl_fetch(
    client: httpx.AsyncClient,
    *,
    index_id: str,
    url_pattern: str,
    limit: int,
) -> tuple[list[Capture], str]:
    endpoint = f"https://index.commoncrawl.org/{index_id}-index"
    params = {"url": url_pattern, "output": "json"}
    found: list[Capture] = []
    seen: set[str] = set()
    try:
        async with client.stream("GET", endpoint, params=params, timeout=90.0) as response:
            if response.status_code >= 400:
                body = ""
                try:
                    body = (await response.aread())[:240].decode("utf-8", errors="replace")
                except Exception:
                    pass
                return [], f"HTTP {response.status_code}: {body or url_pattern}"
            async for line in response.aiter_lines():
                if not line.strip():
                    continue
                if line.lstrip().startswith("{"):
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                else:
                    continue
                if row.get("message"):
                    return [], str(row.get("message"))
                original = row.get("url") or ""
                ts = str(row.get("timestamp") or "")
                if not original or original in seen:
                    continue
                seen.add(original)
                found.append(
                    Capture(
                        original=original,
                        timestamp=ts,
                        status=str(row.get("status") or "200"),
                        mimetype=str(row.get("mime") or row.get("mime-detected") or ""),
                        digest="",
                        length="",
                    )
                )
                if len(found) >= limit:
                    break
    except httpx.HTTPError as exc:
        return [], str(exc)
    return found, ""


async def enumerate_commoncrawl(
    client: httpx.AsyncClient,
    host: str,
    *,
    include_subdomains: bool = True,
    limit: int = 4000,
    index_id: str | None = None,
    index_ids: list[str] | None = None,
) -> list[Capture]:
    """Extra URL feed from Common Crawl (waybackurls second source)."""
    indexes = index_ids or ([index_id] if index_id else await list_commoncrawl_indexes(client, limit=3))
    prefix = commoncrawl_host_pattern(host, include_subdomains)
    patterns = [f"{prefix}/*", f"{host}/*"]
    if include_subdomains and host.count(".") <= 1:
        patterns.append(f"*.{host}*")
    for idx in indexes:
        for pattern in patterns:
            found, _note = await _commoncrawl_fetch(client, index_id=idx, url_pattern=pattern, limit=limit)
            if found:
                return found
    return []


async def enumerate_commoncrawl_with_note(
    client: httpx.AsyncClient,
    host: str,
    *,
    include_subdomains: bool = True,
    limit: int = 4000,
) -> tuple[list[Capture], str]:
    indexes = await list_commoncrawl_indexes(client, limit=3)
    prefix = commoncrawl_host_pattern(host, include_subdomains)
    patterns = [f"{prefix}/*", f"{host}/*"]
    if include_subdomains and host.count(".") <= 1:
        patterns.append(f"*.{host}*")
    notes: list[str] = []
    for idx in indexes:
        for pattern in patterns:
            found, note = await _commoncrawl_fetch(client, index_id=idx, url_pattern=pattern, limit=limit)
            if found:
                return found, f"{idx} · {pattern}"
            if note:
                notes.append(f"{idx}/{pattern}: {note}")
    return [], notes[-1] if notes else "нет записей в Common Crawl"


async def waybackurls_style(
    client: httpx.AsyncClient,
    host: str,
    *,
    include_subdomains: bool = True,
    limit: int = 8000,
    date_from: str = "",
    date_to: str = "",
    status_200_only: bool = True,
) -> list[Capture]:
    """CDX query like tomnomnom/waybackurls: *.domain/* collapse=urlkey."""
    pattern = f"*.{host}/*" if include_subdomains else f"{host}/*"
    return await enumerate_cdx(
        client,
        host,
        include_subdomains=include_subdomains,
        limit=limit,
        url_pattern=pattern,
        date_from=date_from,
        date_to=date_to,
        status_200_only=status_200_only,
    )


# Regex filters on the CDX `original` / mime fields.
TARGETED_FILTERS = [
    auth_cdx_filter(),
    r"original:(?i).*(\.env|wp-config|\.git/|id_rsa|id_ed25519|\.htpasswd|\.htaccess|phpinfo|allinfo\.php|dbconn)",
    r"original:(?i).*(web\.config|appsettings|docker-compose|credentials|service-account|firebase|\.npmrc|\.netrc|\.pypirc|\.settings\.php)",
    r"original:(?i).*(password|passwords|passwd|passlist|credentials|secrets?|logins?|htpasswd)\.(txt|csv|xls|xlsx|sql|bak|old|json|xml|log|ini)",
    r"original:(?i).*(^|/)(configs?|configuration)(\.(php|inc|json|ya?ml|xml|ini|conf|cfg|bak|old|dist)|/)",
    r"original:(?i).*(config|backup|dump|database|secrets?|parameters)\.(php|json|ya?ml|xml|ini|conf|cfg|properties)",
    r"original:(?i).*(\.sql|\.bak|\.old|\.orig|\.swp|\.dist|\.inc)(\?|$)",
    r"original:(?i).*(\.zip|\.tar|\.tgz|\.gz|\.7z|\.rar|\.pem|\.p12|\.key|\.kdbx|\.ovpn)(\?|$)",
    r"original:(?i).*(phpmyadmin|adminer|phpminiadmin|bitrix/backup|bitrix/php_interface|\.DS_Store|server-status|composer\.json)",
    r"original:(?i).*(config|settings|env|secret|api|app\.min|main\.min|bundle|runtime)\.(js|mjs)",
    r"original:(?i).*robots\.txt",
]

MIME_FILTERS = [
    "mimetype:application/json",
    "mimetype:text/xml",
    "mimetype:application/xml",
]


def _escape_filter(word: str) -> str:
    return re.escape(word)[:80]


# waymore/gau-style: ask CDX for exact leak filenames, not just keyword greps.
LEAK_PATHS = (
    "/.env",
    "/.env.bak",
    "/.env.production",
    "/.env.local",
    "/.git/config",
    "/.git/HEAD",
    "/.htpasswd",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/config.php",
    "/config.json",
    "/config.yml",
    "/configuration.php",
    "/appsettings.json",
    "/web.config",
    "/application.properties",
    "/composer.json",
    "/package.json",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/backup.zip",
    "/phpinfo.php",
    "/info.php",
    "/adminer.php",
    "/phpminiadmin.php",
    "/server-status",
    "/debug.log",
    "/error_log",
    "/id_rsa",
    "/.aws/credentials",
    "/api/config",
    "/api/v1/config",
    "/static/js/main.js",
    "/js/app.js",
    "/js/config.js",
)


async def hunt_known_leaks(
    client: httpx.AsyncClient,
    host: str,
    *,
    include_subdomains: bool,
    date_from: str = "",
    date_to: str = "",
    status_200_only: bool = True,
) -> list[Capture]:
    found: list[Capture] = []
    seen: set[str] = set()
    batch_size = 8
    for start in range(0, len(LEAK_PATHS), batch_size):
        chunk = LEAK_PATHS[start : start + batch_size]
        joined = "|".join(re.escape(p) for p in chunk)
        pattern = f"original:(?i).*(?:{joined})(\\?|$)"
        try:
            caps = await enumerate_cdx(
                client,
                host,
                include_subdomains=include_subdomains,
                limit=40,
                extra_filter=pattern,
                date_from=date_from,
                date_to=date_to,
                status_200_only=status_200_only,
            )
        except Exception:
            continue
        for cap in caps:
            if cap.original not in seen:
                seen.add(cap.original)
                found.append(cap)
        await asyncio.sleep(get_settings().wayback_delay_ms / 2000)
    return found


async def targeted_cdx(
    client: httpx.AsyncClient,
    host: str,
    include_subdomains: bool,
    *,
    extra_keywords: list[str] | None = None,
    extra_exts: list[str] | None = None,
    date_from: str = "",
    date_to: str = "",
    status_200_only: bool = True,
    scan_scripts: bool = True,
) -> list[Capture]:
    found: list[Capture] = []
    seen: set[str] = set()
    filters = list(TARGETED_FILTERS)
    if scan_scripts:
        filters.extend(MIME_FILTERS)
    kws = [k for k in (extra_keywords or []) if len(k) >= 3][:15]
    exts = [e.lstrip(".") for e in (extra_exts or []) if e.strip()][:20]
    if kws:
        joined = "|".join(_escape_filter(k) for k in kws)
        filters.append(f"original:(?i).*({joined})")
    if exts:
        joined = "|".join(_escape_filter(e) for e in exts)
        filters.append(f"original:(?i).*\\.({joined})(\\?|$)")

    async def _eat(extra: str, limit: int = 400) -> None:
        try:
            caps = await enumerate_cdx(
                client,
                host,
                include_subdomains=include_subdomains,
                limit=limit,
                extra_filter=extra,
                date_from=date_from,
                date_to=date_to,
                status_200_only=status_200_only,
            )
        except Exception:
            return
        for cap in caps:
            if cap.original not in seen:
                seen.add(cap.original)
                found.append(cap)

    sem = asyncio.Semaphore(8)

    async def _eat_guard(extra: str, limit: int = 400) -> None:
        async with sem:
            await _eat(extra, limit=limit)
            await asyncio.sleep(get_settings().wayback_delay_ms / 2500)

    jobs = [_eat_guard(extra) for extra in filters]
    if scan_scripts:
        jobs.append(_eat_guard("mimetype:application/javascript", limit=200))
    await asyncio.gather(*jobs, return_exceptions=True)
    for cap in await hunt_known_leaks(
        client,
        host,
        include_subdomains=include_subdomains,
        date_from=date_from,
        date_to=date_to,
        status_200_only=status_200_only,
    ):
        if cap.original not in seen:
            seen.add(cap.original)
            found.append(cap)
    return found


ROBOTS_DISALLOW = re.compile(r"(?i)^\s*disallow\s*:\s*(\S+)", re.M)


def parse_robots_paths(text: str) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for match in ROBOTS_DISALLOW.finditer(text or ""):
        raw = match.group(1).strip()
        if raw in {"", "/"}:
            continue
        if raw.startswith("*"):
            continue
        if not raw.startswith("/"):
            raw = "/" + raw
        raw = raw.split("*", 1)[0]
        if raw in seen or len(raw) < 2:
            continue
        seen.add(raw)
        paths.append(raw)
        if len(paths) >= 40:
            break
    return paths


SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
ROBOTS_INTERESTING = re.compile(
    r"(?i)(admin|bitrix|phpmyadmin|\.git|backup|private|include|cgi-bin|wp-admin|config|\.env|sql|passwd)"
)


def parse_sitemap_locs(text: str, limit: int = 400) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in SITEMAP_LOC.finditer(text or ""):
        url = match.group(1).strip()
        if url and url not in seen:
            seen.add(url)
            out.append(url)
        if len(out) >= limit:
            break
    return out


def interesting_robots_paths(paths: list[str]) -> list[str]:
    return [p for p in paths if ROBOTS_INTERESTING.search(p)]


TEXT_MIME_HINTS = (
    "text/",
    "json",
    "xml",
    "javascript",
    "x-www-form-urlencoded",
    "x-sh",
    "x-yaml",
    "yaml",
    "sql",
    "application/octet-stream",
)


def looks_textual(mimetype: str, url: str) -> bool:
    mime = (mimetype or "").lower()
    if any(hint in mime for hint in TEXT_MIME_HINTS) or mime in {"", "unk", "warc/revisit"}:
        return True
    lower = url.lower()
    return any(
        lower.endswith(ext)
        for ext in (
            ".env",
            ".json",
            ".yml",
            ".yaml",
            ".xml",
            ".txt",
            ".php",
            ".py",
            ".js",
            ".mjs",
            ".conf",
            ".ini",
            ".cfg",
            ".sql",
            ".bak",
            ".log",
            ".pem",
            ".key",
            ".inc",
            ".csv",
            ".log",
            ".git/config",
            ".htaccess",
            ".htpasswd",
            ".ovpn",
        )
    )


async def fetch_raw_snapshot(client: httpx.AsyncClient, capture: Capture, max_bytes: int = 2_000_000) -> str | None:
    if not looks_textual(capture.mimetype, capture.original):
        return None
    url = capture.raw_archive_url
    try:
        async with client.stream("GET", url, follow_redirects=True) as response:
            if response.status_code >= 400:
                return None
            content_type = response.headers.get("content-type", "")
            if content_type.startswith(("image/", "video/", "audio/", "font/")):
                return None
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size > max_bytes:
                    break
            raw = b"".join(chunks)
    except httpx.HTTPError:
        return None
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding, errors="replace")
        except Exception:
            continue
    return None


def make_client() -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(
        headers={"User-Agent": settings.wayback_user_agent},
        timeout=httpx.Timeout(settings.wayback_timeout, connect=10.0),
        follow_redirects=True,
    )
