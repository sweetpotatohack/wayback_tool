from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.config import get_settings
from app.services.wayback import Capture, commoncrawl_host_pattern, enumerate_cdx, latest_commoncrawl_index, normalize_target

OFFLINE_MARKERS = (b"Temporarily Offline", b"Internet Archive: Temporarily Offline")


@dataclass(frozen=True)
class DorkDef:
    id: str
    title: str
    category: str
    severity: str
    path: str = ""
    cdx_filter: str = ""
    cc_suffix: str = ""


# Built-in high-signal dorks (always present).
BUILTIN_DORK_LIBRARY: tuple[DorkDef, ...] = (
    DorkDef("env", "Файл .env", "secrets", "critical", path="/.env", cdx_filter=r"original:(?i).*\.env(\?|$)"),
    DorkDef("git", "Git config", "vcs", "critical", path="/.git/config", cdx_filter=r"original:(?i).*\.git/"),
    DorkDef("htpasswd", ".htpasswd", "secrets", "critical", path="/.htpasswd", cdx_filter=r"original:(?i).*\.htpasswd"),
    DorkDef("wp-config", "wp-config.php", "config", "critical", path="/wp-config.php", cdx_filter=r"original:(?i).*wp-config\.php"),
    DorkDef("phpinfo", "phpinfo / allinfo", "disclosure", "high", path="/phpinfo.php", cdx_filter=r"original:(?i).*(phpinfo|allinfo\.php)"),
    DorkDef("adminer", "Adminer / phpMyAdmin", "panels", "high", path="/adminer.php", cdx_filter=r"original:(?i).*(adminer|phpmyadmin|phpminiadmin)"),
    DorkDef("backup-sql", "SQL dump", "backup", "high", path="/backup.sql", cdx_filter=r"original:(?i).*(backup|dump|database)\.sql"),
    DorkDef("backup-zip", "Backup archive", "backup", "high", path="/backup.zip", cdx_filter=r"original:(?i).*\.(zip|tar|tgz|7z|sql\.gz)(\?|$)"),
    DorkDef("web-config", "web.config / appsettings", "config", "high", path="/web.config", cdx_filter=r"original:(?i).*(web\.config|appsettings\.json)"),
    DorkDef("docker", "docker-compose secrets", "config", "medium", path="/docker-compose.yml", cdx_filter=r"original:(?i).*docker-compose"),
    DorkDef("aws-creds", "AWS credentials", "cloud", "critical", path="/.aws/credentials", cdx_filter=r"original:(?i).*\.aws/credentials"),
    DorkDef("id-rsa", "SSH private key", "secrets", "critical", path="/id_rsa", cdx_filter=r"original:(?i).*(id_rsa|id_ed25519|\.pem)(\?|$)"),
    DorkDef("passwd-txt", "passwords.txt", "secrets", "high", path="/passwords.txt", cdx_filter=r"original:(?i).*(password|passwd|credentials).*\.(txt|csv|xls)"),
    DorkDef("config-php", "config.php / settings", "config", "high", path="/config.php", cdx_filter=r"original:(?i).*(config|settings|parameters)\.(php|json|ya?ml|ini)"),
    DorkDef("bitrix-backup", "Bitrix backup", "backup", "high", path="/bitrix/backup/", cdx_filter=r"original:(?i).*bitrix/(backup|php_interface)"),
    DorkDef("server-status", "server-status", "disclosure", "medium", path="/server-status", cdx_filter=r"original:(?i).*server-status"),
    DorkDef("debug-log", "debug / error logs", "logs", "medium", path="/debug.log", cdx_filter=r"original:(?i).*(debug|error).*\.log"),
    DorkDef("api-config", "API config endpoints", "api", "high", path="/api/config", cc_suffix="*api*config*"),
    DorkDef("admin-panel", "inurl:admin", "panels", "medium", path="/admin/", cc_suffix="*admin*"),
    DorkDef("login-panel", "inurl:login", "panels", "medium", path="/login/", cc_suffix="*login*"),
    DorkDef("install-php", "install.php / setup", "install", "high", path="/install.php", cdx_filter=r"original:(?i).*(install|setup)\.php"),
    DorkDef("composer", "composer.json leak", "config", "medium", path="/composer.json", cdx_filter=r"original:(?i).*composer\.json"),
    DorkDef("package-json", "package.json secrets", "config", "medium", path="/package.json", cdx_filter=r"original:(?i).*package\.json"),
    DorkDef("js-config", "JS config bundles", "config", "medium", path="/js/config.js", cdx_filter=r"original:(?i).*(config|env|secret|api).*\.(js|mjs)"),
    DorkDef("swagger", "Swagger / OpenAPI", "api", "medium", path="/swagger.json", cdx_filter=r"original:(?i).*(swagger|openapi).*\.(json|ya?ml)"),
    DorkDef("actuator", "Spring actuator", "api", "high", path="/actuator/env", cdx_filter=r"original:(?i).*actuator/(env|heapdump|configprops)"),
    DorkDef("ds-store", ".DS_Store", "misc", "low", path="/.DS_Store", cdx_filter=r"original:(?i).*\.DS_Store"),
    DorkDef("svn", "SVN metadata", "vcs", "medium", path="/.svn/entries", cdx_filter=r"original:(?i).*\.svn/"),
    DorkDef("cgi-bin", "CGI scripts", "panels", "medium", path="/cgi-bin/", cc_suffix="*cgi-bin*"),
    DorkDef("phpmyadmin-path", "phpMyAdmin path", "panels", "high", path="/phpmyadmin/", cc_suffix="*phpmyadmin*"),
)


def get_dork_library() -> tuple[DorkDef, ...]:
    from app.services.dork_parser import merged_dork_library

    lib, _ = merged_dork_library()
    return lib


# Backward-compatible alias
DORK_LIBRARY: tuple[DorkDef, ...] = BUILTIN_DORK_LIBRARY


def dork_stats() -> dict:
    from app.services.dork_parser import merged_dork_library

    _, stats = merged_dork_library()
    return stats


def dork_categories() -> dict[str, list[DorkDef]]:
    out: dict[str, list[DorkDef]] = {}
    for item in get_dork_library():
        out.setdefault(item.category, []).append(item)
    return out


def path_candidates(host: str, include_subdomains: bool = False) -> list[str]:
    """Synthetic paths only for the apex host — no guessed subdomains."""
    hosts = [normalize_target(host)]
    if not hosts[0]:
        return []
    if include_subdomains:
        hosts.append(f"www.{hosts[0]}")
    schemes = ("https", "http")
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        for dork in get_dork_library():
            if not dork.path:
                continue
            for scheme in schemes:
                url = f"{scheme}://{h}{dork.path}"
                if url not in seen:
                    seen.add(url)
                    out.append(url)
    return out


def captures_from_paths(host: str, include_subdomains: bool = True) -> list[Capture]:
    return [
        Capture(original=url, timestamp="", status="200", mimetype="", digest="", length="")
        for url in path_candidates(host, include_subdomains)
    ]


async def _cc_dork_query(
    client: httpx.AsyncClient,
    host: str,
    suffix: str,
    *,
    include_subdomains: bool,
    index_id: str,
    limit: int,
) -> list[Capture]:
    prefix = commoncrawl_host_pattern(host, include_subdomains)
    pattern = f"{prefix}/{suffix}" if suffix.startswith("*") else f"{prefix}/*{suffix}*"
    endpoint = f"https://index.commoncrawl.org/{index_id}-index"
    found: list[Capture] = []
    seen: set[str] = set()
    try:
        async with client.stream(
            "GET",
            endpoint,
            params={"url": pattern, "output": "json"},
            timeout=45.0,
        ) as response:
            if response.status_code >= 400:
                return []
            async for line in response.aiter_lines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                original = row.get("url") or ""
                if not original or original in seen:
                    continue
                seen.add(original)
                found.append(
                    Capture(
                        original=original,
                        timestamp=str(row.get("timestamp") or ""),
                        status=str(row.get("status") or "200"),
                        mimetype=str(row.get("mime") or row.get("mime-detected") or ""),
                        digest="",
                        length="",
                    )
                )
                if len(found) >= limit:
                    break
    except httpx.HTTPError:
        return []
    return found


async def run_dork_scan(
    client: httpx.AsyncClient,
    host: str,
    *,
    include_subdomains: bool = True,
    use_cdx: bool = True,
    use_commoncrawl: bool = True,
    use_paths: bool = False,
    date_from: str = "",
    date_to: str = "",
    status_200_only: bool = True,
    per_dork_limit: int = 80,
    dork_tier: str = "stable500",
    progress: Callable[[int, int], None] | None = None,
) -> list[Capture]:
    from app.services.dork_tiers import get_library_for_tier, tier_config

    cfg = tier_config(dork_tier)
    if cfg["cdx"] <= 0:
        return []

    per_dork_limit = int(cfg.get("per_dork_limit") or per_dork_limit)
    max_cdx = int(cfg["cdx"])
    max_cc = int(cfg["cc"])

    found: list[Capture] = []
    seen: set[str] = set()

    def _eat(cap: Capture) -> None:
        if cap.original in seen:
            return
        seen.add(cap.original)
        found.append(cap)

    if use_paths:
        for cap in captures_from_paths(host, include_subdomains):
            _eat(cap)

    library = get_library_for_tier(dork_tier)
    sem = asyncio.Semaphore(6)

    if use_cdx:
        cdx_dorks = [d for d in library if d.cdx_filter][:max_cdx]
        total = len(cdx_dorks)
        done = 0

        async def _cdx_one(dork: DorkDef) -> None:
            nonlocal done
            if not dork.cdx_filter:
                return
            async with sem:
                try:
                    caps = await enumerate_cdx(
                        client,
                        host,
                        include_subdomains=include_subdomains,
                        limit=per_dork_limit,
                        extra_filter=dork.cdx_filter,
                        date_from=date_from,
                        date_to=date_to,
                        status_200_only=status_200_only,
                    )
                except Exception:
                    done += 1
                    if progress:
                        progress(done, total)
                    return
                for cap in caps:
                    _eat(cap)
                await asyncio.sleep(get_settings().wayback_delay_ms / 2000)
                done += 1
                if progress:
                    progress(done, total)

        await asyncio.gather(*[_cdx_one(d) for d in cdx_dorks], return_exceptions=True)

    if use_commoncrawl and max_cc > 0:
        index_id = await latest_commoncrawl_index(client)
        cc_pool = [d for d in library if d.cc_suffix]
        if not cc_pool:
            cc_pool = [d for d in get_dork_library() if d.cc_suffix]
        cc_dorks = cc_pool[:max_cc]

        async def _cc_one(dork: DorkDef) -> None:
            async with sem:
                caps = await _cc_dork_query(
                    client,
                    host,
                    dork.cc_suffix,
                    include_subdomains=include_subdomains,
                    index_id=index_id,
                    limit=min(per_dork_limit, 120),
                )
                for cap in caps:
                    _eat(cap)

        await asyncio.gather(*[_cc_one(d) for d in cc_dorks], return_exceptions=True)

    return found
