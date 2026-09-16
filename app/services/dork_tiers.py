"""Curated dork tiers for archive/CDX recon (Top 100 / 500 / 1000 / all)."""

from __future__ import annotations

from app.services.dork_parser import load_google_dorks
from app.services.dorks import BUILTIN_DORK_LIBRARY, DorkDef

ALLOWED_DORK_TIERS = frozenset({"off", "fast100", "stable500", "deep1000", "full3652"})

TIER_META: dict[str, dict] = {
    "off": {
        "label": "Выключено",
        "hint": "Dork-запросы к CDX / Common Crawl не выполняются.",
        "cdx": 0,
        "cc": 0,
        "per_dork_limit": 0,
    },
    "fast100": {
        "label": "Быстрый · Top 100",
        "hint": "Критичные утечки: .env, ключи, бэкапы, phpinfo, admin-панели. ~5–15 мин на цель.",
        "cdx": 100,
        "cc": 10,
        "per_dork_limit": 60,
    },
    "stable500": {
        "label": "Стандарт · Top 500",
        "hint": "Сбалансированный набор: секреты, конфиги, бэкапы, API, CMS. Рекомендуется.",
        "cdx": 500,
        "cc": 24,
        "per_dork_limit": 80,
    },
    "deep1000": {
        "label": "Глубокий · Top 1000",
        "hint": "Расширенный охват Google-dorks + встроенные паттерны. Долго.",
        "cdx": 1000,
        "cc": 40,
        "per_dork_limit": 100,
    },
    "full3652": {
        "label": "Максимум · все dorks",
        "hint": "Полная ranked-библиотека (~3652 CDX-паттерна). Очень долго — часы на домен.",
        "cdx": 3652,
        "cc": 60,
        "per_dork_limit": 120,
    },
}

# High-signal patterns for Wayback / CDX (prepended before ranked Google dorks).
EXTRA_CURATED: tuple[DorkDef, ...] = (
    DorkDef("env-bak", ".env backup variants", "secrets", "critical", cdx_filter=r"original:(?i).*\.env\.(bak|old|save|backup|swp|tmp)"),
    DorkDef("env-local", ".env.local / .production", "secrets", "critical", cdx_filter=r"original:(?i).*\.env\.(local|prod|production|staging)"),
    DorkDef("env-example", ".env.example leak", "secrets", "high", cdx_filter=r"original:(?i).*\.env\.example"),
    DorkDef("git-head", ".git/HEAD exposed", "vcs", "critical", cdx_filter=r"original:(?i).*\.git/HEAD"),
    DorkDef("git-config", ".git/config remote", "vcs", "critical", cdx_filter=r"original:(?i).*\.git/config"),
    DorkDef("git-index", ".git/index", "vcs", "critical", cdx_filter=r"original:(?i).*\.git/index"),
    DorkDef("hg", "Mercurial .hg", "vcs", "high", cdx_filter=r"original:(?i).*\.hg/"),
    DorkDef("db-yml", "database.yml / database.php", "config", "critical", cdx_filter=r"original:(?i).*(database\.ya?ml|db\.php|db_config)"),
    DorkDef("local-settings", "local_settings.py", "config", "critical", cdx_filter=r"original:(?i).*local_settings\.py"),
    DorkDef("settings-py", "Django settings", "config", "high", cdx_filter=r"original:(?i).*settings\.py"),
    DorkDef("application-props", "application.properties", "config", "high", cdx_filter=r"original:(?i).*application(-\w+)?\.(properties|ya?ml)"),
    DorkDef("secrets-yml", "secrets.yml / credentials", "config", "critical", cdx_filter=r"original:(?i).*(secrets|credentials)\.(ya?ml|json|xml)"),
    DorkDef("firebase", "firebase / google-services", "config", "high", cdx_filter=r"original:(?i).*(firebase|google-services)\.json"),
    DorkDef("kube-config", "kubeconfig", "cloud", "critical", cdx_filter=r"original:(?i).*(kubeconfig|\.kube/config)"),
    DorkDef("terraform", "terraform state/tfvars", "cloud", "critical", cdx_filter=r"original:(?i).*\.(tfstate|tfvars)"),
    DorkDef("s3-cfg", "s3 / aws config json", "cloud", "high", cdx_filter=r"original:(?i).*(s3|aws).*\.(json|ya?ml|conf)"),
    DorkDef("gcp-key", "GCP service account json", "cloud", "critical", cdx_filter=r"original:(?i).*service[_-]?account.*\.json"),
    DorkDef("sql-dump", "mysql / pg dump", "backup", "critical", cdx_filter=r"original:(?i).*(mysql|postgres|pg|mssql).*\.(sql|dump|gz)"),
    DorkDef("dump-sql", "dump.sql / db.sql", "backup", "critical", cdx_filter=r"original:(?i).*(dump|database|db|backup).*\.sql"),
    DorkDef("bak-files", ".bak / .old config", "backup", "high", cdx_filter=r"original:(?i).*\.(bak|old|orig|save|copy|~)(\?|$)"),
    DorkDef("tar-gz-backup", "archive backups", "backup", "high", cdx_filter=r"original:(?i).*(backup|site|www|html).*\.(tar|tar\.gz|tgz|zip)"),
    DorkDef("phpinfo-html", "phpinfo in html/txt", "disclosure", "high", cdx_filter=r"original:(?i).*(phpinfo|php-info|test\.php).*\.(html|txt|php)"),
    DorkDef("info-php", "info.php / test.php", "disclosure", "high", cdx_filter=r"original:(?i).*/(info|test|phpinfo|pi)\.php"),
    DorkDef("elmah", "ELMAH / trace.axd", "disclosure", "high", cdx_filter=r"original:(?i).*(elmah|trace\.axd|errorlog)"),
    DorkDef("crossdomain", "crossdomain.xml", "config", "medium", cdx_filter=r"original:(?i).*crossdomain\.xml"),
    DorkDef("clientaccess", "clientaccesspolicy.xml", "config", "medium", cdx_filter=r"original:(?i).*clientaccesspolicy\.xml"),
    DorkDef("robots-txt", "robots.txt sensitive paths", "recon", "low", path="/robots.txt", cdx_filter=r"original:(?i).*/robots\.txt"),
    DorkDef("sitemap", "sitemap.xml", "recon", "low", path="/sitemap.xml", cdx_filter=r"original:(?i).*/sitemap.*\.xml"),
    DorkDef("wp-json", "WordPress REST", "api", "medium", path="/wp-json/", cdx_filter=r"original:(?i).*/wp-json/"),
    DorkDef("wp-uploads", "wp-content/uploads", "backup", "medium", cdx_filter=r"original:(?i).*/wp-content/uploads/.*\.(sql|zip|gz)"),
    DorkDef("wp-debug", "wp-config debug log", "logs", "high", cdx_filter=r"original:(?i).*wp-content/debug\.log"),
    DorkDef("bitrix-settings", "bitrix settings", "config", "high", cdx_filter=r"original:(?i).*bitrix/\.settings\.php"),
    DorkDef("joomla-config", "Joomla configuration", "config", "high", cdx_filter=r"original:(?i).*configuration\.php"),
    DorkDef("drupal-settings", "Drupal settings.php", "config", "high", cdx_filter=r"original:(?i).*sites/default/settings\.php"),
    DorkDef("laravel-log", "laravel.log", "logs", "high", cdx_filter=r"original:(?i).*storage/logs/laravel\.log"),
    DorkDef("symfony-env", "Symfony .env.local.php", "secrets", "critical", cdx_filter=r"original:(?i).*\.env\.local\.php"),
    DorkDef("graphql", "GraphQL introspection", "api", "medium", path="/graphql", cdx_filter=r"original:(?i).*(graphql|gql)"),
    DorkDef("api-docs", "API docs / redoc", "api", "medium", cdx_filter=r"original:(?i).*(api-docs|redoc|swagger-ui)"),
    DorkDef("metrics", "metrics / prometheus", "api", "medium", cdx_filter=r"original:(?i).*/(metrics|prometheus|health)"),
    DorkDef("jenkins-file", "Jenkinsfile / credentials", "config", "high", cdx_filter=r"original:(?i).*(Jenkinsfile|credentials\.xml)"),
    DorkDef("npmrc", ".npmrc / .yarnrc token", "secrets", "high", cdx_filter=r"original:(?i).*\.(npmrc|yarnrc|pypirc)"),
    DorkDef("docker-env", ".dockerenv / Dockerfile secrets", "config", "medium", cdx_filter=r"original:(?i).*(Dockerfile|docker-compose.*\.ya?ml)"),
    DorkDef("vpn-config", "OpenVPN / ovpn", "secrets", "high", cdx_filter=r"original:(?i).*\.(ovpn|pcf|conf)(\?|$)"),
    DorkDef("shell-history", ".bash_history", "secrets", "high", cdx_filter=r"original:(?i).*\.(bash_history|zsh_history)"),
    DorkDef("vim-swp", "vim swap files", "misc", "medium", cdx_filter=r"original:(?i).*\.(swp|swo|swn)(\?|$)"),
    DorkDef("ftp-log", "ftp / access logs", "logs", "medium", cdx_filter=r"original:(?i).*(access|ftp|auth).*\.log"),
    DorkDef("admin-php", "admin.php variants", "panels", "medium", cdx_filter=r"original:(?i).*/admin(er)?\.php", cc_suffix="*admin*"),
    DorkDef("cpanel", "cPanel / WHM paths", "panels", "medium", cdx_filter=r"original:(?i).*(cpanel|whm|webmail)"),
    DorkDef("webdav", "webdav / propfind", "misc", "medium", cdx_filter=r"original:(?i).*(webdav|\.well-known)"),
)

_PRIORITY_TERMS = (
    ".env",
    "password",
    "passwd",
    "credential",
    "secret",
    "api key",
    "private key",
    "htpasswd",
    "wp-config",
    "id_rsa",
    "backup",
    "dump",
    "sql",
    "phpinfo",
    "adminer",
    "phpmyadmin",
    "actuator",
    "swagger",
    ".git",
    "config",
    "aws",
    "service account",
    "terraform",
    "kube",
)


def normalize_dork_tier(raw: str | None, *, enable_dorks: bool | None = None) -> str:
    tier = (raw or "").strip().lower()
    if tier in ALLOWED_DORK_TIERS:
        return tier
    if enable_dorks is False:
        return "off"
    return "stable500"


def effective_dork_tier(project) -> str:
    tier = getattr(project, "dork_tier", "") or ""
    return normalize_dork_tier(tier, enable_dorks=getattr(project, "enable_dorks", True))


def _cdx_ranked_count() -> int:
    return len([d for d in ranked_merged_library() if d.cdx_filter])


def tier_config(tier: str) -> dict:
    normalized = normalize_dork_tier(tier)
    cfg = dict(TIER_META.get(normalized, TIER_META["off"]))
    if normalized == "full3652":
        cfg["cdx"] = _cdx_ranked_count()
        count = cfg["cdx"]
        cfg["label"] = f"Максимум · все dorks ({count})"
    return cfg


def tier_label(tier: str) -> str:
    return tier_config(tier)["label"]


def _dork_key(d: DorkDef) -> str:
    return d.cdx_filter or d.path or d.cc_suffix or d.id


def _score_dork(d: DorkDef) -> tuple:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    lower = d.title.lower()
    bonus = sum(-2 for term in _PRIORITY_TERMS if term in lower)
    cat_rank = {
        "secrets": 0,
        "vcs": 1,
        "config": 2,
        "backup": 3,
        "cloud": 4,
        "disclosure": 5,
        "api": 6,
        "panels": 7,
        "logs": 8,
        "install": 9,
        "recon": 10,
        "misc": 11,
    }
    has_cdx = 0 if d.cdx_filter else 1
    return (rank.get(d.severity, 9), has_cdx, cat_rank.get(d.category, 12), bonus, d.id)


def ranked_merged_library() -> tuple[DorkDef, ...]:
    google, _ = load_google_dorks()
    google.sort(key=_score_dork)

    seen: set[str] = set()
    out: list[DorkDef] = []
    for item in (*BUILTIN_DORK_LIBRARY, *EXTRA_CURATED, *google):
        key = _dork_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return tuple(out)


def get_library_for_tier(tier: str) -> tuple[DorkDef, ...]:
    normalized = normalize_dork_tier(tier)
    if normalized == "off":
        return ()
    lib = ranked_merged_library()
    cdx_items = [d for d in lib if d.cdx_filter]
    if normalized == "full3652":
        return tuple(cdx_items)
    limit = int(tier_config(normalized)["cdx"])
    if limit <= 0:
        return ()
    return tuple(cdx_items[:limit])


def dork_tier_stats() -> dict:
    lib = ranked_merged_library()
    cdx_count = len([d for d in lib if d.cdx_filter])
    return {
        "curated_builtin": len(BUILTIN_DORK_LIBRARY),
        "curated_extra": len(EXTRA_CURATED),
        "ranked_total": len(lib),
        "cdx_ranked": cdx_count,
        "tiers": {k: v["cdx"] for k, v in TIER_META.items() if k != "off"},
    }
