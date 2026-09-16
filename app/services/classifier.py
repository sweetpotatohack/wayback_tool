from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse

from app.services.pentest_intel import classify_auth_url

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

MEDIA_EXT = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".bmp",
    ".tif",
    ".tiff",
    ".mp4",
    ".webm",
    ".mp3",
    ".wav",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".css",
    ".map",
}

OFFICE_NOISE_EXT = {".pdf", ".doc", ".docx", ".ppt", ".pptx"}

SENSITIVE_EXT = {
    ".env",
    ".bak",
    ".old",
    ".orig",
    ".save",
    ".sql",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".json",
    ".yml",
    ".yaml",
    ".xml",
    ".conf",
    ".cfg",
    ".ini",
    ".inc",
    ".log",
    ".txt",
    ".csv",
    ".php",
    ".py",
    ".rb",
    ".java",
    ".properties",
    ".dist",
    ".swp",
    ".tpl",
    ".aspx",
    ".asp",
    ".jsp",
    ".sh",
    ".bat",
    ".ps1",
    ".kdbx",
    ".ovpn",
    ".rdp",
}

NOISE_DIRS = {
    "presscenter",
    "press-center",
    "news",
    "blog",
    "media",
    "passengers",
    "disclosure",
    "tourism",
    "gallery",
    "photo",
    "photos",
    "slider",
    "banner",
    "banners",
    "static",
    "assets",
    "images",
    "img",
    "css",
    "fonts",
}

STRONG_STEMS = {
    "password",
    "passwords",
    "passwd",
    "credentials",
    "secret",
    "secrets",
    "users",
    "logins",
}

# Whole tokens in a file name — not substrings of "authority", "secretion", etc.
KEYWORD_RE = re.compile(
    r"(?i)(?<![a-z0-9])("
    r"passwords?|passwd|pwd|passlist|"
    r"secrets?|credentials?|tokens?|"
    r"apikey|api[_-]?keys?|access[_-]?tokens?|private[_-]?keys?|"
    r"htpasswd|dbpasswd|db_password"
    r")(?![a-z0-9])"
)

LLM_EXTRACT_EXT = {
    ".env",
    ".php",
    ".inc",
    ".ini",
    ".conf",
    ".cfg",
    ".yml",
    ".yaml",
    ".xml",
    ".sql",
    ".txt",
    ".csv",
    ".bak",
    ".old",
    ".properties",
    ".asp",
    ".aspx",
    ".json",
    ".sh",
    ".log",
    ".dist",
    ".tpl",
}


@dataclass(frozen=True)
class UrlClass:
    severity: str
    category: str
    title: str
    pattern: str


RULES: list[tuple[re.Pattern[str], UrlClass]] = [
    (re.compile(r"(?i)(^|/)(\.env)(\.|$|/)|/\.env"), UrlClass("critical", "env", "Файл окружения (.env)", "env")),
    (re.compile(r"(?i)/\.git/(config|HEAD|credentials|index)"), UrlClass("critical", "git", "Служебные файлы Git", "git")),
    (re.compile(r"(?i)(^|/)(id_rsa|id_dsa|id_ed25519|id_ecdsa)(\.pub)?$"), UrlClass("critical", "key", "Приватный SSH-ключ", "ssh")),
    (re.compile(r"(?i)\.(pem|p12|pfx|kdbx)$"), UrlClass("critical", "key", "Ключ / сертификат / KeePass", "keyfile")),
    (
        re.compile(
            r"(?i)(wp-config\.php|settings\.php|local_settings\.py|application(-?\w+)?\.yml|"
            r"config\.inc\.php|config\.inc|dbconn\.php|\.settings\.php|LocalConfiguration\.php)"
        ),
        UrlClass("critical", "config", "Конфиг приложения", "app-config"),
    ),
    (
        re.compile(r"(?i)(credentials|secrets?|service[-_]?account|firebase|google[-_]?services).*\.(json|xml|yml|yaml)$"),
        UrlClass("critical", "secrets-file", "Файл с учётными данными", "creds-file"),
    ),
    (
        re.compile(
            r"(?i)(^|/)(passwords?|passwd|passlist|pass|credentials?|logins?|users?|htpasswd|secret)\."
            r"(txt|csv|xls|xlsx|sql|bak|old|json|xml|log|ini)(\?|$)"
        ),
        UrlClass("high", "secrets-file", "Файл паролей / учёток", "pass-file"),
    ),
    (re.compile(r"(?i)/\.htpasswd$"), UrlClass("critical", "auth", ".htpasswd", "htpasswd")),
    (re.compile(r"(?i)/\.htaccess$"), UrlClass("medium", "auth", ".htaccess", "htaccess")),
    (
        re.compile(r"(?i)(\.aws/credentials|/\.netrc|/\.npmrc|/\.pypirc|/\.dockercfg|/\.docker/config\.json)"),
        UrlClass("critical", "dotfile", "Файл учётных данных CLI", "dot-creds"),
    ),
    (
        re.compile(r"(?i)(dump|backup|db|database|site|www|public_html).*\.(sql|zip|tar\.gz|tgz|rar|7z)$"),
        UrlClass("high", "backup", "Бэкап / дамп", "backup"),
    ),
    (re.compile(r"(?i)\.(sql|bak|old|orig|save|swp|tmp|dist)$"), UrlClass("high", "backup", "Резервная / временная копия", "stale")),
    (
        re.compile(
            r"(?i)(^|/)(configs?|configuration|local_settings)"
            r"(\.(php|inc|json|ya?ml|xml|ini|conf|cfg|bak|old|dist)|/?$)"
        ),
        UrlClass("medium", "config", "config / configs", "config-path"),
    ),
    (
        re.compile(r"(?i)(^|/)parameters\.(ya?ml|yml|php|xml|ini|env)(\?|$)"),
        UrlClass("high", "config", "Symfony parameters", "parameters-file"),
    ),
    (
        re.compile(r"(?i)(config|settings|secrets?)\.(json|ya?ml|xml|ini|conf|cfg|php)$"),
        UrlClass("medium", "config", "Именованный конфиг", "named-config"),
    ),
    (
        re.compile(r"(?i)(web\.config|appsettings(\.[A-Za-z]+)?\.json|docker-compose.*\.ya?ml|\.kdbx$|\.ovpn$)"),
        UrlClass("high", "config", "Серверный конфиг", "server-config"),
    ),
    (
        re.compile(r"(?i)(^|/)(backup|backups|dump|dumps|private|db_backup|old|temp|tmp)(/|$)"),
        UrlClass("low", "recon", "Каталог бэкапов / private", "backup-dir"),
    ),
    (re.compile(r"(?i)(phpinfo|info\.php|test\.php|debug\.php|allinfo\.php)"), UrlClass("high", "disclosure", "phpinfo / debug PHP", "phpinfo")),
    (re.compile(r"(?i)(server-status|server-info)"), UrlClass("high", "disclosure", "Apache server-status", "server-status"),),
    (re.compile(r"(?i)\.DS_Store$"), UrlClass("medium", "disclosure", ".DS_Store", "dsstore")),
    (re.compile(r"(?i)/\.svn/"), UrlClass("high", "vcs", "SVN metadata", "svn")),
    (re.compile(r"(?i)/(crossdomain\.xml|clientaccesspolicy\.xml)$"), UrlClass("medium", "recon", "Cross-domain policy", "crossdomain")),
    (re.compile(r"(?i)(swagger|openapi).*\.(json|ya?ml)$|/swagger"), UrlClass("medium", "api", "OpenAPI / Swagger", "openapi")),
    (re.compile(r"(?i)(graphql|graphiql)"), UrlClass("medium", "api", "GraphQL endpoint", "graphql")),
    (re.compile(r"(?i)/(phpmyadmin|pma|adminer|wp-admin|administrator|manager)(/|$)"), UrlClass("low", "recon", "Админ-панель в архиве", "admin")),
    (re.compile(r"(?i)(bitrix/php_interface/dbconn|bitrix/\.settings|bitrix/backup)"), UrlClass("high", "config", "Bitrix dbconn / settings", "bitrix")),
    (re.compile(r"(?i)(debug\.log|error_log|\.log)$"), UrlClass("medium", "log", "Лог-файл", "log")),
    (re.compile(r"(?i)(^|/)auth(entication)?\.(php|js|json|aspx|asp)$"), UrlClass("low", "recon", "Файл auth", "auth-file")),
    (re.compile(r"(?i)robots\.txt$"), UrlClass("info", "recon", "robots.txt", "robots")),
    (re.compile(r"(?i)sitemap.*\.xml$"), UrlClass("info", "recon", "sitemap.xml", "sitemap")),
]


def _parts(url: str) -> tuple[str, str, str, str]:
    parsed = urlparse(unquote(url))
    path = parsed.path or ""
    name = PurePosixPath(path.rstrip("/")).name.lower()
    ext = PurePosixPath(name).suffix.lower()
    stem = PurePosixPath(name).stem.lower()
    return path, name, ext, stem


def canonical_url(url: str) -> str:
    parsed = urlparse(unquote((url or "").strip()))
    host = (parsed.netloc or "").lower().split("@")[-1]
    if host.startswith("www."):
        host = host[4:]
    if host.endswith(":80"):
        host = host[:-3]
    elif host.endswith(":443"):
        host = host[:-4]
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    return f"{host}{path.lower()}"


def is_marketing_path(url: str) -> bool:
    path, name, ext, stem = _parts(url)
    if ext in MEDIA_EXT:
        return True
    if ext in OFFICE_NOISE_EXT and stem not in STRONG_STEMS:
        return True
    parts = [p.lower() for p in unquote(path).split("/") if p and p.lower() not in {"en", "ru", "www"}]
    if "parameters" in parts and ext not in SENSITIVE_EXT:
        return True
    if any(p in NOISE_DIRS for p in parts) and ext not in SENSITIVE_EXT and name not in {".env", "robots.txt"}:
        return True
    return False


def classify_url(
    url: str,
    extra_keywords: list[str] | None = None,
    extra_exts: list[str] | None = None,
) -> UrlClass | None:
    path, name, ext, stem = _parts(url)
    haystack = url
    extras = [e.lower().lstrip(".") for e in (extra_exts or []) if e.strip()]
    extra_ext_set = {"." + e if not e.startswith(".") else e for e in extras}

    if ext in MEDIA_EXT:
        return None

    auth = classify_auth_url(url)
    if auth and not (auth.pattern == "auth-admin-entry" and is_marketing_path(url)):
        return UrlClass(auth.severity, auth.category, auth.title, auth.pattern)

    for regex, klass in RULES:
        if not (regex.search(haystack) or regex.search(path)):
            continue
        if klass.pattern in {"config-path", "named-config", "kw-path", "backup-dir", "auth-file"} and is_marketing_path(url):
            continue
        return klass

    if ext in extra_ext_set:
        return UrlClass("high", "custom-ext", f"Расширение из настроек ({ext})", "custom-ext")

    if ext == ".key" and "public" not in name:
        return UrlClass("critical", "key", "Ключевой файл (.key)", "keyfile")

    keywords = list(extra_keywords or [])
    filename_kw = KEYWORD_RE.search(name)
    path_kw = KEYWORD_RE.search(path)
    extra_hit = None
    for word in keywords:
        token = word.strip()
        if len(token) < 3:
            continue
        bound = re.compile(rf"(?i)(?<![a-z0-9._-]){re.escape(token)}(?![a-z0-9._-])")
        if bound.search(name) or bound.search(path):
            extra_hit = token
            break

    is_dir = path.endswith("/")
    if filename_kw and ext not in MEDIA_EXT:
        if is_marketing_path(url) and (is_dir or ext in OFFICE_NOISE_EXT):
            filename_kw = None
        elif ext in OFFICE_NOISE_EXT and stem not in STRONG_STEMS:
            filename_kw = None

    if filename_kw and ext not in MEDIA_EXT:
        if ext in SENSITIVE_EXT or ext in extra_ext_set or ext in {".php", ".json", ".txt", ".xml", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".csv"}:
            return UrlClass("high", "keyword", f"Имя файла: {filename_kw.group(1)}", "kw-file")
        if is_dir or not ext:
            return UrlClass("info", "keyword", f"Каталог с ключевым словом ({filename_kw.group(1)})", "kw-path")
        return UrlClass("medium", "keyword", f"Ключевое слово в имени файла ({filename_kw.group(1)})", "kw-file")

    if extra_hit and ext not in MEDIA_EXT and ext not in OFFICE_NOISE_EXT:
        if extra_hit.lower() in name.lower() and (ext in SENSITIVE_EXT or ext in extra_ext_set or not ext):
            return UrlClass("high", "custom-kw", f"Ключ из настроек в имени: {extra_hit}", "custom-kw")
        if extra_hit.lower() in path.lower():
            return UrlClass("low", "custom-kw", f"Ключ из настроек в пути: {extra_hit}", "custom-kw")

    if path_kw and (ext in MEDIA_EXT or ext in OFFICE_NOISE_EXT):
        return None
    if path_kw and ext not in MEDIA_EXT:
        if is_marketing_path(url):
            return None
        return UrlClass("info", "keyword", f"Ключевое слово в пути ({path_kw.group(1)})", "kw-path")

    return None


def is_script_or_data(url: str, mimetype: str = "") -> bool:
    _, _, ext, _ = _parts(url)
    mime = (mimetype or "").lower()
    if ext in {".js", ".mjs", ".json", ".xml", ".map", ".txt", ".csv"}:
        return True
    return any(
        token in mime
        for token in (
            "javascript",
            "json",
            "xml",
            "yaml",
            "x-sh",
            "x-www-form-urlencoded",
        )
    )


def worth_llm_extract(url: str, mimetype: str = "") -> bool:
    """Second pass over anything we already decided to download."""
    _, _, ext, _ = _parts(url)
    if ext in MEDIA_EXT or ext in {".css", ".map", ".woff", ".woff2", ".ttf"}:
        return False
    return True


def is_interesting(url: str) -> bool:
    return classify_url(url) is not None
