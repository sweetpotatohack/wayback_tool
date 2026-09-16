from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse

from app.services.wayback import normalize_target

_SPA_SHELL = re.compile(r"(?i)(<div id=[\"']root[\"']|<app-root|webpack|react|__NEXT_DATA__)")
_AUTH_PATH = re.compile(r"(?i)(/sign-in|/signin|/login|/auth|/account/login|/wp-login)")
_WAYBACK_MISS = re.compile(
    r"(?i)(the wayback machine has not archived that url|page is unavailable for archiving|"
    r"this url has been excluded from the wayback machine)"
)
_NOISE = re.compile(r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>|<!--.*?-->")
_WS = re.compile(r"\s+")


def normalize_body(text: str, *, limit: int = 48000) -> str:
    blob = (text or "")[:limit]
    blob = _NOISE.sub(" ", blob)
    blob = _WS.sub(" ", blob).strip().lower()
    return blob


def body_fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_body(text).encode("utf-8", errors="ignore")).hexdigest()[:20]


def bodies_match(a: str, b: str) -> bool:
    if not a.strip() or not b.strip():
        return False
    return body_fingerprint(a) == body_fingerprint(b)


def is_wayback_miss_page(text: str) -> bool:
    head = (text or "")[:12000]
    return bool(_WAYBACK_MISS.search(head))


def is_auth_redirect(requested_url: str, final_url: str) -> bool:
    req_path = urlparse(requested_url.split(" → ")[0]).path or "/"
    fin_path = urlparse(final_url.split(" → ")[0]).path or "/"
    if req_path.rstrip("/").lower() == fin_path.rstrip("/").lower():
        return False
    if _AUTH_PATH.search(fin_path):
        return True
    req_name = req_path.rstrip("/").split("/")[-1].lower()
    if req_name.startswith(".") or req_name.endswith((".env", ".sql", ".json", ".php", ".bak")):
        if fin_path.rstrip("/").lower() in {"/", ""}:
            return True
    return False


def confirm_live_path_finding(
    url: str,
    text: str,
    content_type: str,
    pattern: str,
    *,
    homepage_text: str = "",
    requested_url: str = "",
) -> tuple[bool, str]:
    """Reject SPA shells and pages identical to the site homepage (soft-404)."""
    from app.services.live_probe import _looks_like_html, _validate_path

    req = requested_url or url
    final = url

    if is_auth_redirect(req, final):
        return False, "редirect на авторизацию / главную"

    if homepage_text and bodies_match(text, homepage_text):
        return False, "тот же ответ что главная (soft-404)"

    if " → " in url:
        if text.lstrip().startswith("{") and "result" in text[:800]:
            return True, "JSON-RPC result"
        return bool(text.strip()), "API body"

    path = urlparse(req).path or ""
    path_low = path.lower()
    ctype = (content_type or "").lower()

    if "json" in ctype and text.lstrip().startswith("{"):
        if homepage_text and bodies_match(text, homepage_text):
            return False, "JSON совпадает с главной"
        return True, "JSON body"

    if path_low.endswith((".js", ".mjs")):
        return len(text) > 40 and not _looks_like_html(text), "JavaScript bundle"

    ok, reason = _validate_path(path, text, secret_hits=[])
    if ok:
        return True, reason

    if _looks_like_html(text):
        if _SPA_SHELL.search(text[:4000]):
            return False, "SPA index (не файл)"
        if any(
            tok in path_low
            for tok in (
                ".env",
                ".git",
                "config",
                "graphql",
                "wp-config",
                "phpinfo",
                "backup",
                ".sql",
                "adminer",
                ".htpasswd",
            )
        ):
            return False, "HTML вместо файла (SPA)"
    return False, reason or "нет подтверждения содержимого"


def host_key(url: str) -> str:
    netloc = urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return normalize_target(netloc) or netloc
