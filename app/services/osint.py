from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from app.services.evidence_fmt import format_evidence
from app.services.wayback import store_secret

_EMAIL = re.compile(
    r"(?<![\w.@])"
    r"([a-z0-9][a-z0-9._%+\-]{0,63}@"
    r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)"
    r"(?![\w.])",
    re.I,
)
_MAILTO = re.compile(r"(?i)mailto:([^\s\"'<>?#]+)")
_TEL_HREF = re.compile(r"(?i)tel:([+\d][\d\s\-().]{6,22})")
_RU_MOBILE = re.compile(
    r"(?<!\d)(?:\+7|7|8)[\s\-]?(?:\(?9\d{2}\)?[\s\-]?)\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)"
)
_RU_LAND = re.compile(
    r"(?<!\d)(?:\+7|8)[\s\-]?\(?[34789]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)"
)
_INTL_PLUS = re.compile(r"(?<!\d)\+\d{10,15}(?!\d)")
_PHONE_LABEL = re.compile(
    r"(?i)(?:phone|tel(?:efon)?|mobile|моб(?:ильный)?|тел(?:ефон)?|факс|fax)"
    r"[\s:=\"']{0,6}([+\d][\d\s\-().]{8,22})"
)

_JUNK_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "domain.com",
    "email.com",
    "localhost",
    "yourdomain.com",
    "yoursite.com",
    "sentry.io",
    "w3.org",
    "schema.org",
    "webpack.js",
    "reactjs.org",
    "googleapis.com",
    "gstatic.com",
    "cloudflare.com",
    "github.com",
    "npmjs.org",
    "placeholder.com",
    "placehold.co",
    "2x.png",
    "3x.png",
}
_JUNK_LOCALS = {
    "noreply",
    "no-reply",
    "donotreply",
    "mailer-daemon",
    "postmaster",
    "example",
    "test",
    "username",
    "your.email",
    "user@",
}

# Placeholder / widget / hash-constant phones seen in archived HTML/JS
_JUNK_PHONE_DIGITS = frozenset(
    {
        "79999999999",
        "89999999999",
        "9999999999",
        "9000000000",
        "8000000000",
        "1234567890",
        "0123456789",
        "2654435769",  # common JS hash constant
        "3864292196",  # MurmurHash / swagger-ui constant
        "2147483647",
        "4294967295",
    }
)


@dataclass(frozen=True)
class OsintHit:
    kind: str
    value: str
    severity: str
    evidence: str
    pattern: str

    @property
    def stored_value(self) -> str:
        return store_secret(self.value)


def _email_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower().strip(".")


def _email_on_scope(domain: str, scope_hosts: list[str]) -> bool:
    if not scope_hosts:
        return False
    for host in scope_hosts:
        h = host.lower().strip(".")
        if not h:
            continue
        if domain == h or domain.endswith("." + h):
            return True
        parts = h.split(".")
        if len(parts) >= 2 and domain == ".".join(parts[-2:]):
            return True
    return False


def _valid_email(email: str) -> bool:
    email = email.strip().lower().strip(".")
    if "@" not in email or len(email) < 6 or len(email) > 254:
        return False
    local, domain = email.rsplit("@", 1)
    if not local or not domain or ".." in email:
        return False
    if any(domain.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".js", ".css", ".webp")):
        return False
    if domain in _JUNK_EMAIL_DOMAINS:
        return False
    if local in _JUNK_LOCALS or any(local.startswith(p) for p in _JUNK_LOCALS):
        return False
    if re.fullmatch(r"[a-f0-9\-]{24,}", local):
        return False
    if re.search(r"(?i)(webpack|chunk|sentry|analytics|fontawesome)", email):
        return False
    return True


def _normalize_phone(raw: str) -> str | None:
    raw = raw.strip().strip(".,;)")
    if not raw:
        return None
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 10 or len(digits) > 15:
        return None
    if len(set(digits)) == 1:
        return None
    if digits in _JUNK_PHONE_DIGITS:
        return None
    if digits.endswith("999999999") or digits.endswith("99999999"):
        return None
    if re.fullmatch(r"9{10,}", digits) or re.fullmatch(r"0{10,}", digits):
        return None
    if digits.startswith("20") and len(digits) >= 12:
        return None
    if digits.startswith(("000", "111111", "123456789")):
        return None
    if raw.startswith("+") or raw.startswith("8") or raw.startswith("7") or len(digits) >= 11:
        return raw[:40]
    if re.search(r"(?i)(phone|tel|факс|моб)", raw):
        return raw[:40]
    return None


def _scan_emails(text: str, *, source_url: str, scope_hosts: list[str]) -> list[OsintHit]:
    hits: list[OsintHit] = []
    seen: set[str] = set()
    sources: list[tuple[str, int, int]] = []
    for match in _EMAIL.finditer(text[:800000]):
        sources.append((match.group(1), match.start(1), match.end(1)))
    for match in _MAILTO.finditer(text[:800000]):
        addr = unquote(match.group(1).split("?")[0].strip())
        if addr:
            idx = match.start(1)
            sources.append((addr, idx, idx + len(addr)))
    for email_raw, start, end in sources:
        email = email_raw.strip().lower().strip(".")
        if not _valid_email(email) or email in seen:
            continue
        seen.add(email)
        domain = _email_domain(email)
        on_scope = _email_on_scope(domain, scope_hosts)
        severity = "medium" if on_scope else "info"
        evidence = (
            format_evidence(source_url, text, start, end)
            if source_url
            else email
        )
        hits.append(
            OsintHit(
                kind="email",
                value=email,
                severity=severity,
                evidence=evidence,
                pattern="osint-email-scope" if on_scope else "osint-email",
            )
        )
    return hits


def _phone_in_code_context(text: str, start: int, end: int) -> bool:
    ctx = text[max(0, start - 24) : min(len(text), end + 24)]
    if re.search(r"\|\s*0\)|<<|>>>|\^|&\s*\d", ctx):
        return True
    if re.search(r"(?i)\.(?:js|mjs|bundle|min)(?:[?:]|$)", ctx):
        return True
    return False


def _scan_phones(text: str, *, source_url: str) -> list[OsintHit]:
    hits: list[OsintHit] = []
    seen: set[str] = set()
    # tel: / RU formats only — bare +NNN in minified JS is almost always arithmetic
    patterns = (_TEL_HREF, _RU_MOBILE, _RU_LAND, _PHONE_LABEL)
    for regex in patterns:
        for match in regex.finditer(text[:800000]):
            raw = match.group(1) if regex is _TEL_HREF or regex is _PHONE_LABEL else match.group(0)
            start = match.start(1 if regex in {_TEL_HREF, _PHONE_LABEL} else 0)
            end = match.end(1 if regex in {_TEL_HREF, _PHONE_LABEL} else 0)
            if regex not in {_TEL_HREF} and _phone_in_code_context(text, start, end):
                continue
            if source_url and re.search(r"\.(?:js|mjs|css)(?:\?|$)", source_url, re.I):
                if regex not in {_TEL_HREF}:
                    continue
            phone = _normalize_phone(raw)
            if not phone:
                continue
            key = re.sub(r"\D", "", phone)
            if key in seen:
                continue
            seen.add(key)
            evidence = (
                format_evidence(source_url, text, start, end)
                if source_url
                else phone
            )
            hits.append(
                OsintHit(
                    kind="phone",
                    value=phone,
                    severity="low",
                    evidence=evidence,
                    pattern="osint-phone",
                )
            )
    return hits


def scan_osint(
    text: str,
    *,
    source_url: str = "",
    scope_hosts: list[str] | None = None,
    max_hits: int = 30,
    emails: bool = True,
    phones: bool = True,
) -> list[OsintHit]:
    if not text or len(text.strip()) < 4:
        return []
    scope = [h.lower() for h in (scope_hosts or []) if h]
    out: list[OsintHit] = []
    if emails:
        out.extend(_scan_emails(text, source_url=source_url, scope_hosts=scope))
    if phones:
        out.extend(_scan_phones(text, source_url=source_url))
    if len(out) > max_hits:
        out.sort(key=lambda h: {"medium": 0, "low": 1, "info": 2}.get(h.severity, 3))
        out = out[:max_hits]
    return out


def osint_title(hit: OsintHit) -> str:
    if hit.kind == "email":
        return f"Email: {hit.value}"
    return f"Телефон: {hit.value}"
