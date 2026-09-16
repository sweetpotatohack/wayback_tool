from __future__ import annotations

import math
import re
from collections import Counter

from app.services.evidence_fmt import format_evidence
from app.services.secrets import SecretHit
from app.services.wayback import store_secret

# LinkFinder-style endpoint harvest from archived JS (public patterns).
_LINKFINDER = re.compile(
    r"""(?i)(?:
        (?:href|src|action|data-url|data-api)\s*=\s*["']([^"']{4,220})["']
        |
        ["']((?:https?:)?//[^"' ]{6,220})["']
        |
        ["'](/[a-z0-9_\-./]{4,180}\.(?:php|json|xml|asp|aspx|jsp|env|bak|sql))["']
        |
        ["'](/(?:api|v[12]|admin|internal|private|graphql|rest)[^"' ]{0,180})["']
        |
        (?:fetch|axios|ajax|\.get|\.post|\.put)\(\s*["']([^"']{6,220})["']
    )""",
    re.X,
)

_QUOTED = re.compile(r"""(['"])([A-Za-z0-9_\-+/=.]{16,80})\1""")
_NEAR_SECRET = re.compile(
    r"(?i)(?:[:=]\s*['\"][^'\"]{8,}['\"]|"
    r"(?:api[_-]?key|apikey|secret|token|password|passwd|auth|credential|access[_-]?key|private[_-]?key)\s*[:=]\s*['\"])"
)

# Known JS/framework noise (React, Bootstrap, password-generator widgets, etc.)
_JUNK_VALUES = frozenset(
    {
        "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    }
)

_JS_IDENTIFIER = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$")
_EVENT_OR_PLUGIN = re.compile(
    r"(?i)(?:\.bs\.|\.data-api|keydown|keyup|click\.|submit\.|change\.|"
    r"generatePassword|PasswordClipboard|PasswordApply|PASSWORD_CONFIRM|"
    r"JS_CORE_|JS_PASSWORD_|webpack|chunk|polyfill|prototype)"
)
_CHARSET_ALPHabet = re.compile(
    r"^(?:abcdefghijklmnopqrstuvwxyz|ABCDEFGHIJKLMNOPQRSTUVWXYZ|0123456789){8,}$",
    re.I,
)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_secret_material(value: str) -> bool:
    """Reject identifiers/constants; keep base64-ish and high-entropy blobs."""
    if value in _JUNK_VALUES:
        return False
    if _CHARSET_ALPHabet.match(value):
        return False
    if _EVENT_OR_PLUGIN.search(value):
        return False
    if value.isupper() and "_" in value and not re.search(r"\d", value):
        return False
    if _JS_IDENTIFIER.match(value) and not re.search(r"\d", value):
        if value[0].islower() or (value[0].isupper() and any(c.islower() for c in value[1:])):
            return False
    if re.fullmatch(r"[a-f0-9]{32,}", value, re.I):
        return True
    if len(value) >= 24 and re.search(r"[A-Za-z]", value) and re.search(r"\d", value):
        if _entropy(value) >= 4.0:
            return True
    if len(value) >= 32 and _entropy(value) >= 3.8:
        if re.search(r"[+/=]", value) or (re.search(r"[a-z]", value) and re.search(r"[A-Z]", value)):
            return True
    return False


def extract_js_endpoints(text: str, limit: int = 40) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in _LINKFINDER.finditer(text or ""):
        val = next((g for g in match.groups() if g), "")
        val = val.strip()
        if not val or val in seen or val.startswith("data:") or val.startswith("mailto:"):
            continue
        if any(x in val.lower() for x in (".png", ".jpg", ".css", ".woff", ".svg", "google-analytics", "gstatic")):
            continue
        seen.add(val)
        found.append(val)
        if len(found) >= limit:
            break
    return found


def scan_js_secrets(text: str, max_hits: int = 8, *, source_url: str = "") -> list[SecretHit]:
    hits: list[SecretHit] = []
    if not text:
        return hits
    window = 70
    for match in _QUOTED.finditer(text[:400000]):
        value = match.group(2)
        if value.startswith("/") and any(
            value.lower().endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".ico")
        ):
            continue
        if not _looks_like_secret_material(value):
            continue
        if _entropy(value) < 3.8:
            continue
        start = max(0, match.start() - window)
        ctx = text[start : match.end() + 20]
        if not _NEAR_SECRET.search(ctx):
            continue
        if re.search(r"(?i)(background|url\(|/images/|\.png|\.jpg|webpack|chunk)", ctx) and len(value) < 28:
            continue
        evidence = (
            format_evidence(source_url, text, match.start(), match.end())
            if source_url
            else re.sub(r"\s+", " ", ctx)[:240]
        )
        hits.append(
            SecretHit(
                name="Высокая энтропия рядом с key/token",
                severity="medium",
                masked=store_secret(value),
                evidence=evidence,
                pattern="js-entropy",
            )
        )
        if len(hits) >= max_hits:
            break
    return hits
