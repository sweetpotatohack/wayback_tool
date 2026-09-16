from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.evidence_fmt import format_evidence
from app.services.wayback import store_secret

# Signature-based scanning of publicly archived text. Patterns follow common
# defensive scanners (gitleaks-style) and are used only against Wayback snapshots.


@dataclass(frozen=True)
class SecretHit:
    name: str
    severity: str
    masked: str
    evidence: str
    pattern: str


def _clip(text: str, start: int, end: int, radius: int = 80) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    snippet = text[a:b].replace("\n", " ")
    return snippet[:240]


PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("AWS Access Key", "critical", "aws-akid", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub PAT", "critical", "github-pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub Fine-grained PAT", "critical", "github-fg", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("GitHub App token", "critical", "github-app", re.compile(r"(gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}")),
    ("GitLab PAT", "critical", "gitlab", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")),
    ("Slack token", "critical", "slack", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("Slack webhook", "high", "slack-hook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("Stripe live key", "critical", "stripe", re.compile(r"sk_live_[0-9a-zA-Z]{16,}")),
    ("Google API key", "high", "google-api", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("SendGrid", "high", "sendgrid", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
    ("Twilio SID", "medium", "twilio", re.compile(r"AC[0-9a-fA-F]{32}")),
    ("Private key block", "critical", "privkey", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", "medium", "jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("npm token", "high", "npm", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("PyPI token", "high", "pypi", re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{20,}")),
    ("Telegram bot token", "high", "tg-bot", re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}")),
    ("OpenAI key", "critical", "openai", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{32,}")),
    ("Heroku API key", "high", "heroku", re.compile(r"(?i)heroku.{0,20}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")),
    ("Azure storage key", "critical", "azure", re.compile(r"(?i)AccountKey=([A-Za-z0-9+/=]{40,})")),
    ("Mailchimp", "high", "mailchimp", re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}")),
    ("Password assignment", "high", "passwd-assign", re.compile(r"""(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]{6,}['"]""")),
    ("PHP password assign", "high", "php-pass", re.compile(r"""(?i)\$(?:db)?_?(?:password|passwd|pwd|pass)\s*=\s*['"][^'"]{3,}['"]""")),
    ("PHP define password", "high", "php-define", re.compile(r"""(?i)define\s*\(\s*['"][A-Z0-9_]*PASSWORD[A-Z0-9_]*['"]\s*,\s*['"][^'"]{3,}['"]""")),
    ("Bitrix DBPassword", "critical", "bitrix-db", re.compile(r"""(?i)\$(?:DBPassword|DBLogin|DBName)\s*=\s*['"][^'"]{2,}['"]""")),
    ("Env-style secret", "high", "env-assign", re.compile(r"(?i)(?:DB_|MYSQL_|POSTGRES_|REDIS_|MAIL_|SMTP_|AWS_|SECRET_)[A-Z0-9_]*(PASSWORD|PWD|SECRET|KEY|TOKEN)\s*=\s*\S{4,}")),
    ("DB connection string", "critical", "dburi", re.compile(r"(?i)(mysql|postgres|postgresql|mongodb|redis|amqp|mssql)://[^\s'\"<>]+")),
    ("Generic bearer", "medium", "bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Mailgun key", "high", "mailgun", re.compile(r"key-[0-9a-f]{32}")),
    ("Twilio auth token", "high", "twilio-auth", re.compile(r"(?i)twilio.{0,24}[0-9a-f]{32}")),
    ("Firebase URL", "medium", "firebase", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    ("AWS secret assign", "critical", "aws-secret", re.compile(r"""(?i)aws.{0,12}secret.{0,12}['"][A-Za-z0-9/+=]{40}['"]""")),
    ("Authorization Basic", "high", "basic-hdr", re.compile(r"(?i)authorization['\"\s:=]+basic\s+[A-Za-z0-9+/=]{12,}")),
    ("Hardcoded apiKey", "high", "apikey-assign", re.compile(r"""(?i)(['"]?api[_-]?key['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{12,}['"])""")),
]


def scan_text(text: str, max_hits: int = 40, *, source_url: str = "") -> list[SecretHit]:
    hits: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    for name, severity, key, regex in PATTERNS:
        for match in regex.finditer(text):
            raw = match.group(0)
            fingerprint = (key, raw[:80])
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            evidence = (
                format_evidence(source_url, text, match.start(), match.end())
                if source_url
                else _clip(text, match.start(), match.end())
            )
            hits.append(
                SecretHit(
                    name=name,
                    severity=severity,
                    masked=store_secret(raw),
                    evidence=evidence,
                    pattern=key,
                )
            )
            if len(hits) >= max_hits:
                return hits
    from app.services.js_intel import scan_js_secrets

    for hit in scan_js_secrets(text, source_url=source_url):
        fingerprint = (hit.pattern, hit.masked[:80])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        hits.append(hit)
        if len(hits) >= max_hits:
            return hits
    for hit in parse_phpinfo(text):
        fingerprint = (hit.pattern, hit.masked[:80])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        hits.append(hit)
        if len(hits) >= max_hits:
            break
    return hits


_PHPINFO_ROW = re.compile(
    r'<td class="e">\s*(.*?)\s*</td>\s*<td class="v">\s*(.*?)\s*</td>',
    re.I | re.S,
)
_PHPINFO_KEY = re.compile(
    r"(?i)(DOCUMENT_ROOT|SCRIPT_FILENAME|SERVER_ADMIN|HOSTNAME|SERVER_SOFTWARE|"
    r"Loaded Configuration File|extension_dir|HTTP_AUTHORIZATION|"
    r"PASSWORD|SECRET|AUTH|DATABASE|MYSQL|POSTGRES|_ENV|_SERVER)"
)


def parse_phpinfo(text: str) -> list[SecretHit]:
    sample = text[:2000]
    if "phpinfo()" not in sample and "PHP Version" not in sample and 'class="e"' not in sample:
        return []
    hits: list[SecretHit] = []
    for raw_key, raw_val in _PHPINFO_ROW.findall(text[:400000]):
        key = re.sub(r"<[^>]+>", "", raw_key).strip()
        val = re.sub(r"<[^>]+>", "", raw_val).replace("&nbsp;", " ").strip()
        if not key or not val or val.lower() in {"no value", "none", ""}:
            continue
        if not _PHPINFO_KEY.search(key):
            continue
        if re.search(r"(?i)password|secret|authorization|credential", key):
            sev = "critical"
        elif re.search(r"(?i)DOCUMENT_ROOT|SCRIPT_FILENAME|SERVER_ADMIN|Loaded Configuration", key):
            sev = "high"
        else:
            sev = "medium"
        hits.append(
            SecretHit(
                name=f"phpinfo: {key[:80]}",
                severity=sev,
                masked=store_secret(val),
                evidence=f"{key}={val[:180]}",
                pattern="phpinfo-key",
            )
        )
        if len(hits) >= 20:
            break
    return hits
