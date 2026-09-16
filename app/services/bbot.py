"""BBOT (Black Lantern) OSINT integration — subprocess runner and result parser."""

from __future__ import annotations

import asyncio
import csv
import json
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from app import DATA_DIR
from app.config import get_settings
from app.services.pentest_intel import (
    classify_auth_url,
    classify_bbot_finding,
    classify_mail_technology,
    classify_open_port,
)
from app.services.wayback import normalize_target

BBOT_ROOT = DATA_DIR / "bbot"

DEFAULT_FLAGS = (
    "subdomain-enum",
    "email-enum",
    "cloud-enum",
    "web-basic",
)
DEFAULT_MODULES = (
    "http",
    "portscan",
    "gowitness",
    "nuclei",
)

DEADLY_MODULES = frozenset(
    {
        "nuclei",
        "ffuf",
        "fuzz",
        "legba",
        "medusa",
        "lightfuzz",
        "generic_ssrf",
        "dotnetnuke",
        "iis_shortnames",
    }
)

_MODULE_ALIASES: dict[str, str] = {
    "nmap": "portscan",
    "masscan": "portscan",
}

_MODULE_FALLBACKS: dict[str, tuple[str, ...]] = {
    "http": ("httpx", "http"),
    "httpx": ("http", "httpx"),
    "nmap": ("portscan",),
}
DEFAULT_OUTPUT_MODULES = (
    "csv",
    "json",
    "txt",
    "subdomains",
    "emails",
)

_BANNER_LINE = re.compile(r"^[\s\|/_\\\-─═╔╗╚╝║╠╣╦╩╬\[\]0-9;38;5;m]+$")


@dataclass
class BbotFinding:
    severity: str
    category: str
    title: str
    original_url: str
    evidence: str
    pattern: str = "bbot"
    archive_url: str = ""


@dataclass
class BbotResult:
    ok: bool
    output_dir: Path
    findings: list[BbotFinding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    screenshots: dict[str, str] = field(default_factory=dict)
    log_tail: str = ""
    error: str = ""


def bbot_bin() -> str:
    cfg = get_settings().bbot_bin.strip() or "bbot"
    return cfg


def _list_bbot_modules(prefix: list[str]) -> set[str]:
    try:
        proc = subprocess.run(
            [*prefix, "--list-modules"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if proc.returncode != 0:
            return set()
        return {m.lower() for m in re.findall(r"^\|\s*([a-z0-9_]+)\s*\|", proc.stdout, re.M)}
    except (OSError, subprocess.TimeoutExpired):
        return set()


def _resolve_bbot_modules(
    prefix: list[str],
    modules: list[str],
    *,
    allow_deadly: bool = False,
) -> tuple[list[str], list[str]]:
    available = _list_bbot_modules(prefix)
    kept: list[str] = []
    dropped: list[str] = []
    seen: set[str] = set()
    for raw in modules:
        token = raw.strip().lower()
        if not token:
            continue
        mod = _MODULE_ALIASES.get(token, token)
        if mod in seen:
            continue
        resolved = mod
        if available:
            candidates = _MODULE_FALLBACKS.get(mod, (mod,))
            resolved = next((c for c in candidates if c in available), "")
            if not resolved:
                dropped.append(raw)
                continue
        if not allow_deadly and resolved in DEADLY_MODULES:
            dropped.append(f"{raw} (deadly — включите --allow-deadly на проекте)")
            continue
        seen.add(resolved)
        kept.append(resolved)
    if not kept:
        for fallback in ("portscan", "httpx", "http", "gowitness"):
            if allow_deadly or fallback not in DEADLY_MODULES:
                if not available or fallback in available:
                    kept = [fallback]
                    break
    return kept, dropped


def _bbot_cmd_prefix() -> list[str] | None:
    """Return a working BBOT invocation prefix — prefer user pipx over root /usr/bin/bbot."""
    settings = get_settings()
    candidates: list[list[str]] = []
    configured = settings.bbot_bin.strip()
    if configured and configured not in {"bbot", "/usr/bin/bbot"}:
        candidates.append([configured])
    user_bbot = Path.home() / ".local/bin/bbot"
    if user_bbot.is_file():
        candidates.append([str(user_bbot)])
    user_py = Path.home() / ".local/share/pipx/venvs/bbot/bin/python"
    if user_py.is_file():
        candidates.append([str(user_py), "-m", "bbot"])
    path = shutil.which("bbot")
    if path and path != str(user_bbot):
        candidates.append([path])
    if configured in {"bbot", "/usr/bin/bbot"} and str(user_bbot) not in {c[0] for c in candidates}:
        candidates.append([configured])
    seen: set[tuple[str, ...]] = set()
    for cmd in candidates:
        key = tuple(cmd)
        if key in seen:
            continue
        seen.add(key)
        try:
            probe = subprocess.run(
                [*cmd, "--version"],
                capture_output=True,
                timeout=25,
                text=True,
            )
            if probe.returncode == 0:
                return cmd
        except (OSError, subprocess.TimeoutExpired):
            continue
    return None


def bbot_available() -> tuple[bool, str]:
    prefix = _bbot_cmd_prefix()
    if prefix:
        return True, prefix[0]
    return False, ""


def scan_output_dir(scan_id: str) -> Path:
    return BBOT_ROOT / scan_id


def _slug(name: str, limit: int = 48) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "scan").lower()).strip("-")
    return (slug[:limit] or "scan")


def expand_hosts_from_bbot(
    hosts: list[str],
    result: BbotResult | None,
    scope_apexes: set[str],
) -> list[str]:
    """Merge in-scope BBOT subdomains before archive / dork passes."""
    if not result:
        return list(hosts)
    expanded = list(hosts)
    seen = {normalize_target(h) for h in hosts if normalize_target(h)}
    for raw in result.subdomains:
        host = normalize_target(raw)
        if not host or host in seen:
            continue
        if not any(host == ap or host.endswith("." + ap) for ap in scope_apexes):
            continue
        seen.add(host)
        expanded.append(host)
    return expanded


def _in_scope_row(tags: str, scope_distance: str) -> bool:
    if not (tags or "").strip() and not (scope_distance or "").strip():
        return True
    t = (tags or "").lower()
    if "in-scope" in t or "target" in t or "seed" in t:
        return True
    if "out-of-scope" in t or "out_of_scope" in t or "affiliate" in t:
        return False
    try:
        return int(scope_distance or "99") <= 1
    except ValueError:
        return True


def _parse_event_data(raw: str) -> dict | str:
    text = (raw or "").strip()
    if not text:
        return {}
    if text.startswith("{") or text.startswith("["):
        try:
            import ast

            val = ast.literal_eval(text)
            return val if isinstance(val, dict) else {"value": str(val)}
        except (SyntaxError, ValueError):
            try:
                return json.loads(text)
            except (json.JSONDecodeError, ValueError):
                return {"value": text[:500]}
    return {"value": text[:500]}


def _resolve_data_dir(output_dir: Path) -> Path:
    if (output_dir / "output.csv").is_file() or (output_dir / "output.json").is_file():
        return output_dir
    if output_dir.is_dir():
        for child in sorted(output_dir.iterdir()):
            if child.is_dir() and (
                (child / "output.csv").is_file() or (child / "output.json").is_file()
            ):
                return child
    return output_dir


def _severity_for_event(event_type: str, data: dict | str, tags: str) -> str:
    t = event_type.upper()
    tag_l = (tags or "").lower()
    if t in {"VULNERABILITY", "FINDING"}:
        if isinstance(data, dict):
            sev = str(data.get("severity") or data.get("level") or "").lower()
            if sev in {"critical", "high", "medium", "low", "info", "informational", "moderate"}:
                if sev == "informational":
                    return "info"
                if sev == "moderate":
                    return "medium"
                return sev
        for level in ("critical", "high", "medium", "low"):
            if f"severity-{level}" in tag_l or level in tag_l.split(","):
                return level
        return "high"
    if t == "EMAIL_ADDRESS":
        return "medium"
    if t in {"OPEN_TCP_PORT", "CODE_REPOSITORY"}:
        return "medium"
    if t == "STORAGE_BUCKET":
        return "high"
    if t in {"DNS_NAME", "URL", "WEBSCREENSHOT", "TECHNOLOGY", "IP_ADDRESS"}:
        return "info"
    return "info"


def _category_for_event(event_type: str) -> str:
    t = event_type.upper()
    mapping = {
        "DNS_NAME": "bbot-dns",
        "EMAIL_ADDRESS": "bbot-email",
        "URL": "bbot-url",
        "OPEN_TCP_PORT": "bbot-port",
        "WEBSCREENSHOT": "bbot-screenshot",
        "FINDING": "bbot-finding",
        "VULNERABILITY": "bbot-vuln",
        "CODE_REPOSITORY": "bbot-code",
        "TECHNOLOGY": "bbot-tech",
        "IP_ADDRESS": "bbot-ip",
        "STORAGE_BUCKET": "bbot-bucket",
        "PROTOCOL": "bbot-protocol",
    }
    return mapping.get(t, "bbot")


def _event_payload(ev: dict) -> tuple[str, dict]:
    """Unified event value for BBOT 2.x (data string/dict) and 3.x (data_json)."""
    data_json = ev.get("data_json")
    if isinstance(data_json, dict):
        return str(
            data_json.get("url")
            or data_json.get("email")
            or data_json.get("host")
            or data_json.get("data")
            or data_json.get("name")
            or data_json.get("description")
            or data_json
        ).strip()[:2000], data_json
    data = ev.get("data")
    if isinstance(data, dict):
        return str(
            data.get("url")
            or data.get("email")
            or data.get("host")
            or data.get("data")
            or data.get("description")
            or data
        ).strip()[:2000], data
    host = str(ev.get("host") or ev.get("netloc") or "").strip()
    if isinstance(data, str) and data.strip():
        return data.strip()[:2000], {}
    if host:
        return host[:2000], {}
    return "", {}


def _event_url(event_type: str, value: str, ev: dict, data: dict) -> str:
    if value.startswith(("http://", "https://")):
        return value
    if isinstance(data, dict):
        url = str(data.get("url") or "").strip()
        if url.startswith(("http://", "https://")):
            return url
    if event_type.upper() == "DNS_NAME" and value:
        host = value.split(",")[0].strip()
        if host and "." in host:
            return f"https://{host}/"
    return ""


def _gowitness_shot_url(data_dir: Path, media_base: str, page_url: str) -> str:
    """Map a page URL to gowitness JPEG under /media/bbot/… if present."""
    if not page_url or not page_url.startswith(("http://", "https://")):
        return ""
    shots_dir = data_dir / "gowitness" / "screenshots"
    if not shots_dir.is_dir():
        return ""
    slug = page_url.replace("://", "--").replace("/", "-")
    for ext in (".jpeg", ".jpg", ".png"):
        candidate = shots_dir / f"{slug}{ext}"
        if candidate.is_file():
            rel = candidate.relative_to(data_dir)
            return f"{media_base}/gowitness/screenshots/{rel.name}"
    for path in sorted(shots_dir.glob(f"*{urlparse(page_url).netloc.replace('.', '-')}*")):
        if path.suffix.lower() in {".jpeg", ".jpg", ".png"}:
            return f"{media_base}/gowitness/screenshots/{path.name}"
    return ""


def lookup_gowitness_shot(scan_id: str, page_url: str) -> dict[str, str]:
    """Resolve gowitness thumb/full URLs for a live page from a scan output dir."""
    if not scan_id or not page_url:
        return {"thumb_url": "", "shot_url": ""}
    out_dir = scan_output_dir(scan_id)
    data_dir = _resolve_data_dir(out_dir)
    try:
        media_base = f"/media/bbot/{data_dir.relative_to(BBOT_ROOT).as_posix()}"
    except ValueError:
        media_base = f"/media/bbot/{scan_id}"
    shot = _gowitness_shot_url(data_dir, media_base, page_url.split(" → ")[0])
    if not shot:
        return {"thumb_url": "", "shot_url": ""}
    return {"thumb_url": shot, "shot_url": shot}


def _ingest_event(
    *,
    event_type: str,
    value: str,
    data: dict,
    tags: str,
    evidence: str,
    ev: dict | None,
    findings: list[BbotFinding],
    urls: list[str],
    subdomains: list[str],
    emails: list[str],
    screenshots: dict[str, str],
    seen: set[tuple[str, str]],
    media_base: str,
    data_dir: Path,
) -> None:
    t = (event_type or "").strip()
    if not t or t.upper() == "SCAN":
        return
    if not _in_scope_row(tags, str((ev or {}).get("scope_distance", ""))):
        return
    value = (value or "").strip()
    if not value:
        return

    if t.upper() == "WEBSCREENSHOT":
        page = value if value.startswith(("http://", "https://")) else ""
        if isinstance(data, dict):
            page = str(data.get("url") or page).strip()
        shot = _gowitness_shot_url(data_dir, media_base, page)
        if shot and page:
            screenshots[page.rstrip("/")] = shot
            screenshots[page] = shot
        return

    sev = _severity_for_event(t, data, tags)
    cat = _category_for_event(t)
    url = _event_url(t, value, ev or {}, data)
    key = (t.upper(), value[:200])
    if key in seen:
        return
    seen.add(key)

    if t.upper() == "DNS_NAME":
        host = value.split(",")[0].strip().lower()
        if host:
            subdomains.append(host)
            url = url or f"https://{host}/"
    elif t.upper() == "EMAIL_ADDRESS":
        email = value.lower().split(",")[0].strip()
        if "@" in email:
            emails.append(email)
            value = email
    elif t.upper() == "URL" and url:
        urls.append(url)

    title = value[:120]
    pattern = f"bbot-{t.lower()}"
    ev_text = ""
    if isinstance(ev, dict):
        ev_text = str(ev.get("discovery_context") or ev.get("discovery_path") or evidence)[:500]

    if t.upper() == "EMAIL_ADDRESS":
        title = f"Email: {value[:120]}"
        url = ""
    elif t.upper() == "DNS_NAME":
        title = f"Subdomain: {value.split(',')[0][:120]}"
    elif t.upper() == "OPEN_TCP_PORT":
        port_num = (ev or {}).get("port") or value.rsplit(":", 1)[-1]
        host_part = str((ev or {}).get("host") or value.rsplit(":", 1)[0])
        resolved = (ev or {}).get("resolved_hosts") or []
        svc = classify_open_port(host_part, port_num, resolved=resolved if isinstance(resolved, list) else None)
        if svc:
            sev, cat, title, pattern = svc.severity, svc.category, svc.title, svc.pattern
            ev_text = svc.evidence or ev_text
        else:
            title = f"Port: {value[:120]}"
        url = ""
    elif t.upper() == "URL":
        auth = classify_auth_url(url or value)
        if auth:
            sev, cat, title, pattern = auth.severity, auth.category, auth.title, auth.pattern
            pattern = "auth-login-live"
    elif t.upper() == "FINDING" and isinstance(data, dict):
        desc = str(data.get("description") or value)
        f_url = str(data.get("url") or url)
        enriched = classify_bbot_finding(desc, str((ev or {}).get("host") or data.get("host") or ""), f_url)
        if enriched:
            sev, cat, title, pattern = enriched.severity, enriched.category, enriched.title, enriched.pattern
            if hasattr(enriched, "evidence"):
                ev_text = enriched.evidence or desc[:400]
            if f_url.startswith(("http://", "https://")):
                url = f_url
    elif t.upper() == "TECHNOLOGY" and isinstance(data, dict):
        tech = str(data.get("technology") or value)
        host_t = str(data.get("host") or (ev or {}).get("host") or "")
        mail = classify_mail_technology(tech, host_t)
        if mail:
            sev, cat, title, pattern = mail.severity, mail.category, mail.title, mail.pattern
            ev_text = mail.evidence or tech[:400]
    elif t.upper() == "STORAGE_BUCKET":
        bucket_name = value
        if isinstance(data, dict):
            bucket_name = str(data.get("name") or data.get("url") or value)
            b_url = str(data.get("url") or "")
            if b_url.startswith(("http://", "https://")):
                url = b_url
        title = f"Storage bucket: {bucket_name[:120]}"
        pattern = "bbot-bucket"
    elif t.upper() == "CODE_REPOSITORY":
        title = f"Git repo: {value[:120]}"
        pattern = "bbot-git"
    elif t.upper() == "VULNERABILITY" and isinstance(data, dict):
        title = f"Vuln: {str(data.get('description') or value)[:100]}"
        pattern = "bbot-vuln"

    resource_url = url if url.startswith(("http://", "https://")) else ""
    if t.upper() == "EMAIL_ADDRESS":
        resource_url = ""
    elif t.upper() == "OPEN_TCP_PORT":
        resource_url = ""

    findings.append(
        BbotFinding(
            severity=sev,
            category=cat,
            title=title,
            original_url=resource_url,
            evidence=ev_text or value[:400],
            archive_url=resource_url,
            pattern=pattern,
        )
    )


def parse_bbot_output(output_dir: Path, *, scan_id: str) -> BbotResult:
    data_dir = _resolve_data_dir(output_dir)
    findings: list[BbotFinding] = []
    urls: list[str] = []
    subdomains: list[str] = []
    emails: list[str] = []
    screenshots: dict[str, str] = {}
    seen: set[tuple[str, str]] = set()
    media_base = ""
    try:
        media_base = f"/media/bbot/{data_dir.relative_to(BBOT_ROOT).as_posix()}"
    except ValueError:
        media_base = f"/media/bbot/{scan_id}"

    csv_path = data_dir / "output.csv"
    if csv_path.is_file():
        with csv_path.open(newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                event_type = (row.get("Event type") or row.get("type") or "").strip()
                data_raw = row.get("Event data") or row.get("data") or ""
                data = _parse_event_data(data_raw)
                if isinstance(data, dict):
                    value = str(
                        data.get("url")
                        or data.get("email")
                        or data.get("host")
                        or data.get("data")
                        or data_raw
                    )
                else:
                    value = str(data or data_raw)
                _ingest_event(
                    event_type=event_type,
                    value=value,
                    data=data if isinstance(data, dict) else {},
                    tags=row.get("Event Tags", "") or row.get("tags", ""),
                    evidence=(row.get("Discovery Path") or row.get("discovery_path") or "")[:500],
                    ev=None,
                    findings=findings,
                    urls=urls,
                    subdomains=subdomains,
                    emails=emails,
                    screenshots=screenshots,
                    seen=seen,
                    media_base=media_base,
                    data_dir=data_dir,
                )

    json_path = data_dir / "output.json"
    if json_path.is_file():
        with json_path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event_type = str(ev.get("type") or "")
                value, data = _event_payload(ev)
                tags = ",".join(ev.get("tags") or [])
                evidence = str(ev.get("discovery_context") or ev.get("discovery_path") or "")[:500]
                _ingest_event(
                    event_type=event_type,
                    value=value,
                    data=data,
                    tags=tags,
                    evidence=evidence,
                    ev=ev,
                    findings=findings,
                    urls=urls,
                    subdomains=subdomains,
                    emails=emails,
                    screenshots=screenshots,
                    seen=seen,
                    media_base=media_base,
                    data_dir=data_dir,
                )

    for fname in ("subdomains.txt", "emails.txt"):
        sidecar = data_dir / fname
        if not sidecar.is_file():
            continue
        for line in sidecar.read_text(encoding="utf-8", errors="replace").splitlines():
            token = line.strip()
            if not token or token.startswith("#"):
                continue
            if fname == "subdomains.txt":
                host = normalize_target(token)
                if host and host not in subdomains:
                    subdomains.append(host)
            elif "@" in token and token not in emails:
                emails.append(token.lower())

    return BbotResult(
        ok=True,
        output_dir=output_dir,
        findings=findings,
        urls=sorted(set(urls)),
        subdomains=sorted(set(subdomains)),
        emails=sorted(set(emails)),
        screenshots=screenshots,
    )


def build_bbot_command(
    targets_file: Path,
    output_dir: Path,
    scan_name: str,
    *,
    allow_deadly: bool = False,
) -> list[str]:
    settings = get_settings()
    prefix = _bbot_cmd_prefix()
    if not prefix:
        raise RuntimeError(
            "BBOT недоступен для текущего пользователя. Установите: pipx install bbot "
            f"(не под root; пользователь: {Path.home().name})"
        )
    flags = [x.strip() for x in settings.bbot_flags.split(",") if x.strip()] or list(DEFAULT_FLAGS)
    raw_modules = [x.strip() for x in settings.bbot_modules.split(",") if x.strip()] or list(DEFAULT_MODULES)
    modules, dropped = _resolve_bbot_modules(prefix, raw_modules, allow_deadly=allow_deadly)
    if not modules:
        raise RuntimeError("BBOT: ни один scan-модуль не доступен — проверьте GHOSTINDEX_BBOT_MODULES")
    out_mods = [
        x.strip()
        for x in (getattr(settings, "bbot_output_modules", "") or "").split(",")
        if x.strip()
    ] or list(DEFAULT_OUTPUT_MODULES)
    cmd = [
        *prefix,
        "-t",
        str(targets_file),
        "-f",
        *flags,
        "-m",
        *modules,
        "-om",
        *out_mods,
        "-n",
        _slug(scan_name),
        "-o",
        str(output_dir),
        "--force",
        "-y",
    ]
    if allow_deadly and settings.bbot_allow_deadly:
        cmd.append("--allow-deadly")
    return cmd, dropped


def _has_bbot_output(output_dir: Path) -> bool:
    data_dir = _resolve_data_dir(output_dir)
    return (data_dir / "output.csv").is_file() or (data_dir / "output.json").is_file()


def _meaningful_bbot_tail(lines: list[str]) -> str:
    useful = [
        ln
        for ln in lines
        if ln.strip()
        and not _BANNER_LINE.match(ln.strip())
        and "____" not in ln
        and "BLS OSINT" not in ln
    ]
    tail = useful[-10:] if useful else lines[-10:]
    return "\n".join(tail).strip()


async def run_bbot_scan(
    hosts: list[str],
    *,
    scan_id: str,
    scan_name: str,
    allow_deadly: bool = False,
    log_line: Callable[[str], None] | None = None,
    cancel_check: Callable[[], None] | None = None,
) -> BbotResult:
    ok, _path = bbot_available()
    if not ok:
        return BbotResult(
            ok=False,
            output_dir=scan_output_dir(scan_id),
            error="BBOT не найден — pipx install bbot (от пользователя, который запускает GhostIndex)",
        )

    out_dir = scan_output_dir(scan_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    targets_file = out_dir / "targets.txt"
    targets_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    try:
        cmd, dropped = build_bbot_command(targets_file, out_dir, scan_name, allow_deadly=allow_deadly)
    except RuntimeError as exc:
        return BbotResult(ok=False, output_dir=out_dir, error=str(exc))

    if log_line and dropped:
        log_line(f"BBOT: пропущены модули (нет в BBOT): {', '.join(dropped)}")

    if log_line:
        log_line(f"BBOT cmd: {' '.join(cmd[:16])}…")

    settings = get_settings()
    timeout = float(settings.bbot_timeout_seconds or 7200)
    log_lines: list[str] = []
    started = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(out_dir),
        )
    except PermissionError as exc:
        return BbotResult(
            ok=False,
            output_dir=out_dir,
            error=(
                "BBOT: нет доступа к бинарнику (pipx install bbot был под root). "
                f"Установите от пользователя {Path.home().name}: pipx install bbot ({exc})"
            ),
        )
    except OSError as exc:
        return BbotResult(ok=False, output_dir=out_dir, error=f"BBOT не запустился: {exc}")

    async def _drain_stdout() -> None:
        assert proc.stdout is not None
        while True:
            if cancel_check:
                cancel_check()
            line_b = await proc.stdout.readline()
            if not line_b:
                break
            line = line_b.decode("utf-8", errors="replace").rstrip()
            if line:
                log_lines.append(line)
                low = line.lower()
                if log_line and (
                    len(log_lines) <= 12
                    or "error" in low
                    or "fail" in low
                    or len(log_lines) % 50 == 0
                ):
                    log_line(line[:240])

    reader = asyncio.create_task(_drain_stdout())
    try:
        rc = await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        rc = await proc.wait()
        await reader
        return BbotResult(
            ok=False,
            output_dir=out_dir,
            error=f"BBOT timeout ({int(timeout)}s)",
            log_tail=_meaningful_bbot_tail(log_lines),
        )
    finally:
        if not reader.done():
            await reader

    parsed = parse_bbot_output(out_dir, scan_id=scan_id)
    parsed.log_tail = _meaningful_bbot_tail(log_lines)
    elapsed = time.monotonic() - started

    err_log = _resolve_data_dir(out_dir) / "error.log"
    if err_log.is_file():
        err_tail = err_log.read_text(encoding="utf-8", errors="replace")[-400:].strip()
        if err_tail:
            parsed.log_tail = f"{parsed.log_tail}\n{err_tail}".strip()

    if not _has_bbot_output(out_dir):
        parsed.ok = False
        log_blob = "\n".join(log_lines).lower()
        missing_mod = "could not find scan module" in log_blob
        need_deadly = "allow-deadly" in log_blob or "deadly modules" in log_blob
        if need_deadly:
            hint = "включите «--allow-deadly» в настройках проекта (nuclei требует флаг)"
        elif missing_mod:
            hint = "проверьте GHOSTINDEX_BBOT_MODULES (http↔httpx, nmap→portscan)"
        else:
            hint = f"pipx install bbot от {Path.home().name} (не /usr/bin/bbot root 2.8)"
        parsed.error = (
            f"BBOT завершился без output.csv ({elapsed:.1f}s, rc={rc}). {hint}. "
            f"{parsed.log_tail[:280]}"
        )
    elif rc != 0 and not parsed.findings and not parsed.subdomains:
        parsed.ok = False
        parsed.error = f"BBOT exit code {rc}. {parsed.log_tail[:240]}"
    else:
        parsed.ok = True
    return parsed
