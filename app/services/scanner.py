from __future__ import annotations

import asyncio
import re
from contextvars import Token
from datetime import datetime, timezone

from urllib.parse import urljoin, urlparse, unquote

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal
from app.models import Finding, Project, Scan, User
from app.services.inventory import append_live_urls, store_url_inventory
from app.services.classifier import (
    SEVERITY_RANK,
    canonical_url,
    classify_url,
    is_marketing_path,
    is_script_or_data,
    worth_llm_extract,
)
from app.services.js_intel import extract_js_endpoints
from app.services.live_auth import build_live_auth
from app.services.live_content import confirm_live_path_finding, host_key, bodies_match, is_auth_redirect, is_wayback_miss_page
from app.services.evidence_fmt import format_context, parse_evidence_loc
from app.services.live_crawler import crawl_live_site, pages_for_llm, select_crawl_hosts
from app.services.live_probe import probe_auth_pages, probe_live_hosts
from app.services.pentest_intel import classify_auth_url, detect_login_form_html
from app.services.llm_queue import LlmContext, bind_llm_context, unbind_llm_context
from app.services.llm import (
    LlmConfig,
    extract_live_secrets_batch,
    extract_secrets_batch,
    review_flags,
    triage_urls,
)
from app.services.notify import notify_scan_complete
from app.services.osint import OsintHit, osint_title, scan_osint
from app.services.screenshots import capture_findings
from app.services.secrets import scan_text
from app.services.dork_tiers import effective_dork_tier
from app.services.dorks import run_dork_scan
from app.services.finding_display import is_hidden_finding
from app.services.findings_dedup import finding_dedupe_key
from app.services.bbot import bbot_available, expand_hosts_from_bbot, run_bbot_scan
from app.services.wayback import (
    Capture,
    compile_url_patterns,
    enumerate_cdx,
    enumerate_commoncrawl,
    enumerate_commoncrawl_with_note,
    enumerate_versions,
    extract_html_links,
    extract_url_secrets,
    fetch_raw_snapshot,
    interesting_robots_paths,
    latest_commoncrawl_index,
    apex_domain,
    is_archived_capture,
    make_client,
    parse_robots_paths,
    parse_sitemap_locs,
    parse_targets,
    probe_wayback,
    reset_wayback_state,
    targeted_cdx,
    waybackurls_style,
)

_LLM_REVIEW_KEEP = frozenset(
    {
        "env",
        "git",
        "ssh",
        "keyfile",
        "app-config",
        "creds-file",
        "pass-file",
        "htpasswd",
        "dot-creds",
        "backup",
        "stale",
        "phpinfo",
        "server-status",
        "bitrix",
        "parameters-file",
        "server-config",
        "auth-login",
        "auth-login-live",
        "auth-login-form",
        "auth-sso",
        "auth-admin-entry",
        "mail-smtp",
        "mail-smtps",
        "mail-submission",
        "mail-imap",
        "mail-imaps",
        "mail-pop3",
        "mail-pop3s",
        "mail-mx",
        "mail-technology",
        "shodan-cve",
        "url-embedded",
    }
)

_DISCLOSURE = re.compile(r"(?i)(phpinfo|allinfo\.php|/info\.php|test\.php|server-status)")

_queue: asyncio.Queue[str] | None = None
_worker_task: asyncio.Task | None = None
_cancelled: set[str] = set()


class ScanCancelled(Exception):
    pass


def scan_queue() -> asyncio.Queue[str]:
    global _queue
    if _queue is None:
        _queue = asyncio.Queue()
    return _queue


async def start_worker() -> None:
    global _worker_task
    if _worker_task and not _worker_task.done():
        return
    _worker_task = asyncio.create_task(_worker_loop())


async def _worker_loop() -> None:
    queue = scan_queue()
    while True:
        scan_id = await queue.get()
        if scan_id in _cancelled:
            _finalize_cancelled(scan_id)
            queue.task_done()
            continue
        try:
            await asyncio.to_thread(_run_scan_sync, scan_id)
        except Exception as exc:  # noqa: BLE001
            if scan_id in _cancelled:
                _finalize_cancelled(scan_id)
            else:
                db = SessionLocal()
                try:
                    scan = db.get(Scan, scan_id)
                    if scan and scan.status not in {"cancelled", "done"}:
                        scan.status = "failed"
                        scan.error = str(exc)[:2000]
                        scan.finished_at = datetime.now(timezone.utc)
                        db.commit()
                finally:
                    db.close()
        finally:
            queue.task_done()


def request_abort(db: Session, scan: Scan) -> Scan:
    _cancelled.add(scan.id)
    if scan.status == "queued":
        scan.status = "cancelled"
        scan.error = "Остановлено пользователем"
        scan.finished_at = datetime.now(timezone.utc)
        _append_log(db, scan, "Прервано до старта")
    elif scan.status == "running":
        _append_log(db, scan, "Запрос на прерывание")
    return scan


def _finalize_cancelled(scan_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan and scan.status in {"queued", "running", "cancelled"}:
            scan.status = "cancelled"
            scan.stage = "Прервано"
            scan.error = scan.error or "Остановлено пользователем"
            scan.finished_at = datetime.now(timezone.utc)
            _append_log(db, scan, "Прервано")
            db.commit()
    finally:
        _cancelled.discard(scan_id)
        db.close()


def _check_cancel(db: Session, scan: Scan) -> None:
    if scan.id not in _cancelled:
        return
    scan.status = "cancelled"
    scan.stage = "Прервано"
    scan.error = "Остановлено пользователем"
    scan.finished_at = datetime.now(timezone.utc)
    _append_log(db, scan, "Прервано по запросу")
    db.commit()
    raise ScanCancelled()


def enqueue_scan(db: Session, project: Project) -> Scan:
    scan = Scan(project_id=project.id, status="queued", stage="В очереди")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    scan_queue().put_nowait(scan.id)
    return scan


def _append_log(db: Session, scan: Scan, line: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    scan.log = (scan.log + f"[{stamp}] {line}\n")[-12000:]
    scan.stage = line[:255]
    db.commit()


def _touch_progress(
    db: Session,
    scan: Scan,
    *,
    urls: int | None = None,
    findings: int | None = None,
    progress: int | None = None,
) -> None:
    if urls is not None:
        scan.urls_seen = urls
    if findings is not None:
        scan.findings_count = findings
    if progress is not None:
        scan.progress = progress
    db.commit()


def _run_scan_sync(scan_id: str) -> None:
    asyncio.run(_run_scan(scan_id))


def _append_osint_hit(
    findings_acc: list[Finding],
    *,
    project_id: str,
    scan_id: str,
    hit: OsintHit,
    url: str,
    archive_url: str,
    capture_ts: str,
    source: str,
    seen: set[tuple],
) -> bool:
    if hit.kind == "phone":
        key: tuple = ("phone", re.sub(r"\D", "", hit.value)[:20])
    else:
        key = (hit.kind, hit.value.lower())
    if key in seen:
        return False
    seen.add(key)
    findings_acc.append(
        Finding(
            project_id=project_id,
            scan_id=scan_id,
            severity=hit.severity,
            category=f"osint-{hit.kind}",
            title=osint_title(hit),
            original_url=url,
            archive_url=archive_url or url,
            capture_ts=capture_ts,
            evidence=hit.evidence,
            masked_secret=hit.stored_value,
            pattern=hit.pattern,
            source=source,
        )
    )
    return True


def _append_osint_from_text(
    findings_acc: list[Finding],
    *,
    project_id: str,
    scan_id: str,
    text: str,
    url: str,
    archive_url: str,
    capture_ts: str,
    source: str,
    hosts: list[str],
    enable_osint: bool,
    seen: set[tuple],
) -> int:
    if not enable_osint or not text:
        return 0
    added = 0
    for hit in scan_osint(text, source_url=url, scope_hosts=hosts):
        if _append_osint_hit(
            findings_acc,
            project_id=project_id,
            scan_id=scan_id,
            hit=hit,
            url=url,
            archive_url=archive_url,
            capture_ts=capture_ts,
            source=source,
            seen=seen,
        ):
            added += 1
    return added


def _store_findings(db: Session, findings_acc: list[Finding]) -> list[Finding]:
    unique: dict[tuple, Finding] = {}
    for item in findings_acc:
        if getattr(item, "id", None):
            continue
        key = finding_dedupe_key(item)
        prev = unique.get(key)
        if not prev or SEVERITY_RANK.get(item.severity, 0) > SEVERITY_RANK.get(prev.severity, 0):
            unique[key] = item
    stored = list(unique.values())
    for item in stored:
        db.add(item)
    if stored:
        db.flush()
    return stored


def _clone_finding(f: Finding, scan_id: str) -> Finding:
    return Finding(
        project_id=f.project_id,
        scan_id=scan_id,
        severity=f.severity,
        category=f.category,
        title=f.title,
        original_url=f.original_url,
        archive_url=f.archive_url,
        capture_ts=f.capture_ts,
        evidence=f.evidence,
        masked_secret=f.masked_secret,
        pattern=f.pattern,
        source=f.source,
    )


def _finalize_project_findings(
    db: Session,
    project: Project,
    scan: Scan,
    findings_acc: list[Finding],
    scope_apexes: set[str],
) -> list[Finding]:
    from app.services.project_hosts import (
        collect_hosts_for_project,
        subdomain_findings_from_hosts,
        sync_project_hosts,
    )

    host_map = collect_hosts_for_project(db, project.id)
    sync_project_hosts(db, project.id, scan.id)
    existing_dns = {canonical_url(f.original_url) for f in findings_acc if f.category == "bbot-dns"}
    for sf in subdomain_findings_from_hosts(
        host_map,
        project_id=project.id,
        scan_id=scan.id,
        scope_apexes=scope_apexes,
    ):
        if canonical_url(sf.original_url) not in existing_dns:
            findings_acc.append(sf)
            existing_dns.add(canonical_url(sf.original_url))

    db.query(Finding).filter(Finding.project_id == project.id).delete()
    db.commit()
    fresh = [_clone_finding(f, scan.id) for f in findings_acc]
    return _store_findings(db, fresh)


def _count_scan_findings(db: Session, scan_id: str) -> int:
    return db.query(Finding).filter(Finding.scan_id == scan_id).count()


def _flush_findings(db: Session, findings_acc: list[Finding]) -> int:
    stored = _store_findings(db, findings_acc)
    if stored:
        db.commit()
    return len(stored)


def parse_csv_list(blob: str) -> list[str]:
    return [x.strip() for x in re.split(r"[\s,;]+", blob or "") if x.strip()]


def _user_llm(user: User | None) -> LlmConfig | None:
    if not user or not user.llm_enabled or not user.llm_base_url or not user.llm_model:
        return None
    return LlmConfig(
        enabled=True,
        base_url=user.llm_base_url,
        api_path=user.llm_api_path or "/v1/chat/completions",
        model=user.llm_model,
        api_key=user.llm_api_key or "",
        temperature=float(user.llm_temperature or 0.2),
        max_tokens=int(user.llm_max_tokens or 1200),
        timeout=float(user.llm_timeout or 180),
    )


def _cdx_kwargs(project: Project) -> dict:
    return {
        "date_from": getattr(project, "date_from", "") or "",
        "date_to": getattr(project, "date_to", "") or "",
        "status_200_only": not bool(getattr(project, "include_non200", False)),
    }


_CDX_UNLIMITED = 500_000


def _max_urls_unlimited(project: Project) -> bool:
    return bool(getattr(project, "max_urls_unlimited", False))


def _per_host_cdx_limit(project: Project, host_count: int) -> int:
    if _max_urls_unlimited(project):
        return _CDX_UNLIMITED
    return max(500, int(project.max_urls or 8000) // max(host_count, 1))


def _host_uses_domain_cdx(host: str, project: Project) -> bool:
    """CDX matchType=domain only for apex targets when subdomains are enabled."""
    return bool(getattr(project, "include_subdomains", True)) and host.count(".") <= 1


def _llm_parallel_slots(llm_cfg: LlmConfig | None) -> int:
    """More concurrent LLM batches when GPU-backed server is configured."""
    return 4 if llm_cfg else 1


# Backward-compatible alias
_per_apex_cdx_limit = _per_host_cdx_limit


def _url_inventory_limit(project: Project, capture_count: int) -> int:
    if _max_urls_unlimited(project):
        return capture_count
    return min(capture_count, max(int(project.max_urls or 15000), 15000))


def _snapshot_fetch_limit(project: Project, queue_len: int, llm_cfg: bool) -> int:
    if getattr(project, "max_snapshot_fetches_unlimited", False):
        return queue_len
    cap = max(int(project.max_snapshot_fetches or 80), 120 if llm_cfg else 80)
    return min(queue_len, cap)


_TRIAGE_HINTS = (
    "admin",
    "backup",
    "old",
    "test",
    "include",
    "php",
    "sql",
    "git",
    "conf",
    "env",
    "dump",
    "private",
    "api",
    "install",
    "setup",
    "bitrix",
    "wp-",
    "cgi",
    "inc",
    "bak",
    "log",
    "debug",
    "phpinfo",
    "allinfo",
    "dbconn",
    "config",
    "secret",
    "passwd",
    "login",
    ".git",
    "web.config",
)


def _triage_pool(captures: list[Capture], klass_fn, limit: int = 240) -> list[Capture]:
    scored: list[tuple[int, Capture]] = []
    for cap in captures:
        url = cap.original
        if is_marketing_path(url):
            continue
        klass = klass_fn(url)
        if klass and SEVERITY_RANK.get(klass.severity, 0) >= 3:
            continue
        path = urlparse(unquote(url)).path.lower()
        score = sum(2 for tok in _TRIAGE_HINTS if tok in path)
        if path.endswith(
            (".php", ".json", ".xml", ".txt", ".sql", ".env", ".bak", ".inc", ".yml", ".yaml", ".conf", ".cfg", ".ini", ".log", ".js", ".mjs")
        ):
            score += 3
        mime = (cap.mimetype or "").lower()
        if "json" in mime or "xml" in mime or "php" in mime or "javascript" in mime:
            score += 1
        if score:
            scored.append((score, cap))
    scored.sort(key=lambda pair: -pair[0])
    seen: set[str] = set()
    out: list[Capture] = []
    for _, cap in scored:
        key = canonical_url(cap.original)
        if key in seen:
            continue
        seen.add(key)
        out.append(cap)
        if len(out) >= limit:
            break
    return out


async def _run_scan(scan_id: str) -> None:
    db = SessionLocal()
    settings = get_settings()
    llm_ctx_token: Token | None = None
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        project = db.get(Project, scan.project_id)
        if not project:
            scan.status = "failed"
            scan.error = "Проект удалён"
            db.commit()
            return

        owner = db.get(User, project.owner_id)
        llm_ctx_token = bind_llm_context(
            LlmContext(
                scan_id=scan.id,
                project_id=project.id,
                project_name=project.name or "",
                log=lambda msg: _append_log(db, scan, msg),
            )
        )
        extra_kw = parse_csv_list(getattr(project, "extra_keywords", "") or "")
        extra_ext = parse_csv_list(getattr(project, "extra_extensions", "") or "")
        scan_js = bool(getattr(project, "scan_javascript", True))
        follow_robots = bool(getattr(project, "follow_robots", True))
        include_recon = bool(getattr(project, "include_recon", True))
        cdx_extra = _cdx_kwargs(project)
        findings_acc: list[Finding] = []
        seen_osint: set[tuple] = set()
        enable_osint = bool(getattr(project, "enable_osint", True))

        if scan.id in _cancelled or scan.status == "cancelled":
            _check_cancel(db, scan)

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 2
        db.commit()
        _append_log(db, scan, "Старт прохода: BBOT → архивы/CDX (dorks параллельно)")

        hosts = parse_targets(project.targets)
        if not hosts:
            scan.status = "failed"
            scan.error = "Не заданы цели"
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            return

        captures: list[Capture] = []
        seen_urls: set[str] = set()
        allow_patterns = compile_url_patterns(getattr(project, "url_allow_pattern", "") or "")
        deny_patterns = compile_url_patterns(getattr(project, "url_deny_pattern", "") or "")
        include_cc = bool(getattr(project, "include_commoncrawl", True))
        enable_dorks = bool(getattr(project, "enable_dorks", True))
        dork_tier = effective_dork_tier(project)
        crawl_html = bool(getattr(project, "crawl_html_links", True))
        multi_disclosure = bool(getattr(project, "multi_snapshot_disclosure", True))

        scope_apexes = {apex_domain(h) for h in hosts}
        bbot_result = None

        if getattr(project, "enable_bbot", False):
            _check_cancel(db, scan)
            if not project.authorized:
                _append_log(db, scan, "BBOT: пропуск — нужно подтверждение authorized на проекте")
            else:
                ok_bbot, bbot_path = bbot_available()
                if not ok_bbot:
                    _append_log(db, scan, "BBOT: не найден в PATH (pipx install bbot)")
                else:
                    allow_deadly = bool(getattr(project, "bbot_allow_deadly", False))
                    scan.stage = "BBOT OSINT"
                    scan.progress = max(scan.progress or 0, 5)
                    db.commit()
                    _append_log(
                        db,
                        scan,
                        f"BBOT ({bbot_path}): {len(hosts)} целей · deadly={'да' if allow_deadly else 'нет'}",
                    )
                    try:
                        bbot_result = await run_bbot_scan(
                            hosts,
                            scan_id=scan.id,
                            scan_name=project.name or scan.id[:8],
                            allow_deadly=allow_deadly,
                            log_line=lambda msg: _append_log(db, scan, msg),
                            cancel_check=lambda: _check_cancel(db, scan),
                        )
                    except ScanCancelled:
                        raise
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"BBOT ошибка: {exc}")
                        bbot_result = None
                    if bbot_result:
                        if bbot_result.error and not bbot_result.findings and not bbot_result.subdomains:
                            _append_log(db, scan, f"BBOT: {bbot_result.error}")
                        for bf in bbot_result.findings:
                            if bf.category in {"bbot-screenshot"} or "webscreenshot" in (bf.title or "").lower():
                                continue
                            email_val = ""
                            if bf.category == "bbot-email" and bf.title.lower().startswith("email:"):
                                email_val = bf.title.split(":", 1)[-1].strip()
                            findings_acc.append(
                                Finding(
                                    project_id=project.id,
                                    scan_id=scan.id,
                                    severity=bf.severity,
                                    category=bf.category,
                                    title=bf.title,
                                    original_url=bf.original_url,
                                    archive_url=bf.archive_url or bf.original_url,
                                    capture_ts="",
                                    evidence=bf.evidence[:500],
                                    masked_secret=email_val,
                                    pattern=bf.pattern,
                                    source="bbot",
                                )
                            )
                        if bbot_result.urls:
                            inv_n = append_live_urls(
                                db,
                                project_id=project.id,
                                scan_id=scan.id,
                                urls=bbot_result.urls,
                                klass_fn=lambda u: classify_url(u, extra_keywords=extra_kw, extra_exts=extra_ext),
                            )
                            if inv_n:
                                _append_log(db, scan, f"BBOT URL-инвентарь: +{inv_n}")
                        flushed = _flush_findings(db, findings_acc)
                        auth_n = sum(1 for f in findings_acc if f.category == "auth-panel")
                        mail_n = sum(1 for f in findings_acc if f.category == "exposed-mail")
                        svc_n = sum(
                            1
                            for f in findings_acc
                            if f.category in {"exposed-service", "exposed-db", "bbot-shodan"}
                        )
                        extra = ""
                        if auth_n or mail_n or svc_n:
                            extra = f" · auth={auth_n} · mail={mail_n} · svc={svc_n}"
                        _append_log(
                            db,
                            scan,
                            f"BBOT готово: {len(bbot_result.findings)} событий · "
                            f"{len(bbot_result.subdomains)} поддоменов · {len(bbot_result.emails)} email"
                            + (f" · в БД: {flushed}" if flushed else "")
                            + extra,
                        )
                        _touch_progress(db, scan, findings=len(findings_acc), progress=max(scan.progress or 0, 12))

        before_hosts = len(hosts)
        hosts = expand_hosts_from_bbot(hosts, bbot_result, scope_apexes)
        if len(hosts) > before_hosts:
            _append_log(
                db,
                scan,
                f"Scope расширен BBOT: +{len(hosts) - before_hosts} хостов → {len(hosts)} целей для CDX/dorks",
            )

        def _in_scope(url: str) -> bool:
            loc_host = urlparse(url).netloc.lower().split("@")[-1].split(":")[0]
            if loc_host.startswith("www."):
                loc_host = loc_host[4:]
            if any(loc_host == h or loc_host.endswith("." + h) for h in hosts):
                return True
            if project.include_subdomains:
                return any(loc_host == apex or loc_host.endswith("." + apex) for apex in scope_apexes)
            return False

        def _passes_deny(url: str) -> bool:
            return not (deny_patterns and any(p.search(url) for p in deny_patterns))

        def _passes_allow(url: str) -> bool:
            return not (allow_patterns and not any(p.search(url) for p in allow_patterns))

        def _add(cap: Capture) -> None:
            if not _in_scope(cap.original):
                return
            if cap.original not in seen_urls:
                seen_urls.add(cap.original)
                captures.append(cap)

        raw_index_total = 0
        dork_matched_urls: set[str] = set()

        def _ingest_caps(batch: list[Capture], label: str) -> None:
            nonlocal raw_index_total
            if not batch:
                _append_log(db, scan, f"{label}: 0 URL из источника")
                return
            raw_index_total += len(batch)
            before = len(captures)
            scope_miss = 0
            for cap in batch:
                if not _in_scope(cap.original):
                    scope_miss += 1
                    continue
                _add(cap)
            added = len(captures) - before
            msg = f"{label}: +{added} URL"
            if scope_miss:
                msg += f" (вне scope: −{scope_miss})"
            _append_log(db, scan, msg)

        async with make_client() as client:
            reset_wayback_state()
            archive_status = await probe_wayback(client)
            cc_index = await latest_commoncrawl_index(client)
            if archive_status == "online":
                _append_log(db, scan, "Archive.org CDX: доступен")
            else:
                _append_log(
                    db,
                    scan,
                    "Archive.org CDX: probe медленный — запрашиваем CDX с повторами (503/rate limit)",
                )
            reset_wayback_state()
            _append_log(db, scan, f"Common Crawl index: {cc_index}")


            host_count = len(hosts)
            per_host = _per_host_cdx_limit(project, host_count)
            use_cdx = True
            if _max_urls_unlimited(project):
                _append_log(db, scan, "CDX: безлимит URL — максимальный охват индекса")
            _append_log(
                db,
                scan,
                f"Архивный проход: {host_count} целей — CC + CDX (dorks параллельно)",
            )
            llm_cfg_early = _user_llm(owner) if getattr(project, "use_llm", True) else None
            if llm_cfg_early:
                _append_log(
                    db,
                    scan,
                    f"LLM активен — глобальная очередь (один запрос к модели за раз, до {_llm_parallel_slots(llm_cfg_early)} батчей/проход)",
                )

            dork_tasks: list[asyncio.Task] = []

            async def _dorks_for_host(host: str) -> tuple[str, list]:
                scan_subs = _host_uses_domain_cdx(host, project)
                host_label = host + (" (+поддомены)" if scan_subs else "")
                try:
                    return host, await run_dork_scan(
                        client,
                        host,
                        include_subdomains=scan_subs,
                        use_cdx=True,
                        use_commoncrawl=True,
                        use_paths=False,
                        dork_tier=dork_tier,
                        **cdx_extra,
                    )
                except Exception as exc:  # noqa: BLE001
                    _append_log(db, scan, f"Dorks ({host_label}): {exc}")
                    return host, []

            if enable_dorks and dork_tier != "off":
                from app.services.dork_tiers import tier_label

                _append_log(
                    db,
                    scan,
                    f"Dorks ({tier_label(dork_tier)}): фон по {host_count} целям — не блокирует CDX",
                )
                if dork_tier == "full3652":
                    _append_log(
                        db,
                        scan,
                        "Dorks: полный набор ~3652 фильтров — может занять 30–90 мин в фоне",
                    )
                for host in hosts:
                    dork_tasks.append(asyncio.create_task(_dorks_for_host(host)))

            for i, host in enumerate(hosts):
                _check_cancel(db, scan)
                base_progress = 8 + int(24 * i / max(host_count, 1))
                scan_subs = _host_uses_domain_cdx(host, project)
                host_label = host + (" (+поддомены)" if scan_subs else "")

                if include_cc or archive_status != "online":
                    _append_log(db, scan, f"Common Crawl: {host_label}")
                    try:
                        cc, cc_note = await enumerate_commoncrawl_with_note(
                            client,
                            host,
                            include_subdomains=scan_subs,
                            limit=per_host if _max_urls_unlimited(project) else min(8000, per_host),
                        )
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"Common Crawl ({host}): {exc}")
                        cc, cc_note = [], str(exc)
                    before = len(captures)
                    for cap in cc:
                        _add(cap)
                    added = len(captures) - before
                    raw_index_total += len(cc)
                    if added:
                        _append_log(db, scan, f"Common Crawl {host}: +{added} URL ({cc_note})")
                    else:
                        hint = f" — {cc_note}" if cc else ""
                        if cc and deny_patterns:
                            hint += " · проверьте deny-regex (может резать .js/.css)"
                        _append_log(db, scan, f"Common Crawl {host}: 0 URL{hint}")
                    _touch_progress(db, scan, urls=len(captures), progress=base_progress + 2)

                if use_cdx:
                    _check_cancel(db, scan)
                    _append_log(db, scan, f"CDX waybackurls: {host_label}")
                    try:
                        wbu = await waybackurls_style(
                            client,
                            host,
                            include_subdomains=scan_subs,
                            limit=per_host,
                            date_from=project.date_from or "",
                            date_to=project.date_to or "",
                            status_200_only=not bool(getattr(project, "include_non200", False)),
                        )
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"CDX waybackurls ({host}): {exc}")
                        wbu = []
                    _ingest_caps(wbu, f"CDX waybackurls {host}")
                    _touch_progress(db, scan, urls=len(captures), progress=base_progress + 4)

                if use_cdx:
                    _check_cancel(db, scan)
                    _append_log(db, scan, f"CDX targeted: {host_label}")
                    try:
                        targeted = await targeted_cdx(
                            client,
                            host,
                            scan_subs,
                            extra_keywords=extra_kw,
                            extra_exts=extra_ext,
                            scan_scripts=scan_js,
                            **cdx_extra,
                        )
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"Ошибка targeted CDX ({host}): {exc}")
                        targeted = []
                    for cap in targeted:
                        _add(cap)
                    _touch_progress(db, scan, urls=len(captures), progress=base_progress + 8)

                    _check_cancel(db, scan)
                    _append_log(db, scan, f"CDX полный индекс: {host_label}")
                    try:
                        broad = await enumerate_cdx(
                            client,
                            host,
                            include_subdomains=scan_subs,
                            limit=per_host,
                            **cdx_extra,
                        )
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"Ошибка CDX ({host}): {exc}")
                        broad = []
                    for cap in broad:
                        _add(cap)
                    _touch_progress(db, scan, urls=len(captures), progress=base_progress + 10)

            if dork_tasks:
                _append_log(db, scan, f"Dorks: ожидание {len(dork_tasks)} фоновых задач…")
                for task in asyncio.as_completed(dork_tasks):
                    _check_cancel(db, scan)
                    host, dork_caps = await task
                    before = len(captures)
                    for cap in dork_caps:
                        dork_matched_urls.add(cap.original)
                        _add(cap)
                    raw_index_total += len(dork_caps)
                    added = len(captures) - before
                    if added:
                        _append_log(
                            db,
                            scan,
                            f"Dorks {host}: +{added} URL (всего dork-хитов: {len(dork_matched_urls)})",
                        )
                    _touch_progress(db, scan, urls=len(captures))
                _append_log(db, scan, f"Dorks завершены: {len(dork_matched_urls)} уникальных хитов")

            if not captures:
                hint = "источники не вернули URL — проверьте CDX/Common Crawl или перезапустите проход."
                if raw_index_total > 0:
                    hint = f"источники вернули {raw_index_total} URL, scope не совпал — добавьте apex в targets или включите поддомены"
                _append_log(db, scan, f"Индекс пуст. {hint}")
            else:
                _append_log(db, scan, f"Собрано URL: {len(captures)}")
                if allow_patterns:
                    match_n = sum(1 for c in captures if _passes_allow(c.original))
                    _append_log(
                        db,
                        scan,
                        f"Allow-regex: {match_n}/{len(captures)} URL попадут в находки (полный индекс во вкладке «Архив URLs»)",
                    )

            if follow_robots and use_cdx:
                robots = [c for c in captures if c.original.lower().split("?")[0].endswith("robots.txt")]
                _append_log(db, scan, f"Разбор robots.txt: {len(robots)} снимок(ов)")
                for cap in robots[:10]:
                    _check_cancel(db, scan)
                    text = await fetch_raw_snapshot(client, cap)
                    scan.snapshots_fetched += 1
                    host = max((h for h in hosts if h in cap.original.lower()), key=len, default=hosts[0])
                    robots_paths = parse_robots_paths(text or "")
                    for path in robots_paths:
                        try:
                            more = await enumerate_cdx(
                                client,
                                host,
                                include_subdomains=False,
                                limit=80,
                                url_pattern=f"{host}{path}*",
                                **cdx_extra,
                            )
                        except Exception:
                            continue
                        for item in more:
                            _add(item)
                    for path in interesting_robots_paths(robots_paths):
                        findings_acc.append(
                            Finding(
                                project_id=project.id,
                                scan_id=scan.id,
                                severity="medium",
                                category="recon",
                                title=f"robots Disallow: {path}",
                                original_url=cap.original,
                                archive_url=cap.archive_url,
                                capture_ts=cap.timestamp,
                                evidence=path,
                                pattern="robots-disallow",
                                source="robots",
                            )
                        )
                    await asyncio.sleep(settings.wayback_delay_ms / 1000)

            sitemaps = [
                c
                for c in captures
                if "sitemap" in c.original.lower() and c.original.lower().split("?")[0].endswith(".xml")
            ]
            if sitemaps:
                _append_log(db, scan, f"Разбор sitemap: {len(sitemaps)} файл(ов)")
                for cap in sitemaps[:8]:
                    _check_cancel(db, scan)
                    text = await fetch_raw_snapshot(client, cap)
                    scan.snapshots_fetched += 1
                    if not text:
                        continue
                    added_map = 0
                    for loc in parse_sitemap_locs(text):
                        loc_host = urlparse(loc).netloc.lower().split("@")[-1].split(":")[0]
                        if loc_host.startswith("www."):
                            loc_host = loc_host[4:]
                        if loc_host and not any(loc_host == h or loc_host.endswith("." + h) for h in hosts):
                            continue
                        before = len(seen_urls)
                        _add(
                            Capture(
                                original=loc,
                                timestamp=cap.timestamp,
                                status=cap.status or "200",
                                mimetype="",
                                digest="",
                                length="",
                            )
                        )
                        if len(seen_urls) > before:
                            added_map += 1
                    if added_map:
                        _append_log(db, scan, f"Sitemap {urlparse(cap.original).path}: +{added_map} URL")
                    await asyncio.sleep(settings.wayback_delay_ms / 1000)

            _touch_progress(db, scan, urls=len(captures), findings=len(findings_acc), progress=38)
            _append_log(db, scan, f"Классификация: {len(captures)} URL · dork-хитов: {len(dork_matched_urls)}")

            def _klass(url: str):
                return classify_url(url, extra_keywords=extra_kw, extra_exts=extra_ext)

            inv_n = store_url_inventory(
                db,
                project_id=project.id,
                scan_id=scan.id,
                captures=captures,
                klass_fn=_klass,
                limit=_url_inventory_limit(project, len(captures)),
            )
            _append_log(db, scan, f"URL-инвентарь: {inv_n} ссылок (вкладка «Архив URLs»)")

            inspect_queue: list[Capture] = []

            for idx, cap in enumerate(captures):
                if idx % 200 == 0:
                    _check_cancel(db, scan)
                    if idx and idx % 400 == 0:
                        _touch_progress(
                            db,
                            scan,
                            findings=len(findings_acc),
                            progress=28 + int(10 * idx / max(len(captures), 1)),
                        )
                klass = _klass(cap.original)
                for title, masked, evidence in extract_url_secrets(cap.original):
                    if not is_archived_capture(cap):
                        continue
                    findings_acc.append(
                        Finding(
                            project_id=project.id,
                            scan_id=scan.id,
                            severity="critical",
                            category="url-secret",
                            title=title,
                            original_url=cap.original,
                            archive_url=cap.archive_url,
                            capture_ts=cap.timestamp,
                            evidence=evidence,
                            masked_secret=masked,
                            pattern="url-embedded",
                            source="url",
                        )
                    )
                    inspect_queue.append(cap)
                if klass:
                    if not include_recon and klass.category == "recon":
                        if klass.pattern == "robots":
                            inspect_queue.append(cap)
                        continue
                    if allow_patterns and not _passes_allow(cap.original):
                        if SEVERITY_RANK.get(klass.severity, 0) >= 2 and is_archived_capture(cap):
                            inspect_queue.append(cap)
                        continue
                    if not is_archived_capture(cap):
                        continue
                    findings_acc.append(
                        Finding(
                            project_id=project.id,
                            scan_id=scan.id,
                            severity=klass.severity,
                            category=klass.category,
                            title=klass.title,
                            original_url=cap.original,
                            archive_url=cap.archive_url,
                            capture_ts=cap.timestamp,
                            evidence=f"mime={cap.mimetype} status={cap.status} length={cap.length}",
                            pattern=klass.pattern,
                            source="dork" if cap.original in dork_matched_urls else "path",
                        )
                    )
                    if SEVERITY_RANK.get(klass.severity, 0) >= 2 and is_archived_capture(cap):
                        inspect_queue.append(cap)
                elif scan_js and is_archived_capture(cap) and is_script_or_data(cap.original, cap.mimetype) and not is_marketing_path(cap.original):
                    lower = cap.original.lower()
                    if lower.endswith((".json", ".xml", ".txt", ".csv", ".js", ".mjs")) or any(
                        tok in lower for tok in ("config", "env", "secret", "token", "apikey", "passwd", "bundle", "app.min", "main.min")
                    ):
                        inspect_queue.append(cap)

            path_n = sum(1 for f in findings_acc if f.source == "path")
            dork_n = sum(1 for f in findings_acc if f.source == "dork")
            bbot_n = sum(1 for f in findings_acc if f.source == "bbot")
            auth_n = sum(1 for f in findings_acc if f.category == "auth-panel")
            mail_n = sum(1 for f in findings_acc if f.category == "exposed-mail")
            _append_log(
                db,
                scan,
                f"Классификация готова: path={path_n} · dork={dork_n} · bbot={bbot_n} · auth={auth_n} · mail={mail_n} · всего {len(findings_acc)}",
            )
            flushed = _flush_findings(db, findings_acc)
            if flushed:
                _touch_progress(db, scan, findings=len(findings_acc), progress=42)

            def _rank(cap: Capture) -> int:
                klass = _klass(cap.original)
                rank = SEVERITY_RANK.get(klass.severity, 0) if klass else 0
                if extract_url_secrets(cap.original):
                    rank = max(rank, 4)
                if "phpinfo" in cap.original.lower() or "allinfo.php" in cap.original.lower():
                    rank = max(rank, 5)
                return rank

            llm_cfg = _user_llm(owner) if getattr(project, "use_llm", True) else None
            llm_calls = 0
            if getattr(project, "llm_unlimited", False):
                llm_budget = 9999
            else:
                llm_budget = min(max(int(getattr(project, "llm_max_calls", 40) or 40), 1), 100)
            do_extract = bool(llm_cfg)

            if llm_cfg and llm_budget > 0:
                pool = _triage_pool(captures, _klass, limit=400)
                _append_log(db, scan, f"LLM-триаж: отбор тел снимков из {len(pool)} путей (секреты/JS/конфиги)")
                already = {canonical_url(c.original) for c in inspect_queue}
                batch_size = 80
                triage_budget = max(2, min(8, llm_budget // 2))
                for start in range(0, len(pool), batch_size):
                    if llm_calls >= triage_budget:
                        break
                    _check_cancel(db, scan)
                    chunk = pool[start : start + batch_size]
                    rows = []
                    for cap in chunk:
                        path = urlparse(unquote(cap.original)).path or cap.original
                        rows.append(f"{path} {cap.mimetype or ''}".strip())
                    try:
                        picks = await triage_urls(llm_cfg, rows)
                        llm_calls += 1
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"LLM triage ошибка: {exc}")
                        continue
                    if not picks:
                        _append_log(db, scan, f"LLM-триаж партия {start // batch_size + 1}: модель не вернула JSON — пропуск")
                        continue
                    added = 0
                    for idx, _sev, _why in picks:
                        cap = chunk[idx]
                        key = canonical_url(cap.original)
                        if key in already:
                            continue
                        already.add(key)
                        inspect_queue.append(cap)
                        added += 1
                    _append_log(db, scan, f"LLM-триаж партия {start // batch_size + 1}: в очередь разбора +{added}")

            unique_inspect: list[Capture] = []
            seen_insp: set[str] = set()
            inspect_queue.sort(key=_rank, reverse=True)
            fetch_limit = _snapshot_fetch_limit(project, len(inspect_queue), bool(llm_cfg))
            if getattr(project, "max_snapshot_fetches_unlimited", False) and inspect_queue:
                _append_log(db, scan, "Разбор снимков: безлимит — в очереди все отобранные URL")
            for cap in inspect_queue:
                key = canonical_url(cap.original)
                if key in seen_insp:
                    continue
                seen_insp.add(key)
                unique_inspect.append(cap)
                if len(unique_inspect) >= fetch_limit:
                    break

            snapshot_texts: list[tuple[Capture, str]] = []
            html_discovered: list[Capture] = []

            async def _snapshots_for_cap(cap: Capture) -> list[Capture]:
                if not multi_disclosure or not _DISCLOSURE.search(cap.original):
                    return [cap]
                try:
                    vers = await enumerate_versions(
                        client,
                        cap.original,
                        limit=4,
                        date_from=project.date_from or "",
                        date_to=project.date_to or "",
                        status_200_only=not bool(getattr(project, "include_non200", False)),
                    )
                except Exception:
                    return [cap]
                if not vers:
                    return [cap]
                seen_ts: set[str] = set()
                out: list[Capture] = []
                for item in vers:
                    if item.timestamp in seen_ts:
                        continue
                    seen_ts.add(item.timestamp)
                    out.append(item)
                return out or [cap]

            if project.inspect_snapshots and unique_inspect:
                _append_log(db, scan, f"Разбор снимков: {len(unique_inspect)} URL")
                chunk_n = 5
                for start in range(0, len(unique_inspect), chunk_n):
                    _check_cancel(db, scan)
                    chunk = unique_inspect[start : start + chunk_n]
                    expanded: list[Capture] = []
                    for cap in chunk:
                        expanded.extend(await _snapshots_for_cap(cap))
                    scan.progress = 40 + int(40 * start / max(len(unique_inspect), 1))
                    texts = await asyncio.gather(
                        *[fetch_raw_snapshot(client, cap) for cap in expanded],
                        return_exceptions=True,
                    )
                    scan.snapshots_fetched += len(expanded)
                    for cap, text in zip(expanded, texts):
                        if isinstance(text, BaseException) or not text:
                            continue
                        if is_wayback_miss_page(text):
                            continue
                        snapshot_texts.append((cap, text))
                        mime = (cap.mimetype or "").lower()
                        if detect_login_form_html(text) and (
                            "html" in mime
                            or cap.original.lower().endswith((".html", ".htm", ".php", ".asp", ".aspx"))
                        ):
                            auth_meta = classify_auth_url(cap.original)
                            findings_acc.append(
                                Finding(
                                    project_id=project.id,
                                    scan_id=scan.id,
                                    severity="medium",
                                    category="auth-panel",
                                    title=auth_meta.title if auth_meta else "Страница авторизации (форма в HTML)",
                                    original_url=cap.original,
                                    archive_url=cap.raw_archive_url,
                                    capture_ts=cap.timestamp,
                                    evidence="password-поле / форма login в архивном снимке",
                                    pattern="auth-login-form",
                                    source="snapshot-auth",
                                )
                            )
                        for hit in scan_text(text):
                            findings_acc.append(
                                Finding(
                                    project_id=project.id,
                                    scan_id=scan.id,
                                    severity=hit.severity,
                                    category="content-secret",
                                    title=hit.name,
                                    original_url=cap.original,
                                    archive_url=cap.raw_archive_url,
                                    capture_ts=cap.timestamp,
                                    evidence=hit.evidence,
                                    masked_secret=hit.masked,
                                    pattern=hit.pattern,
                                    source="snapshot",
                                )
                            )
                        osint_added = _append_osint_from_text(
                            findings_acc,
                            project_id=project.id,
                            scan_id=scan.id,
                            text=text,
                            url=cap.original,
                            archive_url=cap.raw_archive_url,
                            capture_ts=cap.timestamp,
                            source="osint",
                            hosts=hosts,
                            enable_osint=enable_osint,
                            seen=seen_osint,
                        )
                        if osint_added and scan.snapshots_fetched % 15 == 0:
                            _touch_progress(db, scan, findings=len(findings_acc))
                        if cap.original.lower().endswith((".js", ".mjs")) or "javascript" in mime:
                            for ep in extract_js_endpoints(text):
                                abs_url = urljoin(cap.original, ep)
                                klass_ep = _klass(abs_url)
                                if not klass_ep or SEVERITY_RANK.get(klass_ep.severity, 0) < 2:
                                    continue
                                findings_acc.append(
                                    Finding(
                                        project_id=project.id,
                                        scan_id=scan.id,
                                        severity=klass_ep.severity,
                                        category="js-endpoint",
                                        title=f"JS → {klass_ep.title}",
                                        original_url=abs_url,
                                        archive_url=cap.archive_url,
                                        capture_ts=cap.timestamp,
                                        evidence=f"из {cap.original}",
                                        pattern=klass_ep.pattern,
                                        source="js",
                                    )
                                )
                        if crawl_html and (
                            "html" in mime
                            or cap.original.lower().endswith((".html", ".htm", ".php", ".asp", ".aspx"))
                        ):
                            for link in extract_html_links(text, cap.original):
                                if not _in_scope(link):
                                    continue
                                if not _passes_deny(link):
                                    continue
                                cap_link = Capture(
                                    original=link,
                                    timestamp=cap.timestamp,
                                    status="200",
                                    mimetype="text/html",
                                    digest="",
                                    length="",
                                )
                                html_discovered.append(cap_link)
                                _add(cap_link)
                                klass_l = _klass(link)
                                if not klass_l:
                                    continue
                                if allow_patterns and not _passes_allow(link):
                                    continue
                                if not include_recon and klass_l.category == "recon":
                                    continue
                                if SEVERITY_RANK.get(klass_l.severity, 0) < 2:
                                    continue
                                findings_acc.append(
                                    Finding(
                                        project_id=project.id,
                                        scan_id=scan.id,
                                        severity=klass_l.severity,
                                        category=klass_l.category,
                                        title=f"HTML → {klass_l.title}",
                                        original_url=link,
                                        archive_url=cap.archive_url,
                                        capture_ts=cap.timestamp,
                                        evidence=f"ссылка из {cap.original}",
                                        pattern=klass_l.pattern,
                                        source="html-crawl",
                                    )
                                )
                    db.commit()

            if html_discovered and project.inspect_snapshots:
                extra_fetch: list[Capture] = []
                seen_html: set[str] = set()
                for cap in html_discovered:
                    key = canonical_url(cap.original)
                    if key in seen_html or key in seen_insp:
                        continue
                    seen_html.add(key)
                    klass = _klass(cap.original)
                    if klass and SEVERITY_RANK.get(klass.severity, 0) >= 2:
                        extra_fetch.append(cap)
                    if len(extra_fetch) >= 12:
                        break
                if extra_fetch:
                    _append_log(db, scan, f"Догрузка ссылок из HTML: {len(extra_fetch)} URL")
                    texts = await asyncio.gather(
                        *[fetch_raw_snapshot(client, cap) for cap in extra_fetch],
                        return_exceptions=True,
                    )
                    scan.snapshots_fetched += len(extra_fetch)
                    for cap, text in zip(extra_fetch, texts):
                        if isinstance(text, BaseException) or not text:
                            continue
                        snapshot_texts.append((cap, text))
                        for hit in scan_text(text):
                            findings_acc.append(
                                Finding(
                                    project_id=project.id,
                                    scan_id=scan.id,
                                    severity=hit.severity,
                                    category="content-secret",
                                    title=hit.name,
                                    original_url=cap.original,
                                    archive_url=cap.raw_archive_url,
                                    capture_ts=cap.timestamp,
                                    evidence=hit.evidence,
                                    masked_secret=hit.masked,
                                    pattern=hit.pattern,
                                    source="snapshot",
                                )
                            )
                    db.commit()

            if enable_osint:
                archive_osint = sum(1 for f in findings_acc if (f.category or "").startswith("osint"))
                if archive_osint:
                    _append_log(db, scan, f"OSINT (архив): email/телефон — {archive_osint}")

            if do_extract and snapshot_texts:
                llm_pool = [(c, t) for c, t in snapshot_texts if worth_llm_extract(c.original, c.mimetype)]
                skipped = len(snapshot_texts) - len(llm_pool)
                _append_log(
                    db,
                    scan,
                    f"LLM extract секретов из {len(llm_pool)} снимков (JS/конфиги/php)"
                    + (f" (пропущены: {skipped})" if skipped else ""),
                )
                already = {
                    c.original
                    for c, _ in llm_pool
                    if any(f.original_url == c.original and f.source == "snapshot" for f in findings_acc)
                }
                ordered = sorted(llm_pool, key=lambda pair: 0 if pair[0].original in already else 1)
                batch_n = 4
                llm_sem = asyncio.Semaphore(_llm_parallel_slots(llm_cfg))

                async def _extract_pack(pack: list[tuple]) -> tuple[list, list] | None:
                    async with llm_sem:
                        docs = [(c.original, t) for c, t in pack]
                        return await extract_secrets_batch(llm_cfg, docs), pack

                packs: list[list[tuple]] = []
                for start in range(0, len(ordered), batch_n):
                    if len(packs) + llm_calls >= llm_budget:
                        break
                    packs.append(ordered[start : start + batch_n])
                if packs:
                    results = await asyncio.gather(*[_extract_pack(p) for p in packs], return_exceptions=True)
                    for result in results:
                        _check_cancel(db, scan)
                        if llm_calls >= llm_budget:
                            break
                        if isinstance(result, Exception):
                            _append_log(db, scan, f"LLM extract ошибка: {result}")
                            continue
                        if not result:
                            continue
                        packed, pack = result
                        llm_calls += 1
                        for idx, hit in packed:
                            cap = pack[idx][0]
                            findings_acc.append(
                                Finding(
                                    project_id=project.id,
                                    scan_id=scan.id,
                                    severity=hit["severity"],
                                    category="llm-secret",
                                    title=f"LLM: {hit['type']}",
                                    original_url=cap.original,
                                    archive_url=cap.raw_archive_url,
                                    capture_ts=cap.timestamp,
                                    evidence=hit["context"],
                                    masked_secret=hit["masked"],
                                    pattern="llm",
                                    source="llm",
                                )
                            )
                _append_log(db, scan, f"LLM extract: вызовов {llm_calls}")

            if llm_cfg and getattr(project, "llm_review", False) and llm_calls < llm_budget:
                _check_cancel(db, scan)
                path_findings = [f for f in findings_acc if f.source == "path"]
                if path_findings:
                    _append_log(db, scan, f"LLM: переоценка {len(path_findings)} ключевых URL")
                    batch = path_findings[: min(20, llm_budget - llm_calls)]
                    rows = [
                        {
                            "severity": f.severity,
                            "title": f.title,
                            "url": f.original_url,
                            "evidence": f.evidence,
                        }
                        for f in batch
                    ]
                    try:
                        verdicts = await review_flags(llm_cfg, rows)
                        llm_calls += 1
                        drop: set[int] = set()
                        for idx, verd in verdicts.items():
                            if idx < 0 or idx >= len(batch):
                                continue
                            if not verd.get("keep"):
                                drop.add(idx)
                            else:
                                sev = verd.get("severity") or batch[idx].severity
                                if sev in SEVERITY_RANK:
                                    batch[idx].severity = sev
                                if verd.get("reason"):
                                    batch[idx].evidence = (batch[idx].evidence + " · LLM: " + verd["reason"])[:500]
                        for idx in list(drop):
                            finding = batch[idx]
                            url_low = finding.original_url.lower()
                            if finding.pattern in _LLM_REVIEW_KEEP or finding.severity == "critical":
                                drop.discard(idx)
                            elif any(
                                tok in url_low
                                for tok in (".env", "phpinfo", "allinfo.php", ".git/", "web.config", "dbconn", "credentials")
                            ):
                                drop.discard(idx)
                        if drop and len(drop) >= len(batch):
                            _append_log(db, scan, "LLM review: отклонил все — находки сохранены без изменений")
                            drop = set()
                        if drop:
                            drop_ids = {id(batch[i]) for i in drop}
                            for idx in drop:
                                finding = batch[idx]
                                if getattr(finding, "id", None):
                                    db.delete(finding)
                            findings_acc[:] = [f for f in findings_acc if id(f) not in drop_ids]
                            db.commit()
                            _append_log(db, scan, f"LLM review снял ложных: {len(drop)}")
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"LLM review ошибка: {exc}")

            _touch_progress(db, scan, findings=len(findings_acc), progress=min(82, scan.progress or 0))

            if getattr(project, "enable_live_probe", False):
                _check_cancel(db, scan)
                _append_log(db, scan, f"Live-probe: {len(hosts)} целей")
                try:
                    live_hits = await probe_live_hosts(
                        client,
                        hosts,
                        include_subdomains=project.include_subdomains,
                        max_paths=20,
                        concurrency=8 if llm_cfg else 6,
                    )
                except Exception as exc:  # noqa: BLE001
                    _append_log(db, scan, f"Live-probe ошибка: {exc}")
                    live_hits = []
                try:
                    auth_hits = await probe_auth_pages(
                        client,
                        hosts,
                        include_subdomains=project.include_subdomains,
                        concurrency=8,
                    )
                except Exception as exc:  # noqa: BLE001
                    _append_log(db, scan, f"Live auth-probe ошибка: {exc}")
                    auth_hits = []
                for hit in live_hits:
                    findings_acc.append(
                        Finding(
                            project_id=project.id,
                            scan_id=scan.id,
                            severity=hit["severity"],
                            category="live",
                            title=hit["title"],
                            original_url=hit["url"],
                            archive_url=hit["url"],
                            capture_ts="",
                            evidence=hit["evidence"],
                            masked_secret=hit.get("masked") or "",
                            pattern=hit.get("pattern") or "live",
                            source="live",
                        )
                    )
                for hit in auth_hits:
                    findings_acc.append(
                        Finding(
                            project_id=project.id,
                            scan_id=scan.id,
                            severity=hit["severity"],
                            category="auth-panel",
                            title=hit["title"],
                            original_url=hit["url"],
                            archive_url=hit["url"],
                            capture_ts="",
                            evidence=hit["evidence"],
                            masked_secret="",
                            pattern=hit.get("pattern") or "auth-login-live",
                            source="live",
                        )
                    )
                if live_hits:
                    _append_log(db, scan, f"Live-probe: {len(live_hits)} подтверждённых ответов")
                else:
                    _append_log(db, scan, "Live-probe: 0 подтверждённых (SPA/404 отфильтрованы)")
                if auth_hits:
                    _append_log(db, scan, f"Live auth: {len(auth_hits)} страниц входа")

            if getattr(project, "enable_live_crawl", False) or build_live_auth(project).active:
                _check_cancel(db, scan)
                auth = build_live_auth(project)
                crawl_hosts = select_crawl_hosts(hosts, auth)
                if auth.active and not getattr(project, "enable_live_crawl", False):
                    _append_log(db, scan, "Live-crawl: auth задан — автозапуск (включите чекбокс для явного контроля)")
                if getattr(project, "live_crawl_pages_unlimited", False):
                    max_pages = 10000
                else:
                    max_pages = min(max(int(getattr(project, "live_crawl_max_pages", 80) or 80), 1), 1000)
                if getattr(project, "live_crawl_depth_unlimited", False):
                    max_depth = 1000
                else:
                    max_depth = min(max(int(getattr(project, "live_crawl_max_depth", 3) or 3), 1), 1000)
                if not auth.active and not getattr(project, "live_crawl_depth_unlimited", False) and max_depth > 4:
                    max_depth = 4
                crawl_timeout = 1800.0 if getattr(project, "live_crawl_pages_unlimited", False) else (900.0 if auth.active else 600.0)
                pages_label = "∞" if getattr(project, "live_crawl_pages_unlimited", False) else str(max_pages)
                depth_label = "∞" if getattr(project, "live_crawl_depth_unlimited", False) else str(max_depth)
                if getattr(project, "live_crawl_rps_unlimited", False):
                    crawl_rps: float | None = None
                    rps_label = "∞"
                else:
                    crawl_rps = float(min(max(int(getattr(project, "live_crawl_rps", 30) or 30), 10), 200))
                    rps_label = str(int(crawl_rps))
                crawl_concurrency = 12 if llm_cfg else 8
                _append_log(
                    db,
                    scan,
                    f"Live-crawl: {len(crawl_hosts)} целей — полный обход каждой (до {pages_label} стр., глубина {depth_label}, RPS {rps_label}, concurrency {crawl_concurrency})",
                )

                def _crawl_progress(done: int, limit: int, url: str) -> None:
                    _touch_progress(
                        db,
                        scan,
                        findings=len(findings_acc),
                        progress=min(94, 85 + int(8 * done / max(limit, 1))),
                    )
                    if done == 1 or done % 10 == 0:
                        _append_log(db, scan, f"Live-crawl: {done}/{limit} · {url[:100]}")

                for hi, crawl_host in enumerate(crawl_hosts):
                    _check_cancel(db, scan)
                    _append_log(db, scan, f"Live-crawl [{hi + 1}/{len(crawl_hosts)}]: {crawl_host}")
                    try:
                        crawl = await asyncio.wait_for(
                            crawl_live_site(
                                client,
                                [crawl_host],
                                auth=auth,
                                include_subdomains=False,
                                max_pages=max_pages,
                                max_depth=max_depth,
                                concurrency=crawl_concurrency,
                                extra_keywords=extra_kw,
                                extra_exts=extra_ext,
                                progress_cb=_crawl_progress,
                                max_seconds=crawl_timeout,
                                enable_osint=enable_osint,
                                rps=crawl_rps,
                            ),
                            timeout=crawl_timeout + 30,
                        )
                    except asyncio.TimeoutError:
                        _append_log(db, scan, f"Live-crawl ({crawl_host}): превышен лимит {int(crawl_timeout // 60)} мин")
                        crawl = None
                    except Exception as exc:  # noqa: BLE001
                        _append_log(db, scan, f"Live-crawl ({crawl_host}) ошибка: {exc}")
                        crawl = None
                    if not crawl:
                        continue
                    if not crawl.auth_ok and not auth.active:
                        _append_log(db, scan, f"Live-crawl ({crawl_host}): 401/403 — укажите auth в настройках")
                    secret_n = 0
                    path_n = 0
                    osint_n = 0
                    for page in crawl.pages:
                        home = crawl.home_bodies.get(host_key(page.url), "")
                        hits_raw = page.secret_hits if isinstance(page.secret_hits, list) else []
                        for hit in hits_raw:
                            if not hasattr(hit, "severity"):
                                continue
                            req = page.requested_url or page.url
                            if home and bodies_match(page.text, home) and urlparse(req).path not in ("", "/"):
                                continue
                            if is_auth_redirect(req, page.url):
                                continue
                            secret_n += 1
                            findings_acc.append(
                                Finding(
                                    project_id=project.id,
                                    scan_id=scan.id,
                                    severity=hit.severity,
                                    category="content-secret",
                                    title=hit.name,
                                    original_url=page.url,
                                    archive_url=page.url,
                                    capture_ts="",
                                    evidence=hit.evidence,
                                    masked_secret=hit.masked,
                                    pattern=hit.pattern,
                                    source="live-crawl",
                                )
                            )
                        for hit in page.osint_hits:
                            if _append_osint_hit(
                                findings_acc,
                                project_id=project.id,
                                scan_id=scan.id,
                                hit=hit,
                                url=page.url,
                                archive_url=page.url,
                                capture_ts="",
                                source="live-crawl",
                                seen=seen_osint,
                            ):
                                osint_n += 1
                        klass = _klass(page.url)
                        if klass and SEVERITY_RANK.get(klass.severity, 0) >= 2:
                            home = crawl.home_bodies.get(host_key(page.url), "")
                            ok_path, why = confirm_live_path_finding(
                                page.url,
                                page.text,
                                page.content_type,
                                klass.pattern,
                                homepage_text=home,
                                requested_url=page.requested_url or page.url,
                            )
                            if not ok_path:
                                continue
                            path_n += 1
                            findings_acc.append(
                                Finding(
                                    project_id=project.id,
                                    scan_id=scan.id,
                                    severity=klass.severity,
                                    category=klass.category,
                                    title=f"Crawl: {klass.title}",
                                    original_url=page.url,
                                    archive_url=page.url,
                                    capture_ts="",
                                    evidence=format_context(page.url, why or klass.title),
                                    pattern=klass.pattern,
                                    source="live-crawl",
                                )
                            )
                    if llm_cfg and llm_calls < llm_budget:
                        llm_docs = pages_for_llm(crawl.pages, limit=min(24, max(6, llm_budget - llm_calls)))
                        if llm_docs:
                            _append_log(db, scan, f"Live-crawl LLM ({crawl_host}): {len(llm_docs)} док.")
                            batch_n = 4
                            for start in range(0, len(llm_docs), batch_n):
                                if llm_calls >= llm_budget:
                                    break
                                _check_cancel(db, scan)
                                pack = llm_docs[start : start + batch_n]
                                try:
                                    packed = await extract_live_secrets_batch(llm_cfg, pack)
                                    llm_calls += 1
                                except Exception as exc:  # noqa: BLE001
                                    _append_log(db, scan, f"Live-crawl LLM ошибка: {exc}")
                                    break
                                for idx, hit in packed:
                                    cap_url = pack[idx][0]
                                    findings_acc.append(
                                        Finding(
                                            project_id=project.id,
                                            scan_id=scan.id,
                                            severity=hit["severity"],
                                            category="llm-secret",
                                            title=f"Live LLM: {hit['type']}",
                                            original_url=cap_url,
                                            archive_url=cap_url,
                                            capture_ts="",
                                            evidence=format_context(cap_url, hit["context"], hit.get("value", "")),
                                            masked_secret=hit["masked"],
                                            pattern="live-llm",
                                            source="live-crawl",
                                        )
                                    )
                    _append_log(
                        db,
                        scan,
                        f"Live-crawl {crawl_host}: {len(crawl.pages)} стр. · JS {crawl.js_fetched} · API {crawl.api_probed} · regex {secret_n} · OSINT {osint_n} · пути {path_n}",
                    )
                    live_inv = append_live_urls(
                        db,
                        project_id=project.id,
                        scan_id=scan.id,
                        urls=crawl.urls_seen,
                        klass_fn=_klass,
                        pages=crawl.pages,
                        home_bodies=crawl.home_bodies,
                    )
                    if live_inv:
                        _append_log(db, scan, f"Live-crawl URL-инвентарь ({crawl_host}): +{live_inv}")
                    if crawl.errors:
                        _append_log(db, scan, f"Live-crawl warn ({crawl_host}): {crawl.errors[0][:120]}")

        _check_cancel(db, scan)
        scope_apexes_final = {apex_domain(h) for h in parse_targets(project.targets)}
        from app.services.project_hosts import collect_hosts_for_project

        stored = _finalize_project_findings(db, project, scan, findings_acc, scope_apexes_final)
        scan.findings_count = len(stored)
        db.commit()
        _check_cancel(db, scan)
        _append_log(db, scan, "Скриншоты архивных страниц")
        shot_n = await asyncio.to_thread(capture_findings, stored)
        scan.progress = 100
        scan.status = "done"
        scan.finished_at = datetime.now(timezone.utc)
        project.last_scan_at = scan.finished_at
        host_n = len(collect_hosts_for_project(db, project.id))
        _append_log(
            db,
            scan,
            f"Готово. Находок: {len(stored)} · хостов: {host_n} · скриншотов: {shot_n}",
        )
        db.commit()

        notify_scan_complete(owner, project, scan, stored)
    except ScanCancelled:
        stored = _store_findings(db, findings_acc)
        scan = db.get(Scan, scan_id)
        if scan:
            scan.findings_count = _count_scan_findings(db, scan.id)
            scan.status = "cancelled"
            scan.stage = "Прервано"
            scan.error = scan.error or "Остановлено пользователем"
            scan.finished_at = scan.finished_at or datetime.now(timezone.utc)
            db.commit()
        return
    except Exception as exc:  # noqa: BLE001
        if scan_id in _cancelled:
            stored = _store_findings(db, findings_acc)
            scan = db.get(Scan, scan_id)
            if scan:
                scan.findings_count = _count_scan_findings(db, scan.id)
                scan.status = "cancelled"
                scan.stage = "Прервано"
                scan.error = "Остановлено пользователем"
                scan.finished_at = datetime.now(timezone.utc)
                db.commit()
            return
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = datetime.now(timezone.utc)
            _append_log(db, scan, f"Сбой: {exc}")
            db.commit()
        raise
    finally:
        if llm_ctx_token is not None:
            unbind_llm_context(llm_ctx_token)
        _cancelled.discard(scan_id)
        db.close()
