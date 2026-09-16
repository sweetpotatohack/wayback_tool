from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import require_user
from app.models import ArchiveUrl, Finding, Project, Scan, User
from app.schemas import ProjectIn, ScheduleIn
from app.services.findings_dedup import dedupe_findings as _dedupe_findings
from app.services.evidence_fmt import parse_evidence_loc
from app.services.inventory import mime_summary, url_archive_link, url_open_link
from app.services.bbot import lookup_gowitness_shot
from app.services.finding_display import (
    display_evidence,
    display_meta_tags,
    display_resource_url,
    display_title,
    is_hidden_finding,
)
from app.services.screenshots import shot_urls
from app.services.netway import build_netway_graph
from app.services.dork_tiers import ALLOWED_DORK_TIERS, normalize_dork_tier, tier_label
from app.services.scheduler import sync_project_schedule
from app.services.scanner import enqueue_scan, request_abort
from app.services.schedule_config import (
    dump_schedule_config,
    legacy_schedule_to_config,
    schedule_config_for_project,
    schedule_summary,
    validate_schedule_json,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])

ALLOWED_SCHEDULES = {"off", "hourly", "every_6h", "daily", "weekly", "custom"}

PROJECT_FIELDS = (
    "name",
    "description",
    "targets",
    "include_subdomains",
    "inspect_snapshots",
    "max_urls",
    "max_urls_unlimited",
    "max_snapshot_fetches",
    "max_snapshot_fetches_unlimited",
    "date_from",
    "date_to",
    "extra_keywords",
    "extra_extensions",
    "scan_javascript",
    "follow_robots",
    "include_non200",
    "include_recon",
    "use_llm",
    "llm_extract",
    "llm_review",
    "llm_max_calls",
    "llm_unlimited",
    "url_allow_pattern",
    "url_deny_pattern",
    "include_commoncrawl",
    "crawl_html_links",
    "multi_snapshot_disclosure",
    "enable_dorks",
    "dork_tier",
    "enable_live_probe",
    "enable_live_crawl",
    "enable_osint",
    "enable_bbot",
    "bbot_allow_deadly",
    "live_auth_type",
    "live_auth_user",
    "live_auth_pass",
    "live_auth_cookie",
    "live_auth_header",
    "live_crawl_max_pages",
    "live_crawl_max_depth",
    "live_crawl_pages_unlimited",
    "live_crawl_depth_unlimited",
    "live_crawl_rps",
    "live_crawl_rps_unlimited",
)


def _apply_schedule(project: Project, payload: ProjectIn) -> None:
    raw = (getattr(payload, "schedule_json", "") or "").strip()
    if raw:
        cfg, err = validate_schedule_json(raw)
        if err:
            raise HTTPException(400, err)
        project.schedule_json = dump_schedule_config(cfg)
        project.schedule = "custom" if cfg.get("enabled") else "off"
        return
    legacy = (payload.schedule or "off").strip()
    if legacy not in ALLOWED_SCHEDULES:
        legacy = "off"
    if legacy != "off":
        cfg = legacy_schedule_to_config(legacy)
        project.schedule_json = dump_schedule_config(cfg)
        project.schedule = legacy if legacy != "custom" else "custom"
    else:
        project.schedule_json = ""
        project.schedule = "off"


def _apply_project(project: Project, payload: ProjectIn) -> None:
    keep_pass = not (payload.live_auth_pass or "").strip()
    for field in PROJECT_FIELDS:
        if field == "live_auth_pass" and keep_pass and getattr(project, "live_auth_pass", ""):
            continue
        value = getattr(payload, field)
        if field in {
            "name",
            "description",
            "targets",
            "date_from",
            "date_to",
            "extra_keywords",
            "extra_extensions",
            "url_allow_pattern",
            "url_deny_pattern",
            "live_auth_user",
            "live_auth_cookie",
            "live_auth_header",
        }:
            value = (value or "").strip()
        if field == "live_auth_type":
            value = (value or "none").strip().lower()
            if value not in {"none", "basic", "cookie", "header"}:
                value = "none"
        if field == "dork_tier":
            value = normalize_dork_tier(str(value or ""), enable_dorks=bool(getattr(payload, "enable_dorks", True)))
            if value not in ALLOWED_DORK_TIERS:
                value = "stable500"
        setattr(project, field, value)
    project.enable_dorks = normalize_dork_tier(project.dork_tier) != "off"
    if not project.authorized:
        project.bbot_allow_deadly = False
    _apply_schedule(project, payload)


def _schedule_dict(p: Project) -> dict:
    cfg = schedule_config_for_project(p)
    return {
        "schedule": p.schedule,
        "schedule_json": cfg,
        "schedule_summary": schedule_summary(cfg),
    }


def _project_auth_dict(p: Project) -> dict:
    return {
        "enable_live_crawl": bool(getattr(p, "enable_live_crawl", False)),
        "live_auth_type": getattr(p, "live_auth_type", "") or "none",
        "live_auth_user": getattr(p, "live_auth_user", "") or "",
        "live_auth_pass_set": bool(getattr(p, "live_auth_pass", "")),
        "live_auth_cookie": getattr(p, "live_auth_cookie", "") or "",
        "live_auth_header": getattr(p, "live_auth_header", "") or "",
        "live_crawl_max_pages": int(getattr(p, "live_crawl_max_pages", 80) or 80),
        "live_crawl_max_depth": int(getattr(p, "live_crawl_max_depth", 3) or 3),
        "live_crawl_pages_unlimited": bool(getattr(p, "live_crawl_pages_unlimited", False)),
        "live_crawl_depth_unlimited": bool(getattr(p, "live_crawl_depth_unlimited", False)),
        "live_crawl_rps": int(getattr(p, "live_crawl_rps", 30) or 30),
        "live_crawl_rps_unlimited": bool(getattr(p, "live_crawl_rps_unlimited", False)),
    }


def _owned(db: Session, user: User, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(404, "Проект не найден")
    return project


def _counts(db: Session, project_id: str) -> dict[str, int]:
    rows = db.query(Finding).filter(Finding.project_id == project_id).all()
    data = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for item in _dedupe_findings(rows):
        if item.severity in data:
            data[item.severity] += 1
    return data


@router.get("")
def list_projects(user: User = Depends(require_user), db: Session = Depends(get_db)):
    projects = (
        db.query(Project).filter(Project.owner_id == user.id).order_by(Project.updated_at.desc()).all()
    )
    out = []
    for p in projects:
        last = (
            db.query(Scan)
            .filter(Scan.project_id == p.id)
            .order_by(Scan.created_at.desc())
            .first()
        )
        out.append(
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "targets": p.targets,
                "schedule": p.schedule,
                "last_scan_at": _iso(p.last_scan_at),
                "last_status": last.status if last else None,
                "counts": _counts(db, p.id),
            }
        )
    return out


@router.post("")
def create_project(payload: ProjectIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not payload.authorized:
        raise HTTPException(400, "Нужно подтвердить наличие разрешения на оценку целей")
    project = Project(owner_id=user.id, authorized=True)
    _apply_project(project, payload)
    db.add(project)
    db.commit()
    db.refresh(project)
    sync_project_schedule(project)
    return {"id": project.id}


@router.get("/{project_id}")
def get_project(project_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = _owned(db, user, project_id)
    last = db.query(Scan).filter(Scan.project_id == p.id).order_by(Scan.created_at.desc()).first()
    from app.services.project_hosts import ensure_subdomain_findings, sync_project_hosts

    sync_project_hosts(db, p.id)
    ensure_subdomain_findings(db, p.id)
    raw_findings = (
        db.query(Finding)
        .filter(Finding.project_id == p.id)
        .order_by(Finding.created_at.desc())
        .limit(3000)
        .all()
    )
    findings = _dedupe_findings([f for f in raw_findings if not is_hidden_finding(f)])[:1000]
    scans = (
        db.query(Scan).filter(Scan.project_id == p.id).order_by(Scan.created_at.desc()).limit(20).all()
    )
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "targets": p.targets,
        "include_subdomains": p.include_subdomains,
        "inspect_snapshots": p.inspect_snapshots,
        "max_urls": p.max_urls,
        "max_urls_unlimited": bool(getattr(p, "max_urls_unlimited", False)),
        "max_snapshot_fetches": p.max_snapshot_fetches,
        "max_snapshot_fetches_unlimited": bool(getattr(p, "max_snapshot_fetches_unlimited", False)),
        "date_from": p.date_from,
        "date_to": p.date_to,
        "extra_keywords": p.extra_keywords,
        "extra_extensions": p.extra_extensions,
        "scan_javascript": p.scan_javascript,
        "follow_robots": p.follow_robots,
        "include_non200": p.include_non200,
        "include_recon": p.include_recon,
        "use_llm": p.use_llm,
        "llm_extract": p.llm_extract,
        "llm_review": p.llm_review,
        "llm_max_calls": p.llm_max_calls,
        "llm_unlimited": bool(getattr(p, "llm_unlimited", False)),
        "url_allow_pattern": getattr(p, "url_allow_pattern", "") or "",
        "url_deny_pattern": getattr(p, "url_deny_pattern", "") or "",
        "include_commoncrawl": bool(getattr(p, "include_commoncrawl", False)),
        "crawl_html_links": bool(getattr(p, "crawl_html_links", True)),
        "multi_snapshot_disclosure": bool(getattr(p, "multi_snapshot_disclosure", True)),
        "enable_dorks": bool(getattr(p, "enable_dorks", True)),
        "dork_tier": normalize_dork_tier(getattr(p, "dork_tier", ""), enable_dorks=getattr(p, "enable_dorks", True)),
        "dork_tier_label": tier_label(normalize_dork_tier(getattr(p, "dork_tier", ""), enable_dorks=getattr(p, "enable_dorks", True))),
        "enable_live_probe": bool(getattr(p, "enable_live_probe", False)),
        "enable_bbot": bool(getattr(p, "enable_bbot", False)),
        "bbot_allow_deadly": bool(getattr(p, "bbot_allow_deadly", False)),
        **_project_auth_dict(p),
        **_schedule_dict(p),
        "url_inventory_count": db.query(ArchiveUrl).filter(ArchiveUrl.project_id == p.id).count(),
        "mime_summary": mime_summary(db, p.id),
        "last_scan_at": _iso(p.last_scan_at),
        "counts": _counts(db, p.id),
        "last_scan": _scan_dict(last) if last else None,
        "scans": [_scan_dict(s) for s in scans],
        "findings": [_finding_dict(f) for f in findings],
    }


@router.put("/{project_id}")
def update_project(
    project_id: str,
    payload: ProjectIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    p = _owned(db, user, project_id)
    _apply_project(p, payload)
    p.updated_at = datetime.now(timezone.utc)
    db.commit()
    sync_project_schedule(p)
    return {"ok": True}


@router.post("/{project_id}/schedule")
def set_schedule(
    project_id: str,
    payload: ScheduleIn,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    p = _owned(db, user, project_id)
    cfg, err = validate_schedule_json(payload.schedule_json)
    if err:
        raise HTTPException(400, err)
    p.schedule_json = dump_schedule_config(cfg)
    p.schedule = "custom" if cfg.get("enabled") else "off"
    db.commit()
    sync_project_schedule(p)
    return {"ok": True, "schedule_summary": schedule_summary(cfg), "schedule_json": cfg}


@router.delete("/{project_id}")
def delete_project(project_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = _owned(db, user, project_id)
    p.schedule = "off"
    p.schedule_json = ""
    db.commit()
    sync_project_schedule(p)
    db.delete(p)
    db.commit()
    return {"ok": True}


@router.post("/{project_id}/scan")
def start_scan(project_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = _owned(db, user, project_id)
    running = (
        db.query(Scan)
        .filter(Scan.project_id == p.id, Scan.status.in_(["queued", "running"]))
        .first()
    )
    if running:
        return {"id": running.id, "status": running.status, "already": True}
    scan = enqueue_scan(db, p)
    return {"id": scan.id, "status": scan.status}


@router.post("/{project_id}/abort")
def abort_scan(project_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = _owned(db, user, project_id)
    running = (
        db.query(Scan)
        .filter(Scan.project_id == p.id, Scan.status.in_(["queued", "running"]))
        .first()
    )
    if not running:
        raise HTTPException(409, "Нет активного прохода")
    scan = request_abort(db, running)
    return {"id": scan.id, "status": scan.status}


@router.get("/{project_id}/export.csv")
def export_csv(project_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = _owned(db, user, project_id)
    findings = _dedupe_findings(db.query(Finding).filter(Finding.project_id == p.id).all())
    lines = ["\ufeffseverity,category,title,original_url,archive_url,capture_ts,pattern,masked,source,file,line,col,evidence"]

    def cell(v: str) -> str:
        return '"' + (v or "").replace('"', '""').replace("\r", " ").replace("\n", " ") + '"'

    for f in findings:
        loc = parse_evidence_loc(f.evidence or "")
        lines.append(
            ",".join(
                [
                    f.severity,
                    cell(f.category),
                    cell(f.title),
                    cell(f.original_url),
                    cell(f.archive_url),
                    f.capture_ts or "",
                    f.pattern or "",
                    cell(f.masked_secret),
                    f.source or "",
                    cell(loc.get("file", "")),
                    loc.get("line", ""),
                    loc.get("col", ""),
                    cell(f.evidence),
                ]
            )
        )
    body = "\n".join(lines) + "\n"
    safe = quote(f"{p.name}-findings.csv")
    return StreamingResponse(
        iter([body.encode("utf-8")]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{safe}"},
    )


@router.get("/{project_id}/urls/export.csv")
def export_urls_csv(project_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = _owned(db, user, project_id)
    rows = (
        db.query(ArchiveUrl)
        .filter(ArchiveUrl.project_id == p.id)
        .order_by(ArchiveUrl.interesting.desc(), ArchiveUrl.original_url.asc())
        .limit(20000)
        .all()
    )
    lines = ["\ufeffurl,capture_ts,mimetype,status,source,candidate,interesting,pattern"]

    def cell(v: str) -> str:
        return '"' + (v or "").replace('"', '""').replace("\r", " ").replace("\n", " ") + '"'

    for row in rows:
        lines.append(
            ",".join(
                [
                    cell(row.original_url),
                    row.capture_ts or "",
                    cell(row.mimetype),
                    row.status or "",
                    row.source or "",
                    "yes" if row.candidate else "no",
                    "yes" if row.interesting else "no",
                    row.pattern or "",
                ]
            )
        )
    body = "\n".join(lines) + "\n"
    safe = quote(f"{p.name}-urls.csv")
    return StreamingResponse(
        iter([body.encode("utf-8")]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{safe}"},
    )


@router.get("/{project_id}/urls")
def list_urls(
    project_id: str,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    q: str = Query("", max_length=200),
    mime: str = Query("", max_length=80),
    interesting: bool | None = Query(None),
    archived_only: bool = Query(False),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
):
    p = _owned(db, user, project_id)
    query = db.query(ArchiveUrl).filter(ArchiveUrl.project_id == p.id)
    if q.strip():
        like = f"%{q.strip().lower()}%"
        query = query.filter(ArchiveUrl.original_url.ilike(like))
    if mime.strip():
        query = query.filter(ArchiveUrl.mimetype.ilike(f"%{mime.strip()}%"))
    if interesting is True:
        query = query.filter(ArchiveUrl.interesting.is_(True))
    if archived_only:
        query = query.filter(ArchiveUrl.candidate.is_(False))
    total = query.count()
    rows = (
        query.order_by(ArchiveUrl.interesting.desc(), ArchiveUrl.capture_ts.desc(), ArchiveUrl.original_url.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": row.id,
                "url": row.original_url,
                "capture_ts": row.capture_ts,
                "mimetype": row.mimetype,
                "status": row.status,
                "source": row.source,
                "candidate": row.candidate,
                "interesting": row.interesting,
                "pattern": row.pattern,
                "open_url": url_open_link(row),
                "archive_url": url_archive_link(row),
            }
            for row in rows
        ],
    }


@router.get("/{project_id}/netway")
def netway_graph(project_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    p = _owned(db, user, project_id)
    findings = _dedupe_findings(
        [f for f in db.query(Finding).filter(Finding.project_id == p.id).order_by(Finding.created_at.desc()).limit(5000).all()
         if not is_hidden_finding(f)]
    )
    archive_rows = (
        db.query(ArchiveUrl)
        .filter(ArchiveUrl.project_id == p.id)
        .order_by(ArchiveUrl.interesting.desc(), ArchiveUrl.capture_ts.desc())
        .limit(8000)
        .all()
    )
    from app.models import ProjectHost
    from app.services.project_hosts import sync_project_hosts, ensure_subdomain_findings

    host_n = sync_project_hosts(db, p.id)
    ensure_subdomain_findings(db, p.id)
    project_hosts = db.query(ProjectHost).filter(ProjectHost.project_id == p.id).all()
    graph = build_netway_graph(p, findings, archive_rows, project_hosts)
    graph["project"] = {"id": p.id, "name": p.name, "targets": p.targets}
    graph["counts"]["hosts_synced"] = host_n
    return graph


def _iso(value) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _scan_dict(s: Scan) -> dict:
    return {
        "id": s.id,
        "status": s.status,
        "progress": s.progress,
        "stage": s.stage,
        "log": s.log,
        "urls_seen": s.urls_seen,
        "snapshots_fetched": s.snapshots_fetched,
        "findings_count": s.findings_count,
        "error": s.error,
        "started_at": _iso(s.started_at),
        "finished_at": _iso(s.finished_at),
        "created_at": _iso(s.created_at),
    }


def _finding_dict(f: Finding) -> dict:
    source = getattr(f, "source", "") or ""
    open_url = f.original_url
    if " → " in open_url:
        open_url = open_url.split(" → ", 1)[0]
    resource_href, resource_label, resource_kind = display_resource_url(f)
    title = display_title(f.title or "")
    if source in {"live", "live-crawl", "bbot"}:
        link_url = resource_href or (open_url if open_url.startswith(("http://", "https://")) else "")
        archive_link = ""
        live_kind = resource_kind if resource_kind in {"http", "mailto"} else ("http" if link_url else "text")
    else:
        link_url = f.archive_url or resource_href or open_url
        archive_link = f.archive_url or ""
        live_kind = ""
    shots = shot_urls(link_url or archive_link, open_url, f.capture_ts or "", source=source)
    if not shots.get("thumb_url") and f.scan_id and link_url.startswith(("http://", "https://")):
        gw = lookup_gowitness_shot(f.scan_id, link_url)
        if gw.get("thumb_url"):
            shots = gw
    loc = parse_evidence_loc(f.evidence or "")
    email_value = ""
    if (f.category or "") == "bbot-email" and title.lower().startswith("email:"):
        email_value = title.split(":", 1)[-1].strip()
    return {
        "id": f.id,
        "severity": f.severity,
        "category": f.category,
        "title": title,
        "original_url": resource_label or title,
        "open_url": open_url,
        "resource_href": resource_href,
        "resource_kind": resource_kind or live_kind or "text",
        "archive_url": archive_link or f.archive_url,
        "capture_ts": f.capture_ts,
        "evidence": display_evidence(f.evidence or "", category=f.category or ""),
        "evidence_file": loc.get("file") or "",
        "evidence_line": loc.get("line") or "",
        "evidence_col": loc.get("col") or "",
        "evidence_snippet": loc.get("snippet") or display_evidence(f.evidence or "", category=f.category or ""),
        "masked_secret": email_value or f.masked_secret,
        "pattern": f.pattern,
        "meta": display_meta_tags(f),
        "source": f.source,
        "created_at": _iso(f.created_at),
        "thumb_url": shots["thumb_url"],
        "shot_url": shots["shot_url"],
    }
