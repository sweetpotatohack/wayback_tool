"""Dashboard report export — CSV, TXT, HTML, PDF with screenshots."""

from __future__ import annotations

import base64
import csv
import io
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import HTTPException
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from app import APP_DIR
from app.models import Finding, Project, User
from app.services.dashboard_stats import (
    PeriodFilter,
    findings_by_project,
    findings_timeline,
    severity_counts,
)
from app.services.evidence_fmt import parse_evidence_loc
from app.services.findings_dedup import dedupe_findings
from app.services.screenshots import (
    LIVE_SOURCES,
    _chrome,
    capture_one,
    full_path,
    shot_id,
    shot_urls,
)
from app.services.wayback import replay_url

_TEMPLATE = Environment(
    loader=FileSystemLoader(str(APP_DIR / "templates")),
    autoescape=select_autoescape(["html", "xml"]),
)


def _resolve_projects(db: Session, user: User, project_id: str) -> tuple[list[Project], str]:
    projects = db.query(Project).filter(Project.owner_id == user.id).order_by(Project.name).all()
    if project_id and project_id not in {"", "all"}:
        match = [p for p in projects if p.id == project_id]
        if not match:
            raise HTTPException(404, "Проект не найден")
        return match, match[0].name
    return projects, "Все проекты"


def _load_findings(db: Session, project_ids: list[str], period: PeriodFilter) -> list[Finding]:
    if not project_ids:
        return []
    q = db.query(Finding).filter(Finding.project_id.in_(project_ids))
    if period.date_from is not None:
        q = q.filter(Finding.created_at >= period.date_from)
    if period.date_to is not None:
        q = q.filter(Finding.created_at < period.date_to)
    rows = q.order_by(Finding.created_at.desc()).limit(15000).all()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(dedupe_findings(rows), key=lambda f: (order.get(f.severity, 9), f.original_url))


def _open_url_for_shot(f: Finding) -> str:
    original = (f.original_url or "").split(" → ")[0]
    source = f.source or ""
    if source in LIVE_SOURCES:
        return original
    if f.archive_url and "web.archive.org" in f.archive_url:
        return f.archive_url
    if f.capture_ts:
        return f"https://web.archive.org/web/{f.capture_ts}/{original}"
    return replay_url(original, f.capture_ts or "")


def ensure_export_screenshots(findings: list[Finding], *, limit: int = 100) -> int:
    done = 0
    for f in findings[:limit]:
        open_url = _open_url_for_shot(f)
        if not open_url:
            continue
        sid = shot_id(open_url)
        if full_path(sid).exists():
            continue
        if capture_one(open_url, f.original_url or "", f.pattern or "", f.capture_ts or "", f.source or ""):
            done += 1
    return done


def _finding_row(f: Finding, names: dict[str, str], *, embed_shot: bool) -> dict:
    loc = parse_evidence_loc(f.evidence or "")
    source = f.source or ""
    open_url = _open_url_for_shot(f)
    shots = shot_urls(f.archive_url, f.original_url, f.capture_ts or "", source=source)
    shot_b64 = ""
    if embed_shot and open_url:
        fp = full_path(shot_id(open_url))
        if fp.is_file():
            shot_b64 = base64.b64encode(fp.read_bytes()).decode("ascii")
    snippet = (loc.get("snippet") or f.evidence or "").strip()
    return {
        "project_name": names.get(f.project_id, ""),
        "severity": f.severity,
        "category": f.category or "",
        "title": f.title,
        "original_url": f.original_url,
        "open_url": open_url,
        "archive_url": f.archive_url or "",
        "capture_ts": f.capture_ts or "",
        "pattern": f.pattern or "",
        "masked_secret": f.masked_secret or "",
        "source": source,
        "evidence": f.evidence or "",
        "evidence_snippet": snippet[:1200],
        "evidence_file": loc.get("file") or "",
        "evidence_line": loc.get("line") or "",
        "evidence_col": loc.get("col") or "",
        "created_at": f.created_at.strftime("%d.%m.%Y %H:%M") if f.created_at else "",
        "shot_url": shots.get("shot_url") or "",
        "shot_b64": shot_b64,
        "has_shot": bool(shot_b64),
    }


def build_export_bundle(
    db: Session,
    user: User,
    period: PeriodFilter,
    *,
    project_id: str = "all",
    with_screenshots: bool = False,
) -> dict:
    projects, scope_label = _resolve_projects(db, user, project_id)
    scope_ids = [p.id for p in projects]
    names = {p.id: p.name for p in projects}
    sev = severity_counts(db, scope_ids, period)
    timeline = findings_timeline(db, scope_ids, period)
    if len(scope_ids) == 1:
        by_project = [{"id": scope_ids[0], "name": scope_label, "total": sum(sev.values()), "counts": sev}]
    else:
        by_project = [row for row in findings_by_project(db, user, period) if row["id"] in scope_ids]

    raw_findings = _load_findings(db, scope_ids, period)
    shots_captured = 0
    if with_screenshots and raw_findings:
        shots_captured = ensure_export_screenshots(raw_findings, limit=120)

    findings_rows = [
        _finding_row(f, names, embed_shot=with_screenshots) for f in raw_findings
    ]

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC"),
        "period_label": period.label,
        "period_mode": period.mode,
        "scope_label": scope_label,
        "user_name": user.display_name or user.username,
        "sev": sev,
        "total_findings": sum(sev.values()),
        "timeline": timeline,
        "by_project": by_project,
        "findings": findings_rows,
        "findings_export_count": len(findings_rows),
        "shots_in_report": sum(1 for row in findings_rows if row["has_shot"]),
        "shots_captured": shots_captured,
        "projects": [{"id": p.id, "name": p.name, "targets": p.targets or ""} for p in projects],
    }


def export_filename(bundle: dict, ext: str) -> str:
    scope = bundle["scope_label"].replace("/", "-").replace('"', "")[:40]
    period = bundle["period_label"].replace("/", "-").replace(" ", "_")[:30]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"ghostindex-{scope}-{period}-{stamp}.{ext}"


def render_csv(bundle: dict) -> bytes:
    buf = io.StringIO()
    buf.write("\ufeff")
    writer = csv.writer(buf)
    writer.writerow(
        [
            "project",
            "severity",
            "category",
            "title",
            "original_url",
            "open_url",
            "archive_url",
            "capture_ts",
            "pattern",
            "masked",
            "source",
            "created_at",
            "file",
            "line",
            "col",
            "evidence",
            "screenshot",
        ]
    )
    for row in bundle["findings"]:
        writer.writerow(
            [
                row["project_name"],
                row["severity"],
                row["category"],
                row["title"],
                row["original_url"],
                row["open_url"],
                row["archive_url"],
                row["capture_ts"],
                row["pattern"],
                row["masked_secret"],
                row["source"],
                row["created_at"],
                row["evidence_file"],
                row["evidence_line"],
                row["evidence_col"],
                row["evidence"],
                row["shot_url"],
            ]
        )
    return buf.getvalue().encode("utf-8")


def render_txt(bundle: dict) -> bytes:
    lines = [
        "GHOSTINDEX — СВОДКА БЮРО",
        "=" * 56,
        f"Сформировано: {bundle['generated_at']}",
        f"Архивариус: {bundle['user_name']}",
        f"Период: {bundle['period_label']}",
        f"Охват: {bundle['scope_label']}",
        f"Находок в отчёте: {bundle['findings_export_count']}",
        "",
        "СВОДКА ПО SEVERITY",
        "-" * 56,
    ]
    for key in ("critical", "high", "medium", "low", "info"):
        lines.append(f"  {key:8} {bundle['sev'].get(key, 0)}")
    lines.append(f"  {'ИТОГО':8} {bundle['total_findings']}")
    lines.append("")
    if bundle["by_project"]:
        lines.append("ПО ПРОЕКТАМ")
        lines.append("-" * 56)
        for row in bundle["by_project"]:
            lines.append(f"  {row['name']}: {row['total']}")
        lines.append("")
    lines.append("НАХОДКИ")
    lines.append("-" * 56)
    if not bundle["findings"]:
        lines.append("  (нет записей за период)")
    for row in bundle["findings"]:
        lines.append("")
        lines.append(f"[{row['severity'].upper()}] {row['title']}")
        if row["project_name"]:
            lines.append(f"  Проект: {row['project_name']}")
        lines.append(f"  URL: {row['original_url']}")
        if row["open_url"] and row["open_url"] != row["original_url"]:
            lines.append(f"  Открыть: {row['open_url']}")
        if row["category"]:
            lines.append(f"  Категория: {row['category']}")
        if row["pattern"]:
            lines.append(f"  Pattern: {row['pattern']} · {row['source']}")
        if row["masked_secret"]:
            lines.append(f"  Значение: {row['masked_secret']}")
        if row["evidence_snippet"]:
            ev = row["evidence_snippet"].replace("\n", " ")[:500]
            lines.append(f"  Описание: {ev}")
        if row["shot_url"]:
            lines.append(f"  Скриншот: {row['shot_url']}")
    lines.append("")
    lines.append("— конец дела —")
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_html(bundle: dict) -> str:
    tpl = _TEMPLATE.get_template("export_report.html")
    return tpl.render(**bundle)


def render_pdf(bundle: dict) -> bytes:
    html = render_html(bundle)
    chrome = _chrome()
    if not chrome:
        raise HTTPException(
            503,
            "PDF недоступен: установите chromium или google-chrome (apt install chromium)",
        )
    html_path = ""
    pdf_path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as fh:
            fh.write(html)
            html_path = fh.name
        pdf_path = html_path.replace(".html", ".pdf")
        subprocess.run(
            [
                chrome,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--run-all-compositor-stages-before-draw",
                f"--print-to-pdf={pdf_path}",
                html_path,
            ],
            check=True,
            timeout=120,
            capture_output=True,
        )
        data = Path(pdf_path).read_bytes()
        if len(data) < 500:
            raise HTTPException(503, "PDF не сформирован")
        return data
    except subprocess.CalledProcessError as exc:
        err = exc.stderr.decode("utf-8", errors="replace")[:240]
        raise HTTPException(503, f"PDF ошибка: {err}") from exc
    finally:
        if html_path:
            Path(html_path).unlink(missing_ok=True)
        if pdf_path:
            Path(pdf_path).unlink(missing_ok=True)


def content_disposition(filename: str) -> str:
    safe = quote(filename)
    return f"attachment; filename*=UTF-8''{safe}"
