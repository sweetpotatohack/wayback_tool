"""Dashboard aggregates: severity, timeline, scan status, period filters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Finding, Project, Scan, User

SEVERITIES = ("critical", "high", "medium", "low", "info")
LIVE_STATUSES = frozenset({"queued", "running"})


@dataclass(frozen=True)
class PeriodFilter:
    mode: str
    date_from: datetime | None
    date_to: datetime | None
    label: str


def _parse_date(raw: str) -> date | None:
    text = (raw or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%Y%m%d"):
        try:
            return datetime.strptime(text[:10], fmt).date()
        except ValueError:
            continue
    return None


def _day_bounds(day: date) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time.min, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return start, end


def parse_period(
    mode: str = "all",
    *,
    date: str = "",
    date_from: str = "",
    date_to: str = "",
) -> PeriodFilter:
    normalized = (mode or "all").strip().lower()
    if normalized not in {"all", "range", "day"}:
        normalized = "all"

    if normalized == "day":
        picked = _parse_date(date) or datetime.now(timezone.utc).date()
        start, end = _day_bounds(picked)
        return PeriodFilter(
            mode="day",
            date_from=start,
            date_to=end,
            label=picked.strftime("%d.%m.%Y"),
        )

    if normalized == "range":
        start_day = _parse_date(date_from)
        end_day = _parse_date(date_to) or start_day
        if not start_day:
            start_day = datetime.now(timezone.utc).date() - timedelta(days=30)
        if not end_day:
            end_day = start_day
        if end_day < start_day:
            start_day, end_day = end_day, start_day
        start = datetime.combine(start_day, time.min, tzinfo=timezone.utc)
        end = datetime.combine(end_day, time.min, tzinfo=timezone.utc) + timedelta(days=1)
        return PeriodFilter(
            mode="range",
            date_from=start,
            date_to=end,
            label=f"{start_day.strftime('%d.%m.%Y')} — {end_day.strftime('%d.%m.%Y')}",
        )

    return PeriodFilter(mode="all", date_from=None, date_to=None, label="Всё время")


def _project_ids(db: Session, user: User) -> list[str]:
    return [p.id for p in db.query(Project.id).filter(Project.owner_id == user.id).all()]


def _findings_query(db: Session, project_ids: list[str], period: PeriodFilter):
    q = db.query(Finding).filter(Finding.project_id.in_(project_ids))
    if period.date_from is not None:
        q = q.filter(Finding.created_at >= period.date_from)
    if period.date_to is not None:
        q = q.filter(Finding.created_at < period.date_to)
    return q


def severity_counts(db: Session, project_ids: list[str], period: PeriodFilter) -> dict[str, int]:
    counts = {k: 0 for k in SEVERITIES}
    if not project_ids:
        return counts
    rows = (
        _findings_query(db, project_ids, period)
        .with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )
    for sev, n in rows:
        if sev in counts:
            counts[sev] = int(n)
    return counts


def scans_running(db: Session, user: User) -> int:
    return (
        db.query(Scan)
        .join(Project, Scan.project_id == Project.id)
        .filter(Project.owner_id == user.id, Scan.status.in_(tuple(LIVE_STATUSES)))
        .count()
    )


def scans_completed_in_period(db: Session, user: User, period: PeriodFilter) -> int:
    q = (
        db.query(Scan)
        .join(Project, Scan.project_id == Project.id)
        .filter(Project.owner_id == user.id, Scan.status == "done")
    )
    if period.date_from is not None:
        q = q.filter(Scan.finished_at >= period.date_from)
    if period.date_to is not None:
        q = q.filter(Scan.finished_at < period.date_to)
    return q.count()


def _scan_dict(scan: Scan | None) -> dict | None:
    if not scan:
        return None
    return {
        "id": scan.id,
        "status": scan.status,
        "progress": int(scan.progress or 0),
        "stage": scan.stage or scan.status,
        "urls_seen": int(scan.urls_seen or 0),
        "findings_count": int(scan.findings_count or 0),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    }


def project_cards(db: Session, user: User, period: PeriodFilter) -> list[dict]:
    projects = db.query(Project).filter(Project.owner_id == user.id).order_by(Project.updated_at.desc()).all()
    cards: list[dict] = []
    for p in projects:
        counts = severity_counts(db, [p.id], period)
        active = (
            db.query(Scan)
            .filter(Scan.project_id == p.id, Scan.status.in_(tuple(LIVE_STATUSES)))
            .order_by(Scan.created_at.desc())
            .first()
        )
        last = db.query(Scan).filter(Scan.project_id == p.id).order_by(Scan.created_at.desc()).first()
        cards.append(
            {
                "id": p.id,
                "name": p.name,
                "description": p.description or "",
                "schedule": p.schedule or "off",
                "last_scan_at": p.last_scan_at.isoformat() if p.last_scan_at else None,
                "last_scan_label": p.last_scan_at.strftime("%d.%m.%Y %H:%M") if p.last_scan_at else None,
                "counts": counts,
                "active_scan": _scan_dict(active),
                "last_scan": _scan_dict(last),
            }
        )
    return cards


def findings_timeline(db: Session, project_ids: list[str], period: PeriodFilter) -> list[dict]:
    if not project_ids:
        return []

    chart_period = period
    if period.mode == "all":
        end_day = datetime.now(timezone.utc).date()
        start_day = end_day - timedelta(days=29)
        chart_period = parse_period(
            "range",
            date_from=start_day.strftime("%Y-%m-%d"),
            date_to=end_day.strftime("%Y-%m-%d"),
        )

    if chart_period.mode == "day" and chart_period.date_from:
        bucket = func.strftime("%H", Finding.created_at)
        label_fmt = "hour"
    else:
        bucket = func.date(Finding.created_at)
        label_fmt = "day"

    rows = (
        _findings_query(db, project_ids, chart_period)
        .with_entities(bucket.label("bucket"), Finding.severity, func.count(Finding.id))
        .group_by("bucket", Finding.severity)
        .order_by("bucket")
        .all()
    )

    buckets: dict[str, dict] = {}
    for b, sev, n in rows:
        key = str(b or "")
        if key not in buckets:
            buckets[key] = {"label": key, "total": 0, **{s: 0 for s in SEVERITIES}}
        buckets[key][sev if sev in SEVERITIES else "info"] = int(n)
        buckets[key]["total"] += int(n)

    if label_fmt == "hour" and chart_period.date_from:
        day = chart_period.date_from.date()
        out: list[dict] = []
        for hour in range(24):
            key = f"{hour:02d}"
            item = buckets.get(key) or buckets.get(str(hour)) or {"label": key, "total": 0, **{s: 0 for s in SEVERITIES}}
            item = {**item, "label": f"{hour:02d}:00", "total": item.get("total", 0)}
            for s in SEVERITIES:
                item.setdefault(s, 0)
            out.append(item)
        return out

    if label_fmt == "day" and chart_period.date_from and chart_period.date_to:
        start_day = chart_period.date_from.date()
        end_day = chart_period.date_to.date() - timedelta(days=1)
        if end_day < start_day:
            end_day = start_day
        out = []
        cursor = start_day
        while cursor <= end_day:
            key = cursor.isoformat()
            item = buckets.get(key, {"label": key, "total": 0, **{s: 0 for s in SEVERITIES}})
            item = {
                "label": cursor.strftime("%d.%m"),
                "total": int(item.get("total") or 0),
                **{s: int(item.get(s) or 0) for s in SEVERITIES},
            }
            out.append(item)
            cursor += timedelta(days=1)
        return out

    out = list(buckets.values())
    for item in out:
        if label_fmt == "hour":
            try:
                item["label"] = f"{int(item['label']):02d}:00"
            except (ValueError, TypeError):
                pass
        else:
            try:
                d = datetime.strptime(str(item["label"])[:10], "%Y-%m-%d").date()
                item["label"] = d.strftime("%d.%m")
            except ValueError:
                pass
    return out


def findings_by_project(db: Session, user: User, period: PeriodFilter) -> list[dict]:
    projects = db.query(Project).filter(Project.owner_id == user.id).order_by(Project.name).all()
    out: list[dict] = []
    for p in projects:
        counts = severity_counts(db, [p.id], period)
        total = sum(counts.values())
        if total <= 0 and period.mode != "all":
            continue
        out.append({"id": p.id, "name": p.name, "total": total, "counts": counts})
    out.sort(key=lambda x: x["total"], reverse=True)
    return out


def dashboard_payload(db: Session, user: User, period: PeriodFilter) -> dict:
    project_ids = _project_ids(db, user)
    sev = severity_counts(db, project_ids, period)
    total = sum(sev.values())
    cards = project_cards(db, user, period)
    return {
        "period": {
            "mode": period.mode,
            "label": period.label,
            "date_from": period.date_from.isoformat() if period.date_from else None,
            "date_to": period.date_to.isoformat() if period.date_to else None,
        },
        "sev": sev,
        "total_findings": total,
        "scans_running": scans_running(db, user),
        "scans_completed": scans_completed_in_period(db, user, period),
        "cards": cards,
        "timeline": findings_timeline(db, project_ids, period),
        "by_project": findings_by_project(db, user, period),
        "export_ready": True,
    }
