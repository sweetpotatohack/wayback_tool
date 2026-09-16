from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Finding, Project, User
from app.services.dashboard_stats import PeriodFilter

WIRE_FEED_LIMIT = 6


def wire_feed_items(
    db: Session,
    user: User,
    *,
    limit: int = WIRE_FEED_LIMIT,
    period: PeriodFilter | None = None,
) -> list[dict]:
    """Random findings from this user's projects only (explicit owner filter)."""
    q = (
        db.query(Finding, Project.name, Project.id)
        .join(Project, Finding.project_id == Project.id)
        .filter(Project.owner_id == user.id)
    )
    if period:
        if period.date_from is not None:
            q = q.filter(Finding.created_at >= period.date_from)
        if period.date_to is not None:
            q = q.filter(Finding.created_at < period.date_to)

    rows = q.order_by(func.random()).limit(limit).all()
    return [
        {
            "id": f.id,
            "severity": f.severity or "info",
            "title": f.title or "",
            "original_url": f.original_url or "",
            "category": f.category or "",
            "project_name": pname,
            "project_id": pid,
        }
        for f, pname, pid in rows
    ]
