from __future__ import annotations

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.db import SessionLocal
from app.models import Project, Scan
from app.services.scanner import enqueue_scan
from app.services.schedule_config import build_triggers, schedule_config_for_project

scheduler = AsyncIOScheduler()


def _job_prefix(project_id: str) -> str:
    return f"project-{project_id}-"


def _job_id(project_id: str, rule_id: str) -> str:
    return f"{_job_prefix(project_id)}{rule_id}"


async def _run_project_job(project_id: str) -> None:
    db = SessionLocal()
    try:
        project = db.get(Project, project_id)
        if not project:
            return
        cfg = schedule_config_for_project(project)
        if not cfg.get("enabled"):
            return
        running = (
            db.query(Scan)
            .filter(Scan.project_id == project_id, Scan.status.in_(["queued", "running"]))
            .first()
        )
        if running:
            return
        enqueue_scan(db, project)
    finally:
        db.close()


def _remove_project_jobs(project_id: str) -> None:
    prefix = _job_prefix(project_id)
    for job in list(scheduler.get_jobs()):
        if job.id.startswith(prefix):
            job.remove()


def sync_project_schedule(project: Project) -> None:
    _remove_project_jobs(project.id)
    cfg = schedule_config_for_project(project)
    if not cfg.get("enabled"):
        return
    for rule_id, trigger in build_triggers(cfg):
        scheduler.add_job(
            _run_project_job,
            trigger=trigger,
            id=_job_id(project.id, rule_id),
            args=[project.id],
            replace_existing=True,
        )


def load_all_schedules() -> None:
    db = SessionLocal()
    try:
        projects = db.query(Project).all()
        for project in projects:
            cfg = schedule_config_for_project(project)
            if cfg.get("enabled"):
                sync_project_schedule(project)
    finally:
        db.close()


def start_scheduler() -> None:
    if not scheduler.running:
        scheduler.start()
    load_all_schedules()
