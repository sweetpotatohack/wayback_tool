"""Background dashboard export jobs with progress tracking."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from fastapi import HTTPException

from app.db import SessionLocal
from app.models import User
from app.services.dashboard_export import (
    build_export_bundle,
    export_filename,
    render_csv,
    render_html,
    render_pdf,
    render_txt,
)
from app.services.dashboard_stats import PeriodFilter

ProgressFn = Callable[[int, str], None]

_jobs: dict[str, ExportJob] = {}
_lock = threading.Lock()


@dataclass
class ExportJob:
    id: str
    user_id: str
    fmt: str
    progress: int = 0
    stage: str = "В очереди"
    status: str = "pending"  # pending | running | done | error
    error: str = ""
    filename: str = ""
    filepath: Path | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _set_progress(job: ExportJob, pct: int, stage: str, *, status: str = "running") -> None:
    job.progress = max(0, min(100, int(pct)))
    job.stage = stage
    job.status = status


def create_export_job(user_id: str, fmt: str) -> ExportJob:
    job = ExportJob(id=uuid.uuid4().hex, user_id=user_id, fmt=fmt)
    with _lock:
        _purge_old_jobs()
        _jobs[job.id] = job
    return job


def get_export_job(job_id: str, user_id: str) -> ExportJob | None:
    with _lock:
        job = _jobs.get(job_id)
        if not job or job.user_id != user_id:
            return None
        return job


def _purge_old_jobs() -> None:
    now = datetime.now(timezone.utc)
    drop: list[str] = []
    for jid, job in _jobs.items():
        age = (now - job.created_at).total_seconds()
        if age > 3600 or (job.status in {"done", "error"} and age > 600):
            if job.filepath:
                job.filepath.unlink(missing_ok=True)
            drop.append(jid)
    for jid in drop:
        _jobs.pop(jid, None)


def _run_job(job_id: str, period: PeriodFilter, project_id: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return
        fmt = job.fmt
        user_id = job.user_id

    db = SessionLocal()
    tmp_path: Path | None = None
    try:
        user = db.get(User, user_id)
        if not user:
            raise RuntimeError("Пользователь не найден")

        def progress(pct: int, stage: str) -> None:
            with _lock:
                j = _jobs.get(job_id)
                if j:
                    _set_progress(j, pct, stage)

        progress(5, "Подготовка параметров")
        with_screenshots = fmt in {"html", "pdf"}

        def shot_progress(done: int, total: int) -> None:
            if total <= 0:
                return
            span = 45 if fmt == "pdf" else 50
            base = 25
            pct = base + int((done / total) * span)
            progress(pct, f"Скриншоты {done}/{total}")

        bundle = build_export_bundle(
            db,
            user,
            period,
            project_id=project_id or "all",
            with_screenshots=with_screenshots,
            progress=progress,
            shot_progress=shot_progress,
        )

        progress(78 if with_screenshots else 55, "Формирование файла")
        if fmt == "csv":
            data = render_csv(bundle)
        elif fmt == "txt":
            data = render_txt(bundle)
        elif fmt == "html":
            progress(88, "Сборка HTML")
            data = render_html(bundle).encode("utf-8")
        elif fmt == "pdf":
            progress(88, "Рендер PDF (chromium)")
            data = render_pdf(bundle)
        else:
            raise RuntimeError("Неизвестный формат")

        filename = export_filename(bundle, fmt)
        tmp_path = Path(f"/tmp/ghostindex-export-{job_id}.{fmt}")
        tmp_path.write_bytes(data)

        with _lock:
            j = _jobs.get(job_id)
            if j:
                j.filename = filename
                j.filepath = tmp_path
                _set_progress(j, 100, "Готово", status="done")
    except HTTPException as exc:
        if tmp_path:
            tmp_path.unlink(missing_ok=True)
        with _lock:
            j = _jobs.get(job_id)
            if j:
                j.error = str(exc.detail)
                _set_progress(j, j.progress, "Ошибка", status="error")
    except Exception as exc:
        if tmp_path:
            tmp_path.unlink(missing_ok=True)
        with _lock:
            j = _jobs.get(job_id)
            if j:
                j.error = str(exc)
                _set_progress(j, j.progress, "Ошибка", status="error")
    finally:
        db.close()


def start_export_job(user_id: str, fmt: str, period: PeriodFilter, project_id: str) -> ExportJob:
    job = create_export_job(user_id, fmt)
    thread = threading.Thread(
        target=_run_job,
        args=(job.id, period, project_id or "all"),
        daemon=True,
        name=f"export-{job.id[:8]}",
    )
    thread.start()
    return job
