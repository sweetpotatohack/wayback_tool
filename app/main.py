from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import APP_DIR, AVATAR_DIR, DATA_DIR
from app.bootstrap import rotate_bootstrap_admin
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.routers import admin, auth, pages, profile, projects, scans
from app.services.scanner import start_worker
from app.services.scheduler import start_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    AVATAR_DIR.mkdir(parents=True, exist_ok=True)
    from app.services.screenshots import SHOT_DIR

    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    from app.services.bbot import BBOT_ROOT

    BBOT_ROOT.mkdir(parents=True, exist_ok=True)
    init_db()
    db = SessionLocal()
    try:
        rotate_bootstrap_admin(db)
        from datetime import datetime, timezone

        from app.models import Scan

        db.query(Scan).filter(Scan.status.in_(["queued", "running"])).update(
            {
                Scan.status: "failed",
                Scan.error: "Процесс перезапущен — проход прерван",
                Scan.stage: "Прервано рестартом",
                Scan.finished_at: datetime.now(timezone.utc),
            },
            synchronize_session=False,
        )
        db.commit()
    finally:
        db.close()
    await start_worker()
    start_scheduler()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, docs_url=None, redoc_url=None, lifespan=lifespan)
    static_dir = APP_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    AVATAR_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/media/avatars", StaticFiles(directory=str(AVATAR_DIR)), name="avatars")
    from app.services.screenshots import SHOT_DIR

    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/media/screenshots", StaticFiles(directory=str(SHOT_DIR)), name="screenshots")
    from app.services.bbot import BBOT_ROOT

    BBOT_ROOT.mkdir(parents=True, exist_ok=True)
    app.mount("/media/bbot", StaticFiles(directory=str(BBOT_ROOT)), name="bbot")
    app.include_router(pages.router)
    app.include_router(auth.router)
    app.include_router(projects.router)
    app.include_router(scans.router)
    app.include_router(profile.router)
    app.include_router(admin.router)
    return app


app = create_app()
