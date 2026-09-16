from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import require_user
from app.models import Project, Scan, User
from app.routers.projects import _scan_dict

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Скан не найден")
    project = db.get(Project, scan.project_id)
    if not project or project.owner_id != user.id:
        raise HTTPException(404, "Скан не найден")
    return _scan_dict(scan)
