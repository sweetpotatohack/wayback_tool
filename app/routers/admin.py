from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import require_admin
from app.models import User

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users")
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "display_name": u.display_name,
            "status": u.status,
            "is_admin": u.is_admin,
            "is_bootstrap_admin": u.is_bootstrap_admin,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.post("/users/{user_id}/approve")
def approve(user_id: str, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    user.status = "approved"
    user.approved_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@router.post("/users/{user_id}/reject")
def reject(user_id: str, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    if user.is_bootstrap_admin:
        raise HTTPException(400, "Системного администратора нельзя отклонить")
    user.status = "rejected"
    db.commit()
    return {"ok": True}


@router.post("/users/{user_id}/disable")
def disable(user_id: str, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "Пользователь не найден")
    if user.is_bootstrap_admin:
        raise HTTPException(400, "Системного администратора нельзя отключить")
    user.status = "disabled"
    db.commit()
    return {"ok": True}
