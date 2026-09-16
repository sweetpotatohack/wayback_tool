from urllib.parse import quote

from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import COOKIE
from app.models import User
from app.security import create_token, hash_password, verify_password

router = APIRouter()


def _cookie_response(redirect: str, token: str) -> RedirectResponse:
    from app.config import get_settings

    response = RedirectResponse(redirect, status_code=303)
    response.set_cookie(
        COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=get_settings().cookie_secure,
        max_age=get_settings().session_hours * 3600,
        path="/",
    )
    return response


@router.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username.strip()).first()
    if not user or not verify_password(password, user.password_hash):
        return RedirectResponse("/login?err=" + quote("Неверный логин или пароль"), status_code=303)
    if user.status == "pending":
        return RedirectResponse("/pending", status_code=303)
    if user.status != "approved" and not user.is_admin:
        return RedirectResponse("/login?err=" + quote("Аккаунт отклонён или отключён"), status_code=303)
    return _cookie_response("/dashboard", create_token(user.id))


@router.post("/register")
def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(""),
    db: Session = Depends(get_db),
):
    username = username.strip()
    email = email.strip().lower()
    if len(username) < 3 or len(password) < 8:
        return RedirectResponse("/register?err=" + quote("Логин от 3 символов, пароль от 8"), status_code=303)
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        return RedirectResponse("/register?err=" + quote("Такой логин или почта уже заняты"), status_code=303)
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        display_name=display_name.strip() or username,
        status="pending",
    )
    db.add(user)
    db.commit()
    return RedirectResponse("/pending", status_code=303)


@router.post("/logout")
@router.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE, path="/")
    return response
