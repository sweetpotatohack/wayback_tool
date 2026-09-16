from io import BytesIO
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app import AVATAR_DIR
from app.db import get_db
from app.deps import require_user
from app.models import User
from app.schemas import EmailIn, LlmIn, NotifyIn, PasswordIn, SmtpIn, ThemeIn
from app.security import hash_password, verify_password
from app.services.llm import LlmConfig, ping
from app.services.notify import send_test_telegram
from app.services.smtp_user import send_test_smtp

router = APIRouter(prefix="/api/profile", tags=["profile"])

PRESETS = {"archive", "night", "paper", "terminal"}


@router.post("/password")
def change_password(payload: PasswordIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "Текущий пароль неверен")
    user.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"ok": True}


@router.post("/email")
def change_email(payload: EmailIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "Текущий пароль неверен")
    email = str(payload.email).lower()
    exists = db.query(User).filter(User.email == email, User.id != user.id).first()
    if exists:
        raise HTTPException(400, "Эта почта уже используется")
    user.email = email
    db.commit()
    return {"ok": True, "email": user.email}


@router.post("/theme")
def change_theme(payload: ThemeIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if payload.theme_preset not in PRESETS:
        raise HTTPException(400, "Неизвестный пресет")
    user.theme_preset = payload.theme_preset
    user.accent = payload.accent if payload.accent.startswith("#") else "#d4894a"
    user.radius = payload.radius
    user.density = payload.density if payload.density in {"comfortable", "compact"} else "comfortable"
    user.font_scale = min(max(payload.font_scale, 0.85), 1.25)
    user.grain = payload.grain
    db.commit()
    return {"ok": True}


@router.post("/notify")
def change_notify(payload: NotifyIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    user.notify_email = payload.notify_email
    user.notify_telegram = payload.notify_telegram
    if payload.telegram_bot_token and not payload.telegram_bot_token.startswith("••••"):
        user.telegram_bot_token = payload.telegram_bot_token.strip()
    user.telegram_chat_id = payload.telegram_chat_id.strip()
    if payload.notify_min_severity in {"critical", "high", "medium", "low", "info"}:
        user.notify_min_severity = payload.notify_min_severity
    user.notify_attach_screenshots = payload.notify_attach_screenshots
    db.commit()
    return {"ok": True}


@router.post("/smtp")
def change_smtp(payload: SmtpIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    user.smtp_enabled = payload.smtp_enabled
    user.smtp_host = payload.smtp_host.strip()
    user.smtp_port = int(payload.smtp_port or 587)
    user.smtp_user = payload.smtp_user.strip()
    if payload.smtp_password and not payload.smtp_password.startswith("••••"):
        user.smtp_password = payload.smtp_password
    user.smtp_from = payload.smtp_from.strip()
    user.smtp_tls = payload.smtp_tls
    db.commit()
    return {"ok": True}


@router.post("/smtp/test")
def test_smtp(user: User = Depends(require_user)):
    ok, msg = send_test_smtp(user)
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "detail": msg}


@router.post("/notify/test-telegram")
def test_telegram(user: User = Depends(require_user)):
    if not user.telegram_bot_token or not user.telegram_chat_id:
        raise HTTPException(400, "Сначала сохраните токен бота и chat_id")
    ok, msg = send_test_telegram(user.telegram_bot_token, user.telegram_chat_id)
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "detail": msg}


@router.post("/llm")
def change_llm(payload: LlmIn, user: User = Depends(require_user), db: Session = Depends(get_db)):
    user.llm_enabled = payload.llm_enabled
    user.llm_base_url = payload.llm_base_url.strip()
    user.llm_api_path = payload.llm_api_path.strip() or "/v1/chat/completions"
    user.llm_model = payload.llm_model.strip()
    if payload.llm_api_key and not payload.llm_api_key.startswith("••••"):
        user.llm_api_key = payload.llm_api_key.strip()
    user.llm_temperature = payload.llm_temperature
    user.llm_max_tokens = payload.llm_max_tokens
    user.llm_timeout = payload.llm_timeout
    db.commit()
    return {"ok": True}


@router.post("/llm/test")
async def test_llm(user: User = Depends(require_user)):
    if not user.llm_base_url or not user.llm_model:
        raise HTTPException(400, "Сначала сохраните Base URL и модель")
    cfg = LlmConfig(
        enabled=True,
        base_url=user.llm_base_url,
        api_path=user.llm_api_path or "/v1/chat/completions",
        model=user.llm_model,
        api_key=user.llm_api_key or "",
        temperature=float(user.llm_temperature or 0.2),
        max_tokens=min(int(user.llm_max_tokens or 32), 64),
        timeout=float(user.llm_timeout or 60),
    )
    ok, msg = await ping(cfg)
    if not ok:
        raise HTTPException(400, msg)
    return {"ok": True, "detail": msg}


@router.post("/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if file.content_type not in {"image/jpeg", "image/png", "image/webp", "image/gif"}:
        raise HTTPException(400, "Нужен JPEG, PNG, WebP или GIF")
    data = await file.read()
    if len(data) > 2_500_000:
        raise HTTPException(400, "Файл больше 2.5 МБ")
    try:
        from PIL import Image

        image = Image.open(BytesIO(data)).convert("RGB")
        image.thumbnail((512, 512))
        side = min(image.size)
        left = (image.width - side) // 2
        top = (image.height - side) // 2
        image = image.crop((left, top, left + side, top + side)).resize((256, 256))
        AVATAR_DIR.mkdir(parents=True, exist_ok=True)
        name = f"{user.id}-{uuid4().hex[:8]}.webp"
        path = AVATAR_DIR / name
        image.save(path, "WEBP", quality=86)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Не удалось обработать изображение: {exc}") from exc
    if user.avatar_file:
        old = AVATAR_DIR / Path(user.avatar_file).name
        if old.exists():
            old.unlink(missing_ok=True)
    user.avatar_file = name
    db.commit()
    return {"ok": True, "url": f"/media/avatars/{name}"}
