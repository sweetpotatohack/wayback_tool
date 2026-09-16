from __future__ import annotations

import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app import ADMIN_FILE, DATA_DIR
from app.config import get_settings
from app.models import User
from app.security import hash_password

BANNER = r"""
  ╔══════════════════════════════════════════════════════════╗
  ║              G H O S T I N D E X   DESK                  ║
  ║         Wayback intelligence · authorized use only       ║
  ╚══════════════════════════════════════════════════════════╝
"""


def _persist_creds(username: str, password: str) -> None:
    ADMIN_FILE.write_text(f"username={username}\npassword={password}\n", encoding="utf-8")
    try:
        ADMIN_FILE.chmod(0o600)
    except OSError:
        pass


def _announce(username: str, password: str, reused: bool) -> None:
    title = "Учётные данные администратора обновлены" if reused else "Администратор создан"
    print(
        f"{BANNER}\n"
        f"  {title} при старте.\n\n"
        f"  login:     {username}\n"
        f"  password:  {password}\n\n"
        f"  Сохраните эти данные — они не показываются в веб-интерфейсе.\n"
        f"  Копия: {ADMIN_FILE}\n",
        flush=True,
    )
    _persist_creds(username, password)


def rotate_bootstrap_admin(db: Session) -> tuple[str, str]:
    settings = get_settings()
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    admin = db.query(User).filter(User.is_bootstrap_admin.is_(True)).order_by(User.created_at.asc()).first()

    if settings.keep_admin and admin:
        print(
            f"{BANNER}\n"
            f"  Админ сохранён (GHOSTINDEX_KEEP_ADMIN=true): {admin.username}\n"
            f"  Пароль — в предыдущем запуске или в {ADMIN_FILE}\n",
            flush=True,
        )
        return admin.username, ""

    username = f"archivist_{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(18)

    if admin:
        # Не удаляем строку: у админа уже могут быть проекты (owner_id NOT NULL).
        admin.username = username
        admin.email = f"{username}@ghostindex.local"
        admin.password_hash = hash_password(password)
        admin.is_admin = True
        admin.status = "approved"
        admin.display_name = admin.display_name or "Archivist"
        if not admin.approved_at:
            admin.approved_at = datetime.now(timezone.utc)
        db.commit()
        _announce(username, password, reused=True)
        return username, password

    admin = User(
        username=username,
        email=f"{username}@ghostindex.local",
        password_hash=hash_password(password),
        is_admin=True,
        is_bootstrap_admin=True,
        status="approved",
        display_name="Archivist",
        approved_at=datetime.now(timezone.utc),
    )
    db.add(admin)
    db.commit()
    _announce(username, password, reused=False)
    return username, password
