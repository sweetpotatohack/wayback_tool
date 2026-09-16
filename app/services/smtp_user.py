from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

from app.config import get_settings
from app.models import User


@dataclass
class SmtpProfile:
    host: str
    port: int
    user: str
    password: str
    from_addr: str
    use_tls: bool


def smtp_for_user(user: User | None) -> SmtpProfile | None:
    if not user or not getattr(user, "smtp_enabled", False):
        return None
    host = (getattr(user, "smtp_host", "") or "").strip()
    if not host:
        return None
    from_addr = (getattr(user, "smtp_from", "") or user.email or "").strip()
    if not from_addr:
        return None
    return SmtpProfile(
        host=host,
        port=int(getattr(user, "smtp_port", 587) or 587),
        user=(getattr(user, "smtp_user", "") or "").strip(),
        password=getattr(user, "smtp_password", "") or "",
        from_addr=from_addr,
        use_tls=bool(getattr(user, "smtp_tls", True)),
    )


def global_smtp() -> SmtpProfile | None:
    settings = get_settings()
    if not settings.smtp_host:
        return None
    return SmtpProfile(
        host=settings.smtp_host,
        port=int(settings.smtp_port or 587),
        user=settings.smtp_user or "",
        password=settings.smtp_password or "",
        from_addr=settings.smtp_from or settings.smtp_user or "ghostindex@localhost",
        use_tls=bool(settings.smtp_tls),
    )


def resolve_smtp(user: User | None) -> SmtpProfile | None:
    return smtp_for_user(user) or global_smtp()


def send_smtp_message(
    profile: SmtpProfile,
    *,
    to: str,
    subject: str,
    body: str,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> tuple[bool, str]:
    if not to or not profile.host:
        return False, "SMTP не настроен"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = profile.from_addr
    msg["To"] = to
    msg.set_content(body)
    for filename, data, mime in attachments or []:
        main, sub = (mime.split("/", 1) + ["octet-stream"])[:2]
        msg.add_attachment(data, maintype=main, subtype=sub, filename=filename)
    try:
        with smtplib.SMTP(profile.host, profile.port, timeout=20) as smtp:
            if profile.use_tls:
                smtp.starttls()
            if profile.user:
                smtp.login(profile.user, profile.password)
            smtp.send_message(msg)
        return True, "Отправлено"
    except OSError as exc:
        return False, str(exc)[:400]


def send_test_smtp(user: User, to: str | None = None) -> tuple[bool, str]:
    profile = smtp_for_user(user)
    if not profile:
        return False, "Сначала включите и сохраните SMTP в кабинете"
    recipient = (to or user.email or "").strip()
    if not recipient:
        return False, "Укажите email получателя в профиле"
    return send_smtp_message(
        profile,
        to=recipient,
        subject="GhostIndex: тест SMTP",
        body="Тестовое письмо. Ваш SMTP настроен корректно.",
    )
