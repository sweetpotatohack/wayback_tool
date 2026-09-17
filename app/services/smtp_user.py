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


def notify_recipient(user: User | None) -> str:
    if not user:
        return ""
    custom = (getattr(user, "notify_email_to", "") or "").strip()
    if custom:
        return custom
    return (user.email or "").strip()


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
    timeout = 45
    host = profile.host
    port = profile.port
    use_ssl = port == 465 or (not profile.use_tls and port == 465)
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=timeout) as smtp:
                if profile.user:
                    smtp.login(profile.user, profile.password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if profile.use_tls:
                    smtp.starttls()
                    smtp.ehlo()
                if profile.user:
                    smtp.login(profile.user, profile.password)
                smtp.send_message(msg)
        return True, "Отправлено"
    except TimeoutError:
        return False, f"Таймаут {host}:{port} — сервер недоступен из этой сети (VPN, firewall, порт)."
    except smtplib.SMTPServerDisconnected as exc:
        hint = " Попробуйте порт 465 без STARTTLS или проверьте VPN."
        return False, f"{host}:{port}: {str(exc)[:220]}.{hint}"
    except OSError as exc:
        text = str(exc)[:320]
        if "timed out" in text.lower() or "unreachable" in text.lower():
            return False, f"{host}:{port}: {text}. Проверьте VPN и доступность SMTP."
        return False, text


def send_test_smtp(user: User, to: str | None = None) -> tuple[bool, str]:
    profile = resolve_smtp(user)
    if not profile:
        return False, "Включите «Мой SMTP» в кабинете или настройте SMTP в .env сервера"
    recipient = (to or notify_recipient(user) or "").strip()
    if not recipient:
        return False, "Укажите email получателя в блоке «Оповещения»"
    ok, msg = send_smtp_message(
        profile,
        to=recipient,
        subject="GhostIndex: тест SMTP",
        body=f"Тестовое письмо на {recipient}. SMTP и адрес получателя настроены.",
    )
    if ok:
        return True, f"Письмо отправлено на {recipient}"
    return False, msg
