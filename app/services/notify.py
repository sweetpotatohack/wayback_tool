from __future__ import annotations

import httpx

from app.config import get_settings
from app.models import Finding, Project, Scan, User
from app.services.classifier import SEVERITY_RANK
from app.services.http_outbound import human_network_error, sync_client
from app.services.screenshots import full_path, replay_url, shot_id
from app.services.smtp_user import notify_recipient, resolve_smtp, send_smtp_message

SEVERITY_RU = {
    "critical": "критично",
    "high": "высокая",
    "medium": "средняя",
    "low": "низкая",
    "info": "инфо",
}


def _should_notify(user: User, findings: list[Finding]) -> list[Finding]:
    threshold = SEVERITY_RANK.get(user.notify_min_severity, 3)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= threshold]


def _body(project: Project, scan: Scan, hits: list[Finding]) -> str:
    lines = [
        f"GhostIndex · проект «{project.name}»",
        f"Проход завершён. Находок всего: {scan.findings_count}, выше порога: {len(hits)}.",
        "",
    ]
    for item in hits[:20]:
        lines.append(f"[{item.severity}] {item.title}")
        lines.append(f"  {item.original_url}")
        if item.masked_secret:
            lines.append(f"  Значение: {item.masked_secret}")
        if item.evidence:
            lines.append(f"  {item.evidence[:240]}")
        lines.append("")
    return "\n".join(lines)


def _screenshot_attachments(user: User, hits: list[Finding], limit: int = 5) -> list[tuple[str, bytes, str]]:
    if not getattr(user, "notify_attach_screenshots", True):
        return []
    out: list[tuple[str, bytes, str]] = []
    for item in hits[:limit]:
        archive = item.archive_url or replay_url(item.original_url, item.capture_ts or "")
        if not archive:
            continue
        path = full_path(shot_id(archive))
        if not path.exists():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        name = f"finding-{len(out) + 1}.jpg"
        out.append((name, data, "image/jpeg"))
    return out


def notify_scan_complete(user: User | None, project: Project, scan: Scan, findings: list[Finding]) -> None:
    if not user:
        return
    hits = _should_notify(user, findings)
    if not hits:
        return
    text = _body(project, scan, hits)
    if user.notify_email:
        profile = resolve_smtp(user)
        recipient = notify_recipient(user)
        if profile and recipient:
            attachments = _screenshot_attachments(user, hits)
            send_smtp_message(
                profile,
                to=recipient,
                subject=f"[GhostIndex] {project.name}: {len(hits)} находок",
                body=text,
                attachments=attachments or None,
            )
    if user.notify_telegram and user.telegram_bot_token and user.telegram_chat_id:
        _send_telegram(user.telegram_bot_token, user.telegram_chat_id, text, user=user)


def _telegram_api_url(token: str, method: str) -> str:
    base = get_settings().telegram_api_base.rstrip("/")
    return f"{base}/bot{token}/{method}"


def _parse_telegram_error(response: httpx.Response) -> str:
    try:
        data = response.json()
    except Exception:
        return response.text[:300] or f"HTTP {response.status_code}"
    if data.get("ok"):
        return ""
    desc = str(data.get("description") or "Неизвестная ошибка Telegram")
    low = desc.lower()
    if "chat not found" in low:
        return (
            "Чат не найден. Добавьте бота в группу/канал, напишите /start "
            "и проверьте chat_id (для группы id отрицательный)."
        )
    if "bot was blocked" in low:
        return "Пользователь заблокировал бота — разблокируйте или напишите /start."
    if "unauthorized" in low or "token" in low:
        return "Неверный токен бота. Проверьте токен у @BotFather."
    if "group chat was upgraded" in low:
        return "Группа стала supergroup — обновите chat_id (новый id в getUpdates)."
    return desc


def _send_telegram(token: str, chat_id: str, text: str, *, user: User | None = None) -> None:
    url = _telegram_api_url(token, "sendMessage")
    try:
        with sync_client(user=user) as client:
            client.post(url, json={"chat_id": chat_id, "text": text[:3500]})
    except httpx.HTTPError:
        return


def send_test_telegram(token: str, chat_id: str, *, user: User | None = None) -> tuple[bool, str]:
    token = (token or "").strip()
    chat_id = (chat_id or "").strip()
    if not token or not chat_id:
        return False, "Укажите токен бота и chat_id"
    url = _telegram_api_url(token, "sendMessage")
    try:
        with sync_client(user=user) as client:
            response = client.post(
                url,
                json={"chat_id": chat_id, "text": "GhostIndex: тестовое оповещение. Канал настроен."},
            )
    except httpx.HTTPError as exc:
        return False, human_network_error(exc, host="api.telegram.org", user=user)

    if response.status_code == 200:
        try:
            if response.json().get("ok"):
                return True, "Сообщение отправлено"
        except Exception:
            return True, "Сообщение отправлено"
    return False, _parse_telegram_error(response)
