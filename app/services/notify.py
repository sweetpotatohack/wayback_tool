from __future__ import annotations

import httpx

from app.models import Finding, Project, Scan, User
from app.services.classifier import SEVERITY_RANK
from app.services.screenshots import full_path, replay_url, shot_id
from app.services.smtp_user import resolve_smtp, send_smtp_message

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
        if profile:
            attachments = _screenshot_attachments(user, hits)
            send_smtp_message(
                profile,
                to=user.email,
                subject=f"[GhostIndex] {project.name}: {len(hits)} находок",
                body=text,
                attachments=attachments or None,
            )
    if user.notify_telegram and user.telegram_bot_token and user.telegram_chat_id:
        _send_telegram(user.telegram_bot_token, user.telegram_chat_id, text)


def _send_telegram(token: str, chat_id: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        httpx.post(
            url,
            json={"chat_id": chat_id, "text": text[:3500]},
            timeout=15,
        )
    except httpx.HTTPError:
        return


def send_test_telegram(token: str, chat_id: str) -> tuple[bool, str]:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        response = httpx.post(
            url,
            json={"chat_id": chat_id, "text": "GhostIndex: тестовое оповещение. Канал настроен."},
            timeout=15,
        )
        if response.status_code == 200:
            return True, "Сообщение отправлено"
        return False, response.text[:300]
    except httpx.HTTPError as exc:
        return False, str(exc)
