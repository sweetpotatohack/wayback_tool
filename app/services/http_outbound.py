"""Shared outbound HTTP client settings (proxy, timeouts)."""

from __future__ import annotations

from urllib.parse import quote

import httpx

from app.config import get_settings
from app.models import User

_PROXY_TYPES = {"socks5", "http", "https"}


def build_proxy_url(
    proxy_type: str,
    host: str,
    port: int,
    *,
    username: str = "",
    password: str = "",
) -> str:
    scheme = (proxy_type or "socks5").strip().lower()
    if scheme not in _PROXY_TYPES:
        scheme = "socks5"
    host = (host or "127.0.0.1").strip()
    port = int(port or 10808)
    user = (username or "").strip()
    pwd = (password or "").strip()
    if user and pwd:
        auth = f"{quote(user, safe='')}:{quote(pwd, safe='')}@"
    elif user:
        auth = f"{quote(user, safe='')}@"
    else:
        auth = ""
    return f"{scheme}://{auth}{host}:{port}"


def proxy_from_user(user: User | None) -> str | None:
    if not user or not getattr(user, "outbound_proxy_enabled", False):
        return None
    return build_proxy_url(
        user.outbound_proxy_type or "socks5",
        user.outbound_proxy_host or "127.0.0.1",
        user.outbound_proxy_port or 10808,
        username=user.outbound_proxy_user or "",
        password=user.outbound_proxy_password or "",
    )


def outbound_proxy(user: User | None = None) -> str | None:
    user_proxy = proxy_from_user(user)
    if user_proxy:
        return user_proxy
    settings = get_settings()
    env_proxy = (settings.https_proxy or settings.http_proxy or "").strip()
    return env_proxy or None


def sync_client(*, user: User | None = None, timeout: float = 20.0, connect: float = 12.0) -> httpx.Client:
    return httpx.Client(
        proxy=outbound_proxy(user),
        timeout=httpx.Timeout(timeout, connect=connect),
        follow_redirects=True,
    )


def human_network_error(exc: Exception, *, host: str = "внешний сервис", user: User | None = None) -> str:
    msg = str(exc).strip()
    low = msg.lower()
    proxy = outbound_proxy(user)
    if "socks" in low and ("support" in low or "missing" in low or "socksio" in low):
        return "SOCKS5 требует пакет httpx[socks]. Переустановите зависимости: pip install 'httpx[socks]'"
    if "101" in msg or "network is unreachable" in low:
        if proxy:
            return (
                f"Нет маршрута до {host} через прокси {proxy}. "
                "Проверьте, что sing-box/xray/hiddify запущен и локальный порт совпадает."
            )
        return (
            f"Нет маршрута до {host} (Network unreachable). "
            "Включите прокси в кабинете или задайте GHOSTINDEX_HTTPS_PROXY в .env."
        )
    if "timed out" in low or "timeout" in low:
        return f"Таймаут подключения к {host}. Проверьте прокси/VPN."
    if "connection refused" in low:
        return f"Соединение отклонено ({host}). Локальный прокси не слушает порт — запустите VLESS-клиент."
    if "name or service not known" in low or "getaddrinfo" in low:
        return f"Не удалось разрешить DNS для {host}."
    return msg or f"Ошибка сети ({host})"


def test_proxy(user: User) -> tuple[bool, str]:
    proxy = outbound_proxy(user)
    if not proxy:
        return False, "Прокси выключен — включите и сохраните настройки"
    try:
        with sync_client(user=user, timeout=15.0, connect=10.0) as client:
            response = client.get("https://api.telegram.org")
        if response.status_code < 500:
            return True, f"OK через {proxy} · HTTP {response.status_code}"
        return False, f"Прокси ответил HTTP {response.status_code}"
    except httpx.HTTPError as exc:
        return False, human_network_error(exc, host="api.telegram.org", user=user)
