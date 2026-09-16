from __future__ import annotations

import json
import re
from dataclasses import dataclass

import httpx

from app.services.wayback import store_secret
from app.services.llm_queue import llm_request

TRIAGE_SYSTEM = (
    "Ты аналитик Wayback OSINT. Даны пути одного сайта. "
    "Выбери индексы, которые стоит скачать из архива: утечки, конфиги, бэкапы, ключи, "
    "админки, phpinfo, .env, .git, дампы, installer, логи, dbconn, web.config. "
    "Не бери новости, пресс-центр, пассажирские страницы, SVG/картинки, PDF-сертификаты, "
    "характеристики самолётов (/parameters/), маркетинг. "
    "JSON: {\"picks\":[{\"i\":12,\"sev\":\"high\",\"why\":\"phpinfo\"}]}. Максимум 25 picks."
)

EXTRACT_BATCH_SYSTEM = (
    "Ты аналитик архивных снимков Wayback. Даны документы с индексом i. "
    "Извлеки только реально присутствующие секреты: пароли, ключи, токены, строки подключения, "
    "путь DOCUMENT_ROOT/SCRIPT_FILENAME из phpinfo, basic auth. Ничего не выдумывай. "
    "JSON: {\"findings\":[{\"i\":0,\"type\":\"...\",\"severity\":\"critical|high|medium\","
    "\"value\":\"...\",\"context\":\"короткий фрагмент\"}]}"
)

EXTRACT_SYSTEM = (
    "Ты аналитик архивных снимков Wayback Machine. "
    "Из текста извлеки только реально присутствующие секреты: пароли, API-ключи, токены, "
    "приватные ключи, строки подключения, basic auth, AWS/GCP/Azure ключи. "
    "Ничего не выдумывай. Если секретов нет — пустой список. "
    "Ответ строго JSON: {\"findings\":[{\"type\":\"...\",\"severity\":\"critical|high|medium\","
    "\"value\":\"...\",\"context\":\"короткий фрагмент\"}]}"
)

LIVE_EXTRACT_SYSTEM = (
    "Ты аналитик безопасности. Даны документы с живого сайта (не архив). "
    "Извлеки только реально присутствующие секреты: пароли, API-ключи, JWT, токены, "
    "строки подключения к БД, приватные ключи, учётные данные в JS/JSON/конфигах. "
    "Не выдумывай. Игнорируй публичный маркетинговый контент. "
    "JSON: {\"findings\":[{\"i\":0,\"type\":\"...\",\"severity\":\"critical|high|medium\","
    "\"value\":\"...\",\"context\":\"короткий фрагмент\"}]}"
)

REVIEW_SYSTEM = (
    "Ты отсекаешь ложные срабатывания OSINT по Wayback. "
    "Картинки, CSS, маркетинговые URL вроде /passengers/secret/, обычный HTML без конфигов — false. "
    "Конфиги, .env, бэкапы, ключи, robots с Disallow на админку, JS с токенами — true. "
    "Ответ строго JSON: {\"items\":[{\"i\":0,\"keep\":true,\"severity\":\"high\",\"reason\":\"...\"}]}"
)


@dataclass
class LlmConfig:
    enabled: bool
    base_url: str
    api_path: str
    model: str
    api_key: str
    temperature: float
    max_tokens: int
    timeout: float


def chat_url(cfg: LlmConfig) -> str:
    base = (cfg.base_url or "").rstrip("/")
    path = cfg.api_path or "/v1/chat/completions"
    if not path.startswith("/"):
        path = "/" + path
    if base.endswith("/v1") and path.startswith("/v1/"):
        return base + path[3:]
    return base + path


async def chat(cfg: LlmConfig, messages: list[dict], *, max_tokens: int | None = None) -> str:
    if not cfg.enabled or not cfg.base_url or not cfg.model:
        raise RuntimeError("LLM не настроен")
    headers = {"Content-Type": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    payload = {
        "model": cfg.model,
        "messages": messages,
        "temperature": cfg.temperature,
        "max_tokens": max_tokens or cfg.max_tokens,
        "stream": False,
    }
    timeout = httpx.Timeout(cfg.timeout, connect=15.0)
    async with llm_request():
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.post(chat_url(cfg), headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Неожиданный ответ LLM: {str(data)[:400]}") from exc


def _parse_json(text: str) -> dict | list:
    blob = text.strip()
    if not blob:
        return {}
    if blob.startswith("```"):
        blob = re.sub(r"^```(?:json)?\s*", "", blob)
        blob = re.sub(r"\s*```$", "", blob)
    match = re.search(r"[\{\[]", blob)
    if match:
        blob = blob[match.start() :]
    try:
        return json.loads(blob)
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}


async def ping(cfg: LlmConfig) -> tuple[bool, str]:
    try:
        reply = await chat(
            cfg,
            [
                {"role": "system", "content": "Ответь одним словом: pong"},
                {"role": "user", "content": "ping"},
            ],
            max_tokens=16,
        )
        return True, (reply or "").strip()[:200] or "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:400]


async def extract_secrets(cfg: LlmConfig, url: str, text: str) -> list[dict]:
    snippet = text[:8000]
    raw = await chat(
        cfg,
        [
            {"role": "system", "content": EXTRACT_SYSTEM},
            {"role": "user", "content": f"URL: {url}\n\nСнимок:\n{snippet}"},
        ],
    )
    data = _parse_json(raw)
    items = data.get("findings", []) if isinstance(data, dict) else data
    out = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or "").strip()
        if len(value) < 4:
            continue
        sev = str(item.get("severity") or "high").lower()
        if sev not in SEV:
            sev = "high"
        out.append(
            {
                "type": str(item.get("type") or "LLM secret")[:80],
                "severity": sev,
                "value": value[:400],
                "context": str(item.get("context") or "")[:240],
                "masked": store_secret(value),
            }
        )
    return out[:20]


SEV = {"critical", "high", "medium", "low", "info"}


async def review_flags(cfg: LlmConfig, rows: list[dict]) -> dict[int, dict]:
    if not rows:
        return {}
    listing = "\n".join(
        f'{i}. [{r.get("severity")}] {r.get("title")} | {r.get("url")} | {r.get("evidence", "")[:80]}'
        for i, r in enumerate(rows)
    )
    raw = await chat(
        cfg,
        [
            {"role": "system", "content": REVIEW_SYSTEM},
            {"role": "user", "content": listing},
        ],
    )
    data = _parse_json(raw)
    items = data.get("items", []) if isinstance(data, dict) else data
    result: dict[int, dict] = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item.get("i"))
        except (TypeError, ValueError):
            continue
        result[idx] = {
            "keep": bool(item.get("keep", True)),
            "severity": str(item.get("severity") or rows[idx].get("severity") if 0 <= idx < len(rows) else "low"),
            "reason": str(item.get("reason") or "")[:200],
        }
    return result


async def triage_urls(cfg: LlmConfig, rows: list[str]) -> list[tuple[int, str, str]]:
    if not rows:
        return []
    listing = "\n".join(f"{i} {line}" for i, line in enumerate(rows))
    raw = await chat(
        cfg,
        [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": listing[:12000]},
        ],
        max_tokens=900,
    )
    if not (raw or "").strip():
        return []
    data = _parse_json(raw)
    picks = data.get("picks", []) if isinstance(data, dict) else data
    out: list[tuple[int, str, str]] = []
    seen: set[int] = set()
    for item in picks or []:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item.get("i"))
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= len(rows) or idx in seen:
            continue
        seen.add(idx)
        sev = str(item.get("sev") or item.get("severity") or "medium").lower()
        if sev not in SEV:
            sev = "medium"
        why = str(item.get("why") or item.get("reason") or "llm-triage")[:80]
        out.append((idx, sev, why))
    return out[:25]


async def extract_secrets_batch(cfg: LlmConfig, docs: list[tuple[str, str]]) -> list[tuple[int, dict]]:
    if not docs:
        return []
    blob = "\n".join(f"--- doc {i} ---\nURL: {url}\n{text[:2500]}\n" for i, (url, text) in enumerate(docs))
    raw = await chat(
        cfg,
        [
            {"role": "system", "content": EXTRACT_BATCH_SYSTEM},
            {"role": "user", "content": blob[:14000]},
        ],
        max_tokens=min(int(cfg.max_tokens or 1200), 1800),
    )
    data = _parse_json(raw)
    items = data.get("findings", []) if isinstance(data, dict) else data
    out: list[tuple[int, dict]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item.get("i", 0))
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= len(docs):
            continue
        value = str(item.get("value") or "").strip()
        if len(value) < 4:
            continue
        sev = str(item.get("severity") or "high").lower()
        if sev not in SEV:
            sev = "high"
        out.append(
            (
                idx,
                {
                    "type": str(item.get("type") or "LLM secret")[:80],
                    "severity": sev,
                    "value": value[:400],
                    "context": str(item.get("context") or "")[:240],
                    "masked": store_secret(value),
                },
            )
        )
    return out[:40]


async def extract_live_secrets_batch(cfg: LlmConfig, docs: list[tuple[str, str]]) -> list[tuple[int, dict]]:
    if not docs:
        return []
    blob = "\n".join(f"--- doc {i} ---\nURL: {url}\n{text[:3000]}\n" for i, (url, text) in enumerate(docs))
    raw = await chat(
        cfg,
        [
            {"role": "system", "content": LIVE_EXTRACT_SYSTEM},
            {"role": "user", "content": blob[:16000]},
        ],
        max_tokens=min(int(cfg.max_tokens or 1200), 2000),
    )
    data = _parse_json(raw)
    items = data.get("findings", []) if isinstance(data, dict) else data
    out: list[tuple[int, dict]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        try:
            idx = int(item.get("i", 0))
        except (TypeError, ValueError):
            continue
        if idx < 0 or idx >= len(docs):
            continue
        value = str(item.get("value") or "").strip()
        if len(value) < 4:
            continue
        sev = str(item.get("severity") or "high").lower()
        if sev not in SEV:
            sev = "high"
        out.append(
            (
                idx,
                {
                    "type": str(item.get("type") or "Live secret")[:80],
                    "severity": sev,
                    "value": value[:400],
                    "context": str(item.get("context") or "")[:240],
                    "masked": store_secret(value),
                },
            )
        )
    return out[:40]
