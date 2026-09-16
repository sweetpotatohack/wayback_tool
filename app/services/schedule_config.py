from __future__ import annotations

import json
import uuid
from typing import Any

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

WEEKDAY_LABELS = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"]


def _empty_config() -> dict[str, Any]:
    return {"enabled": False, "rules": []}


def parse_schedule_config(raw: str | dict | None) -> dict[str, Any]:
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return _empty_config()
    else:
        return _empty_config()
    if not isinstance(data, dict):
        return _empty_config()
    rules: list[dict] = []
    for item in data.get("rules") or []:
        if not isinstance(item, dict):
            continue
        rule_type = str(item.get("type") or "").strip().lower()
        rid = str(item.get("id") or uuid.uuid4().hex[:10])
        if rule_type == "every":
            minutes = int(item.get("minutes") or 0)
            if minutes < 5:
                continue
            rules.append({"id": rid, "type": "every", "minutes": min(minutes, 7 * 24 * 60)})
        elif rule_type == "daily":
            hour = min(max(int(item.get("hour", 9)), 0), 23)
            minute = min(max(int(item.get("minute", 0)), 0), 59)
            rules.append({"id": rid, "type": "daily", "hour": hour, "minute": minute})
        elif rule_type == "weekly":
            hour = min(max(int(item.get("hour", 9)), 0), 23)
            minute = min(max(int(item.get("minute", 0)), 0), 59)
            days_raw = item.get("weekdays") or item.get("days") or [0, 1, 2, 3, 4]
            days = sorted({min(max(int(d), 0), 6) for d in days_raw if str(d).isdigit() or isinstance(d, int)})
            if not days:
                days = [0]
            rules.append({"id": rid, "type": "weekly", "hour": hour, "minute": minute, "weekdays": days})
    enabled = bool(data.get("enabled")) and bool(rules)
    return {"enabled": enabled, "rules": rules}


def legacy_schedule_to_config(schedule: str) -> dict[str, Any]:
    mapping = {
        "hourly": [{"type": "every", "minutes": 60}],
        "every_6h": [{"type": "every", "minutes": 360}],
        "daily": [{"type": "daily", "hour": 9, "minute": 0}],
        "weekly": [{"type": "weekly", "hour": 9, "minute": 0, "weekdays": [0]}],
    }
    rules = mapping.get(schedule or "")
    if not rules:
        return _empty_config()
    out = []
    for r in rules:
        out.append({"id": uuid.uuid4().hex[:10], **r})
    return {"enabled": True, "rules": out}


def schedule_config_for_project(project) -> dict[str, Any]:
    raw = getattr(project, "schedule_json", "") or ""
    cfg = parse_schedule_config(raw)
    if cfg["rules"]:
        return cfg
    legacy = getattr(project, "schedule", "off") or "off"
    if legacy != "off":
        return legacy_schedule_to_config(legacy)
    return _empty_config()


def schedule_summary(cfg: dict[str, Any]) -> str:
    if not cfg.get("enabled") or not cfg.get("rules"):
        return "Только вручную"
    parts: list[str] = []
    for rule in cfg["rules"]:
        if rule["type"] == "every":
            m = int(rule["minutes"])
            if m % 1440 == 0:
                parts.append(f"каждые {m // 1440} д.")
            elif m % 60 == 0:
                parts.append(f"каждые {m // 60} ч.")
            else:
                parts.append(f"каждые {m} мин.")
        elif rule["type"] == "daily":
            parts.append(f"ежедн. {rule['hour']:02d}:{rule['minute']:02d}")
        elif rule["type"] == "weekly":
            days = ", ".join(WEEKDAY_LABELS[d] for d in rule.get("weekdays", []) if 0 <= d < 7)
            parts.append(f"{days} {rule['hour']:02d}:{rule['minute']:02d}")
    return " · ".join(parts) if parts else "Только вручную"


def dump_schedule_config(cfg: dict[str, Any]) -> str:
    return json.dumps(parse_schedule_config(cfg), ensure_ascii=False)


def build_triggers(cfg: dict[str, Any]) -> list[tuple[str, object]]:
    """Return list of (rule_id, APScheduler trigger)."""
    triggers: list[tuple[str, object]] = []
    for rule in cfg.get("rules") or []:
        rid = rule.get("id") or uuid.uuid4().hex[:10]
        if rule["type"] == "every":
            triggers.append((rid, IntervalTrigger(minutes=int(rule["minutes"]))))
        elif rule["type"] == "daily":
            triggers.append(
                (
                    rid,
                    CronTrigger(hour=int(rule["hour"]), minute=int(rule["minute"])),
                )
            )
        elif rule["type"] == "weekly":
            dow = ",".join(str(int(d)) for d in rule.get("weekdays", [0]))
            triggers.append(
                (
                    rid,
                    CronTrigger(
                        day_of_week=dow,
                        hour=int(rule["hour"]),
                        minute=int(rule["minute"]),
                    ),
                )
            )
    return triggers


def validate_schedule_json(text: str) -> tuple[dict[str, Any], str | None]:
    try:
        cfg = parse_schedule_config(text)
    except (TypeError, ValueError) as exc:
        return _empty_config(), str(exc)
    if cfg.get("enabled") and not cfg.get("rules"):
        return cfg, "Включено расписание без правил"
    return cfg, None
