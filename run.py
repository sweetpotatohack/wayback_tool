#!/usr/bin/env python3
"""Запуск GhostIndex. При первом старте сам создаёт .venv и ставит зависимости."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
REQ = ROOT / "requirements.txt"


def _venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def _in_project_venv() -> bool:
    try:
        return Path(sys.prefix).resolve() == VENV.resolve()
    except OSError:
        return False


def _venv_has_deps(py: Path) -> bool:
    probe = subprocess.run(
        [str(py), "-c", "import fastapi, uvicorn, apscheduler, sqlalchemy, jwt, bcrypt, httpx, jinja2, PIL"],
        capture_output=True,
    )
    return probe.returncode == 0


def _ensure_deps() -> None:
    py = _venv_python()
    if not py.exists():
        print("[GhostIndex] Первый запуск — создаю окружение .venv", flush=True)
        subprocess.check_call([sys.executable, "-m", "venv", str(VENV)])
    marker = VENV / ".deps-ok"
    if marker.exists() and REQ.exists() and marker.stat().st_mtime >= REQ.stat().st_mtime:
        return
    if _venv_has_deps(py):
        marker.write_text("ok\n", encoding="utf-8")
        return
    print("[GhostIndex] Ставлю зависимости (один раз, дальше просто стартует)", flush=True)
    subprocess.check_call([str(py), "-m", "pip", "install", "-r", str(REQ)])
    marker.write_text("ok\n", encoding="utf-8")


def main() -> None:
    if not _in_project_venv():
        try:
            _ensure_deps()
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            sys.exit(
                "Не удалось подготовить окружение.\n"
                "Debian / Kali / Ubuntu:\n"
                "  sudo apt update && sudo apt install -y python3 python3-venv python3-pip\n"
                "Затем снова:  python3 run.py\n"
                f"({exc})"
            )
        py = _venv_python()
        os.execv(str(py), [str(py), str(ROOT / "run.py"), *sys.argv[1:]])

    import uvicorn

    from app.config import get_settings

    settings = get_settings()
    print(f"[GhostIndex] http://{settings.host}:{settings.port}", flush=True)
    print("[GhostIndex] Выгрузка отчётов: /api/dashboard/export (CSV, TXT, HTML, PDF)", flush=True)
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    main()
