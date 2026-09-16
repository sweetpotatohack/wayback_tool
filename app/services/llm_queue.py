"""Global LLM access queue — one in-flight request to the model at a time."""

from __future__ import annotations

import asyncio
import sys
import threading
from collections import deque
from contextlib import asynccontextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Callable

from app import DATA_DIR

_LLM_LOCK_PATH = DATA_DIR / ".llm.lock"


@dataclass
class LlmContext:
    scan_id: str = ""
    project_id: str = ""
    project_name: str = ""
    log: Callable[[str], None] | None = None


_ctx: ContextVar[LlmContext | None] = ContextVar("llm_ctx", default=None)

_meta_lock = threading.Lock()
_holder: LlmContext | None = None
_waiters: deque[tuple[str, str]] = deque()
_active_requests = 0
_lock_fh = None
_thread_lock = threading.Lock()


def bind_llm_context(ctx: LlmContext) -> Token:
    return _ctx.set(ctx)


def unbind_llm_context(token: Token) -> None:
    _ctx.reset(token)


def llm_status() -> dict:
    with _meta_lock:
        holder = _holder
        waiting = list(_waiters)
        busy = _active_requests > 0
    return {
        "busy": busy,
        "holder": {
            "scan_id": holder.scan_id if holder else "",
            "project_id": holder.project_id if holder else "",
            "project_name": holder.project_name if holder else "",
        },
        "queue": [{"scan_id": s, "project_name": n} for s, n in waiting],
        "queue_len": len(waiting),
    }


def _is_busy() -> bool:
    with _meta_lock:
        return _active_requests > 0


def _blocking_acquire() -> None:
    global _lock_fh, _active_requests
    if sys.platform != "win32":
        import fcntl

        _LLM_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        _lock_fh = open(_LLM_LOCK_PATH, "a+")
        fcntl.flock(_lock_fh.fileno(), fcntl.LOCK_EX)
    else:
        _thread_lock.acquire()
    with _meta_lock:
        _active_requests += 1


def _blocking_release() -> None:
    global _lock_fh, _active_requests
    with _meta_lock:
        _active_requests = max(0, _active_requests - 1)
    if sys.platform != "win32" and _lock_fh is not None:
        import fcntl

        fcntl.flock(_lock_fh.fileno(), fcntl.LOCK_UN)
        _lock_fh.close()
        _lock_fh = None
    elif _thread_lock.locked():
        _thread_lock.release()


@asynccontextmanager
async def llm_request():
    """Wait for LLM if another scan/project holds the slot; no wait when free."""
    ctx = _ctx.get() or LlmContext()
    global _holder
    loop = asyncio.get_running_loop()

    will_wait = _is_busy()
    waiter_key = (ctx.scan_id or ctx.project_id, ctx.project_name or (ctx.scan_id[:8] if ctx.scan_id else "?"))
    if will_wait:
        with _meta_lock:
            _waiters.append(waiter_key)
            pos = len(_waiters)
            who = (_holder.project_name if _holder else "") or "другой проход"
        if ctx.log:
            ctx.log(f"LLM: ожидание очереди — занят «{who}» (позиция {pos})")

    await loop.run_in_executor(None, _blocking_acquire)
    try:
        with _meta_lock:
            if will_wait:
                try:
                    _waiters.remove(waiter_key)
                except ValueError:
                    pass
            _holder = ctx
        if will_wait and ctx.log:
            ctx.log("LLM: слот получен — запрос к модели")
        yield
    finally:
        with _meta_lock:
            if _holder is ctx:
                _holder = None
        await loop.run_in_executor(None, _blocking_release)
