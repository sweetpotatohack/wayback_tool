from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import urlparse


def line_col_at(text: str, offset: int) -> tuple[int, int]:
    if offset < 0:
        offset = 0
    head = text[:offset]
    line = head.count("\n") + 1
    col = offset - head.rfind("\n")
    return line, max(col, 1)


def source_label(url: str) -> str:
    if " → " in url:
        base, method = url.split(" → ", 1)
        file = PurePosixPath(urlparse(base).path).name or urlparse(base).netloc
        return f"API {method} ({file})"
    path = urlparse(url).path or url
    name = PurePosixPath(path).name or urlparse(url).netloc or url
    return name


def format_evidence(
    source_url: str,
    text: str,
    start: int,
    end: int,
    *,
    extra: str = "",
) -> str:
    line, col = line_col_at(text, start)
    label = source_label(source_url)
    snippet = re.sub(r"\s+", " ", text[max(0, start - 60) : min(len(text), end + 60)]).strip()
    snippet = snippet[:320]
    loc = f"[{label}:{line}:{col}]"
    if extra:
        return f"{loc} {extra} · …{snippet}…"
    return f"{loc} …{snippet}…"


def format_context(source_url: str, context: str, value: str = "") -> str:
    label = source_label(source_url)
    ctx = (context or "").strip()
    if value and value in ctx:
        idx = ctx.find(value)
        if idx >= 0:
            return format_evidence(source_url, ctx, idx, idx + len(value), extra=ctx[max(0, idx - 20) : idx + len(value) + 20][:120])
    if ctx.startswith("["):
        return ctx
    return f"[{label}] {ctx[:400]}"


def parse_evidence_loc(evidence: str) -> dict[str, str]:
    m = re.match(r"^\[([^:\]]+):(\d+):(\d+)\]\s*(.*)$", evidence or "", re.S)
    if not m:
        return {"file": "", "line": "", "col": "", "snippet": evidence or ""}
    return {
        "file": m.group(1),
        "line": m.group(2),
        "col": m.group(3),
        "snippet": m.group(4).strip(),
    }
