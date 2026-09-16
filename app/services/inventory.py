from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session

from app.models import ArchiveUrl
from app.services.live_content import bodies_match, confirm_live_path_finding, host_key
from app.services.wayback import Capture, is_archived_capture

LIVE_SOURCES = frozenset({"live-crawl", "live", "bbot"})


def store_url_inventory(
    db: Session,
    *,
    project_id: str,
    scan_id: str,
    captures: list[Capture],
    klass_fn,
    source_map: dict[str, str] | None = None,
    limit: int = 15000,
) -> int:
    db.query(ArchiveUrl).filter(ArchiveUrl.project_id == project_id).delete()
    source_map = source_map or {}
    rows: list[ArchiveUrl] = []
    seen: set[str] = set()
    for cap in captures[:limit]:
        key = cap.original
        if key in seen:
            continue
        seen.add(key)
        klass = klass_fn(cap.original)
        archived = is_archived_capture(cap)
        rows.append(
            ArchiveUrl(
                project_id=project_id,
                scan_id=scan_id,
                original_url=cap.original,
                capture_ts=cap.timestamp or "",
                mimetype=cap.mimetype or "",
                status=cap.status or "",
                source=source_map.get(key, "cdx" if archived else "candidate"),
                candidate=not archived,
                interesting=bool(klass),
                pattern=klass.pattern if klass else "",
            )
        )
    if rows:
        db.bulk_save_objects(rows)
    db.commit()
    return len(rows)


def mime_summary(db: Session, project_id: str) -> list[dict]:
    rows = (
        db.query(ArchiveUrl.mimetype, ArchiveUrl.interesting)
        .filter(ArchiveUrl.project_id == project_id, ArchiveUrl.candidate.is_(False))
        .all()
    )
    counts: Counter[str] = Counter()
    interesting: Counter[str] = Counter()
    for mime, is_interesting in rows:
        key = (mime or "unknown").split(";")[0].strip() or "unknown"
        counts[key] += 1
        if is_interesting:
            interesting[key] += 1
    return [
        {"mimetype": mime, "count": count, "interesting": interesting.get(mime, 0)}
        for mime, count in counts.most_common(40)
    ]


def append_live_urls(
    db: Session,
    *,
    project_id: str,
    scan_id: str,
    urls: list[str],
    klass_fn,
    limit: int = 5000,
    pages: list | None = None,
    home_bodies: dict[str, str] | None = None,
) -> int:
    if not urls and not pages:
        return 0
    existing = {
        row[0]
        for row in db.query(ArchiveUrl.original_url).filter(ArchiveUrl.project_id == project_id).all()
    }
    page_map: dict[str, object] = {}
    if pages:
        for page in pages:
            page_map[page.url] = page
            req = getattr(page, "requested_url", "") or page.url
            page_map[req] = page
    homes = home_bodies or {}
    rows: list[ArchiveUrl] = []
    seen: set[str] = set()
    ordered = list(dict.fromkeys(urls))
    for url in ordered:
        if url in existing or url in seen:
            continue
        seen.add(url)
        page = page_map.get(url)
        text = getattr(page, "text", "") if page else ""
        ctype = getattr(page, "content_type", "") if page else ""
        req_url = getattr(page, "requested_url", url) if page else url
        home = homes.get(host_key(url), "")
        klass = klass_fn(url)
        interesting = False
        pattern = klass.pattern if klass else ""
        if klass and text:
            ok, _ = confirm_live_path_finding(
                url,
                text,
                ctype,
                klass.pattern,
                homepage_text=home,
                requested_url=req_url,
            )
            interesting = ok
            if not ok:
                pattern = ""
        elif klass:
            interesting = False
        elif url.lower().endswith((".js", ".mjs", ".json")) and text:
            interesting = not (home and bodies_match(text, home))
        rows.append(
            ArchiveUrl(
                project_id=project_id,
                scan_id=scan_id,
                original_url=url,
                capture_ts="",
                mimetype="live",
                status="200",
                source="live-crawl",
                candidate=True,
                interesting=interesting,
                pattern=pattern,
            )
        )
        if len(rows) >= limit:
            break
    if rows:
        db.bulk_save_objects(rows)
        db.commit()
    return len(rows)


def url_open_link(row: ArchiveUrl) -> str:
    if row.source in LIVE_SOURCES or row.candidate:
        return row.original_url
    if row.capture_ts:
        return f"https://web.archive.org/web/{row.capture_ts}/{row.original_url}"
    return row.original_url


def url_archive_link(row: ArchiveUrl) -> str:
    if row.source in LIVE_SOURCES or row.candidate:
        return ""
    if row.capture_ts:
        return f"https://web.archive.org/web/{row.capture_ts}/{row.original_url}"
    return ""
