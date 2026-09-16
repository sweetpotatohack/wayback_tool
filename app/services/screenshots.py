from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from PIL import Image, ImageDraw, ImageFont

from app import DATA_DIR
from app.services.wayback import Capture, is_archived_capture, replay_url
from app.services.live_content import is_wayback_miss_page

LIVE_SOURCES = frozenset({"live", "live-crawl", "bbot"})

SHOT_DIR = DATA_DIR / "screenshots"
BINARY_EXT = {
    ".zip",
    ".gz",
    ".tgz",
    ".7z",
    ".rar",
    ".sql",
    ".bak",
    ".old",
    ".pem",
    ".p12",
    ".key",
    ".exe",
    ".dll",
    ".pdf",
    ".doc",
    ".xls",
}
SKIP_PATTERNS = {"robots", "sitemap"}


def shot_id(archive_url: str) -> str:
    return hashlib.sha256((archive_url or "").encode("utf-8")).hexdigest()[:20]


def full_path(sid: str) -> Path:
    return SHOT_DIR / f"{sid}.jpg"


def thumb_path(sid: str) -> Path:
    return SHOT_DIR / f"{sid}_t.jpg"


def shot_urls(
    archive_url: str,
    original_url: str = "",
    capture_ts: str = "",
    *,
    source: str = "",
) -> dict[str, str]:
    if source in LIVE_SOURCES and original_url:
        url = original_url.split(" → ")[0]
    elif archive_url and "web.archive.org" in archive_url:
        url = archive_url
    elif capture_ts and original_url and is_archived_capture(
        Capture(original_url, capture_ts, "200", "", "", "")
    ):
        url = f"https://web.archive.org/web/{capture_ts}/{original_url}"
    elif archive_url:
        url = archive_url
    elif original_url:
        url = replay_url(original_url, capture_ts)
    else:
        url = ""
    if not url:
        return {"thumb_url": "", "shot_url": ""}
    sid = shot_id(url)
    thumb = thumb_path(sid)
    full = full_path(sid)
    return {
        "thumb_url": f"/media/screenshots/{thumb.name}" if thumb.exists() else "",
        "shot_url": f"/media/screenshots/{full.name}" if full.exists() else "",
    }


def _chrome() -> str | None:
    for name in (
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
    ):
        path = shutil.which(name)
        if path:
            return path
    return None


def _placeholder(sid: str, title: str, subtitle: str) -> None:
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (1280, 800), (28, 24, 18))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 28)
        small = ImageFont.truetype("DejaVuSans.ttf", 18)
    except OSError:
        font = ImageFont.load_default()
        small = font
    draw.text((48, 80), (title or "архив")[:80], fill=(212, 137, 74), font=font)
    y = 140
    for line in (subtitle or "").splitlines() or [""]:
        draw.text((48, y), line[:110], fill=(200, 190, 170), font=small)
        y += 28
        if y > 720:
            break
    img.save(full_path(sid), "JPEG", quality=82)
    img.resize((320, 200)).save(thumb_path(sid), "JPEG", quality=70)


def _make_thumb(sid: str) -> None:
    src = full_path(sid)
    if not src.exists():
        return
    with Image.open(src) as im:
        im = im.convert("RGB")
        im.thumbnail((320, 200))
        im.save(thumb_path(sid), "JPEG", quality=72)


def _wayback_replay_ok(open_url: str) -> bool:
    if "web.archive.org" not in (open_url or ""):
        return True
    try:
        import httpx

        response = httpx.get(open_url, timeout=18.0, follow_redirects=True)
        return response.status_code < 500 and not is_wayback_miss_page(response.text)
    except Exception:
        return False


def capture_one(
    archive_url: str,
    original_url: str = "",
    pattern: str = "",
    capture_ts: str = "",
    source: str = "",
) -> bool:
    """Render a Wayback replay page, live URL, or a placeholder to JPEG + thumbnail."""
    open_url = archive_url or original_url
    if source == "live" and original_url:
        open_url = original_url
    elif source in {"live-crawl"} and original_url:
        open_url = original_url
    elif not archive_url and original_url and source not in LIVE_SOURCES:
        open_url = replay_url(original_url, capture_ts)
    if not open_url:
        return False
    if "web.archive.org" in open_url and not _wayback_replay_ok(open_url):
        return False
    sid = shot_id(open_url)
    if full_path(sid).exists() and thumb_path(sid).exists():
        return True
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    path = urlparse(original_url or open_url).path.lower()
    ext = Path(path.rstrip("/")).suffix
    if pattern in SKIP_PATTERNS or ext in BINARY_EXT:
        _placeholder(sid, Path(path).name or pattern or "файл", original_url or open_url)
        return True
    chrome = _chrome()
    png_out = SHOT_DIR / f"{sid}.png"
    if chrome:
        try:
            subprocess.run(
                [
                    chrome,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--hide-scrollbars",
                    "--window-size=1280,800",
                    f"--screenshot={png_out}",
                    "--timeout=25000",
                    open_url,
                ],
                check=False,
                timeout=40,
                capture_output=True,
            )
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            png_out = Path()
        src = png_out if png_out.exists() and png_out.stat().st_size > 2000 else None
        if src:
            try:
                with Image.open(src) as im:
                    rgb = im.convert("RGB")
                    rgb.save(full_path(sid), "JPEG", quality=78)
                    rgb.thumbnail((320, 200))
                    rgb.save(thumb_path(sid), "JPEG", quality=72)
                src.unlink(missing_ok=True)
                return True
            except Exception:
                src.unlink(missing_ok=True)
    _placeholder(sid, "снимок", original_url or open_url)
    return True


def capture_findings(findings, *, limit: int = 400) -> int:
    done = 0
    seen: set[str] = set()
    ranked = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity, 9),
    )
    for item in ranked:
        original = item.original_url or ""
        source = getattr(item, "source", "") or ""
        capture_ts = item.capture_ts or ""
        if source not in LIVE_SOURCES and not capture_ts:
            continue
        if source in LIVE_SOURCES:
            url = original.split(" → ")[0]
        else:
            url = item.archive_url or replay_url(original, capture_ts)
        if not url or url in seen:
            continue
        if item.pattern in SKIP_PATTERNS:
            continue
        if "web.archive.org" in url and not _wayback_replay_ok(url):
            continue
        seen.add(url)
        capture_one(url, original, item.pattern, capture_ts, source)
        done += 1
        if done >= limit:
            break
    return done
