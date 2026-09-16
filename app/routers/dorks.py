from fastapi import APIRouter, Depends, Query

from app.deps import require_user
from app.models import User
from app.services.dork_parser import GOOGLE_DORKS_FILE
from app.services.dorks import BUILTIN_DORK_LIBRARY, dork_categories, dork_stats, get_dork_library

router = APIRouter(prefix="/api/dorks", tags=["dorks"])


@router.get("")
def list_dorks(
    _user: User = Depends(require_user),
    per_category: int = Query(40, ge=5, le=200),
):
    stats = dork_stats()
    cats = dork_categories()
    return {
        "stats": stats,
        "builtin_count": len(BUILTIN_DORK_LIBRARY),
        "total_active": stats.get("merged_total", 0),
        "google_file": str(GOOGLE_DORKS_FILE),
        "categories": {
            name: [
                {
                    "id": d.id,
                    "title": d.title,
                    "severity": d.severity,
                    "path": d.path,
                    "has_cdx": bool(d.cdx_filter),
                    "has_cc": bool(d.cc_suffix),
                }
                for d in items[:per_category]
            ]
            for name, items in cats.items()
        },
    }


@router.get("/search")
def search_raw_dorks(
    q: str = Query("", min_length=1, max_length=120),
    _user: User = Depends(require_user),
    limit: int = Query(50, ge=1, le=200),
):
    needle = q.lower()
    hits: list[str] = []
    if GOOGLE_DORKS_FILE.exists():
        for line in GOOGLE_DORKS_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
            if needle in line.lower():
                hits.append(line.strip())
                if len(hits) >= limit:
                    break
    lib = [d for d in get_dork_library() if needle in d.title.lower()][:limit]
    return {
        "query": q,
        "raw_hits": hits,
        "parsed": [
            {"id": d.id, "title": d.title, "severity": d.severity, "category": d.category}
            for d in lib
        ],
    }
