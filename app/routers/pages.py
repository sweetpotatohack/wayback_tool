from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app import APP_DIR
from app.db import get_db
from app.services.dork_tiers import effective_dork_tier
from app.deps import get_current_user, require_user
from app.models import Project, User
from app.services.dashboard_export import (
    build_export_bundle,
    content_disposition,
    export_filename,
    render_csv,
    render_html,
    render_pdf,
    render_txt,
)
from app.services.dashboard_stats import dashboard_payload, parse_period
from app.services.dashboard_wire import WIRE_FEED_LIMIT, wire_feed_items

router = APIRouter()
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

PRESET_META = {
    "archive": {"bg": "#0e0d0b", "ink": "#f0e6d4", "accent": "#d4894a", "card": "#1c1913"},
    "night": {"bg": "#07090f", "ink": "#d7e0f2", "accent": "#6ea8ff", "card": "#121826"},
    "paper": {"bg": "#f4efe4", "ink": "#2a241c", "accent": "#9c4b2d", "card": "#fffaf1"},
    "terminal": {"bg": "#050805", "ink": "#c6f2c2", "accent": "#3ddc84", "card": "#0b140b"},
}


def theme_vars(user: User | None) -> dict:
    preset = (user.theme_preset if user else "archive") or "archive"
    meta = PRESET_META.get(preset, PRESET_META["archive"])
    accent = (user.accent if user else meta["accent"]) or meta["accent"]
    radius = (user.radius if user else "12") or "12"
    density = (user.density if user else "comfortable") or "comfortable"
    scale = user.font_scale if user else 1.0
    grain = user.grain if user else True
    return {
        "preset": preset,
        "accent": accent,
        "radius": radius,
        "density": density,
        "scale": scale,
        "grain": "1" if grain else "0",
        "bg": meta["bg"],
        "ink": meta["ink"],
        "card": meta["card"],
    }


def ctx(request: Request, user: User | None, **extra):
    data = {
        "request": request,
        "user": user,
        "theme": theme_vars(user),
        "avatar_url": f"/media/avatars/{user.avatar_file}" if user and user.avatar_file else None,
    }
    data.update(extra)
    return data


def render(request: Request, name: str, user: User | None, **extra):
    return templates.TemplateResponse(request, name, ctx(request, user, **extra))


def _guard(user: User | None, need_admin: bool = False):
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.status == "pending" and not user.is_admin:
        return RedirectResponse("/pending", status_code=303)
    if user.status != "approved" and not user.is_admin:
        return RedirectResponse("/login?err=disabled", status_code=303)
    if need_admin and not user.is_admin:
        return RedirectResponse("/dashboard", status_code=303)
    return None


@router.get("/")
def root(user: User | None = Depends(get_current_user)):
    if user and (user.status == "approved" or user.is_admin):
        return RedirectResponse("/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@router.get("/login")
def login_page(request: Request, err: str = "", user: User | None = Depends(get_current_user)):
    if user and (user.status == "approved" or user.is_admin):
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "login.html", user, err=err)


@router.get("/register")
def register_page(request: Request, err: str = "", user: User | None = Depends(get_current_user)):
    return render(request, "register.html", user, err=err)


@router.get("/pending")
def pending_page(request: Request, user: User | None = Depends(get_current_user)):
    return render(request, "pending.html", user)


@router.get("/dashboard")
def dashboard(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    denied = _guard(user)
    if denied:
        return denied
    period = parse_period("all")
    stats = dashboard_payload(db, user, period)
    cards = stats["cards"]
    recent = wire_feed_items(db, user, limit=WIRE_FEED_LIMIT, period=period)
    return render(
        request,
        "dashboard.html",
        user,
        cards=cards,
        sev=stats["sev"],
        total_findings=stats["total_findings"],
        scans_running=stats["scans_running"],
        scans_completed=stats["scans_completed"],
        recent=recent,
        period=stats["period"],
        timeline=stats["timeline"],
        by_project=stats["by_project"],
        issue_date=datetime.now().strftime("%d.%m.%Y"),
    )


@router.get("/api/dashboard/stats")
def dashboard_stats_api(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    period: str = Query("all"),
    date: str = Query(""),
    date_from: str = Query(""),
    date_to: str = Query(""),
):
    filt = parse_period(period, date=date, date_from=date_from, date_to=date_to)
    return dashboard_payload(db, user, filt)


@router.get("/api/dashboard/wire-feed")
def dashboard_wire_feed(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    period: str = Query("all"),
    date: str = Query(""),
    date_from: str = Query(""),
    date_to: str = Query(""),
):
    filt = parse_period(period, date=date, date_from=date_from, date_to=date_to)
    return {"items": wire_feed_items(db, user, limit=WIRE_FEED_LIMIT, period=filt)}


@router.get("/api/dashboard/export")
def dashboard_export(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    format: str = Query("csv", alias="format"),
    period: str = Query("all"),
    date: str = Query(""),
    date_from: str = Query(""),
    date_to: str = Query(""),
    project_id: str = Query("all"),
):
    fmt = (format or "csv").strip().lower()
    if fmt not in {"csv", "txt", "html", "pdf"}:
        raise HTTPException(400, "format: csv, txt, html или pdf")
    filt = parse_period(period, date=date, date_from=date_from, date_to=date_to)
    with_shots = fmt in {"html", "pdf"}
    bundle = build_export_bundle(
        db,
        user,
        filt,
        project_id=project_id or "all",
        with_screenshots=with_shots,
    )
    filename = export_filename(bundle, fmt)
    disp = content_disposition(filename)
    if fmt == "csv":
        return Response(
            content=render_csv(bundle),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": disp},
        )
    if fmt == "txt":
        return Response(
            content=render_txt(bundle),
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": disp},
        )
    if fmt == "html":
        return Response(
            content=render_html(bundle).encode("utf-8"),
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": disp},
        )
    return Response(
        content=render_pdf(bundle),
        media_type="application/pdf",
        headers={"Content-Disposition": disp},
    )


@router.get("/projects")
def projects_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    denied = _guard(user)
    if denied:
        return denied
    projects = db.query(Project).filter(Project.owner_id == user.id).order_by(Project.updated_at.desc()).all()
    return render(request, "projects.html", user, projects=projects)


@router.get("/projects/new")
def project_new(request: Request, user: User | None = Depends(get_current_user)):
    denied = _guard(user)
    if denied:
        return denied
    return render(request, "project_form.html", user, project=None, dork_tier_selected="stable500")


@router.get("/projects/{project_id}")
def project_detail(project_id: str, request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    denied = _guard(user)
    if denied:
        return denied
    project = db.get(Project, project_id)
    if not project or project.owner_id != user.id:
        return RedirectResponse("/projects", status_code=303)
    return render(request, "project_detail.html", user, project=project)


@router.get("/projects/{project_id}/edit")
def project_edit(project_id: str, request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    denied = _guard(user)
    if denied:
        return denied
    project = db.get(Project, project_id)
    if not project or project.owner_id != user.id:
        return RedirectResponse("/projects", status_code=303)
    return render(request, "project_form.html", user, project=project, dork_tier_selected=effective_dork_tier(project))


@router.get("/cabinet")
def cabinet(request: Request, user: User | None = Depends(get_current_user)):
    denied = _guard(user)
    if denied:
        return denied
    token_masked = ""
    if user.telegram_bot_token:
        token_masked = "••••" + user.telegram_bot_token[-4:]
    llm_key_masked = ""
    if user.llm_api_key:
        llm_key_masked = "••••" + user.llm_api_key[-4:]
    smtp_pass_masked = ""
    if user.smtp_password:
        smtp_pass_masked = "••••" + user.smtp_password[-4:]
    return render(
        request,
        "profile.html",
        user,
        token_masked=token_masked,
        llm_key_masked=llm_key_masked,
        smtp_pass_masked=smtp_pass_masked,
    )


@router.get("/admin")
def admin_page(request: Request, user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    denied = _guard(user, need_admin=True)
    if denied:
        return denied
    users = db.query(User).order_by(User.created_at.desc()).all()
    pending = sum(1 for u in users if u.status == "pending")
    return render(request, "admin.html", user, users=users, pending=pending)

