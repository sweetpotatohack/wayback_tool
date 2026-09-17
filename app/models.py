from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_bootstrap_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    display_name: Mapped[str] = mapped_column(String(120), default="")
    avatar_file: Mapped[str | None] = mapped_column(String(255), nullable=True)
    theme_preset: Mapped[str] = mapped_column(String(32), default="archive")
    accent: Mapped[str] = mapped_column(String(16), default="#d4894a")
    radius: Mapped[str] = mapped_column(String(8), default="12")
    density: Mapped[str] = mapped_column(String(20), default="comfortable")
    font_scale: Mapped[float] = mapped_column(default=1.0)
    grain: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_email_to: Mapped[str] = mapped_column(String(255), default="")
    notify_telegram: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_bot_token: Mapped[str] = mapped_column(String(255), default="")
    telegram_chat_id: Mapped[str] = mapped_column(String(64), default="")
    notify_min_severity: Mapped[str] = mapped_column(String(16), default="high")
    smtp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    smtp_host: Mapped[str] = mapped_column(String(255), default="")
    smtp_port: Mapped[int] = mapped_column(Integer, default=587)
    smtp_user: Mapped[str] = mapped_column(String(255), default="")
    smtp_password: Mapped[str] = mapped_column(String(255), default="")
    smtp_from: Mapped[str] = mapped_column(String(255), default="")
    smtp_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_attach_screenshots: Mapped[bool] = mapped_column(Boolean, default=True)
    outbound_proxy_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    outbound_proxy_type: Mapped[str] = mapped_column(String(16), default="socks5")
    outbound_proxy_host: Mapped[str] = mapped_column(String(255), default="127.0.0.1")
    outbound_proxy_port: Mapped[int] = mapped_column(Integer, default=10808)
    outbound_proxy_user: Mapped[str] = mapped_column(String(120), default="")
    outbound_proxy_password: Mapped[str] = mapped_column(String(255), default="")
    outbound_proxy_vless: Mapped[str] = mapped_column(Text, default="")
    llm_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    llm_base_url: Mapped[str] = mapped_column(String(255), default="")
    llm_api_path: Mapped[str] = mapped_column(String(120), default="/v1/chat/completions")
    llm_model: Mapped[str] = mapped_column(String(160), default="")
    llm_api_key: Mapped[str] = mapped_column(String(255), default="")
    llm_temperature: Mapped[float] = mapped_column(default=0.2)
    llm_max_tokens: Mapped[int] = mapped_column(Integer, default=1200)
    llm_timeout: Mapped[int] = mapped_column(Integer, default=180)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    projects: Mapped[list[Project]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    targets: Mapped[str] = mapped_column(Text, default="")
    include_subdomains: Mapped[bool] = mapped_column(Boolean, default=True)
    inspect_snapshots: Mapped[bool] = mapped_column(Boolean, default=True)
    max_urls: Mapped[int] = mapped_column(Integer, default=8000)
    max_urls_unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    max_snapshot_fetches: Mapped[int] = mapped_column(Integer, default=80)
    max_snapshot_fetches_unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    date_from: Mapped[str] = mapped_column(String(14), default="")
    date_to: Mapped[str] = mapped_column(String(14), default="")
    extra_keywords: Mapped[str] = mapped_column(Text, default="")
    extra_extensions: Mapped[str] = mapped_column(Text, default="")
    scan_javascript: Mapped[bool] = mapped_column(Boolean, default=True)
    follow_robots: Mapped[bool] = mapped_column(Boolean, default=True)
    include_non200: Mapped[bool] = mapped_column(Boolean, default=False)
    include_recon: Mapped[bool] = mapped_column(Boolean, default=True)
    use_llm: Mapped[bool] = mapped_column(Boolean, default=True)
    llm_extract: Mapped[bool] = mapped_column(Boolean, default=True)
    llm_review: Mapped[bool] = mapped_column(Boolean, default=False)
    llm_max_calls: Mapped[int] = mapped_column(Integer, default=40)
    llm_unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    url_allow_pattern: Mapped[str] = mapped_column(Text, default="")
    url_deny_pattern: Mapped[str] = mapped_column(Text, default="")
    include_commoncrawl: Mapped[bool] = mapped_column(Boolean, default=True)
    crawl_html_links: Mapped[bool] = mapped_column(Boolean, default=True)
    multi_snapshot_disclosure: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_dorks: Mapped[bool] = mapped_column(Boolean, default=True)
    dork_tier: Mapped[str] = mapped_column(String(16), default="stable500")
    enable_live_probe: Mapped[bool] = mapped_column(Boolean, default=False)
    enable_live_crawl: Mapped[bool] = mapped_column(Boolean, default=False)
    enable_osint: Mapped[bool] = mapped_column(Boolean, default=True)
    enable_bbot: Mapped[bool] = mapped_column(Boolean, default=False)
    bbot_allow_deadly: Mapped[bool] = mapped_column(Boolean, default=False)
    live_auth_type: Mapped[str] = mapped_column(String(16), default="none")
    live_auth_user: Mapped[str] = mapped_column(String(120), default="")
    live_auth_pass: Mapped[str] = mapped_column(String(255), default="")
    live_auth_cookie: Mapped[str] = mapped_column(Text, default="")
    live_auth_header: Mapped[str] = mapped_column(Text, default="")
    live_crawl_max_pages: Mapped[int] = mapped_column(Integer, default=80)
    live_crawl_max_depth: Mapped[int] = mapped_column(Integer, default=3)
    live_crawl_pages_unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    live_crawl_depth_unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    live_crawl_rps: Mapped[int] = mapped_column(Integer, default=30)
    live_crawl_rps_unlimited: Mapped[bool] = mapped_column(Boolean, default=False)
    schedule: Mapped[str] = mapped_column(String(20), default="off")
    schedule_json: Mapped[str] = mapped_column(Text, default="")
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    owner: Mapped[User] = relationship(back_populates="projects")
    scans: Mapped[list[Scan]] = relationship(back_populates="project", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="project", cascade="all, delete-orphan")
    archive_urls: Mapped[list[ArchiveUrl]] = relationship(back_populates="project", cascade="all, delete-orphan")
    project_hosts: Mapped[list["ProjectHost"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class ProjectHost(Base):
    __tablename__ = "project_hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    apex: Mapped[str] = mapped_column(String(255), default="", index=True)
    source: Mapped[str] = mapped_column(String(24), default="bbot")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="project_hosts")


class ArchiveUrl(Base):
    __tablename__ = "archive_urls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    original_url: Mapped[str] = mapped_column(Text)
    capture_ts: Mapped[str] = mapped_column(String(20), default="")
    mimetype: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(8), default="")
    source: Mapped[str] = mapped_column(String(24), default="cdx")
    candidate: Mapped[bool] = mapped_column(Boolean, default=False)
    interesting: Mapped[bool] = mapped_column(Boolean, default=False)
    pattern: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="archive_urls")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    stage: Mapped[str] = mapped_column(String(255), default="В очереди")
    log: Mapped[str] = mapped_column(Text, default="")
    urls_seen: Mapped[int] = mapped_column(Integer, default=0)
    snapshots_fetched: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(64), default="")
    title: Mapped[str] = mapped_column(String(255))
    original_url: Mapped[str] = mapped_column(Text)
    archive_url: Mapped[str] = mapped_column(Text, default="")
    capture_ts: Mapped[str] = mapped_column(String(20), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    masked_secret: Mapped[str] = mapped_column(Text, default="")
    pattern: Mapped[str] = mapped_column(String(80), default="")
    source: Mapped[str] = mapped_column(String(32), default="url")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="findings")
    scan: Mapped[Scan | None] = relationship(back_populates="findings")
