from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    display_name: str = Field(default="", max_length=120)


class LoginIn(BaseModel):
    username: str
    password: str


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=4000)
    targets: str = Field(min_length=1, max_length=20000)
    include_subdomains: bool = True
    inspect_snapshots: bool = True
    max_urls: int = Field(default=8000, ge=50, le=100000)
    max_urls_unlimited: bool = False
    max_snapshot_fetches: int = Field(default=80, ge=0, le=500)
    max_snapshot_fetches_unlimited: bool = False
    schedule: str = Field(default="off")
    authorized: bool = False
    date_from: str = Field(default="", max_length=14)
    date_to: str = Field(default="", max_length=14)
    extra_keywords: str = Field(default="", max_length=2000)
    extra_extensions: str = Field(default="", max_length=500)
    scan_javascript: bool = True
    follow_robots: bool = True
    include_non200: bool = False
    include_recon: bool = True
    use_llm: bool = True
    llm_extract: bool = True
    llm_review: bool = False
    llm_max_calls: int = Field(default=40, ge=1, le=100)
    llm_unlimited: bool = False
    url_allow_pattern: str = Field(default="", max_length=4000)
    url_deny_pattern: str = Field(default="", max_length=4000)
    include_commoncrawl: bool = True
    crawl_html_links: bool = True
    multi_snapshot_disclosure: bool = True
    enable_dorks: bool = True
    dork_tier: str = Field(default="stable500", max_length=16)
    enable_live_probe: bool = False
    enable_live_crawl: bool = False
    enable_osint: bool = True
    enable_bbot: bool = False
    bbot_allow_deadly: bool = False
    live_auth_type: str = Field(default="none", max_length=16)
    live_auth_user: str = Field(default="", max_length=120)
    live_auth_pass: str = Field(default="", max_length=255)
    live_auth_cookie: str = Field(default="", max_length=8000)
    live_auth_header: str = Field(default="", max_length=8000)
    live_crawl_max_pages: int = Field(default=80, ge=1, le=1000)
    live_crawl_max_depth: int = Field(default=3, ge=1, le=1000)
    live_crawl_pages_unlimited: bool = False
    live_crawl_depth_unlimited: bool = False
    live_crawl_rps: int = Field(default=30, ge=10, le=200)
    live_crawl_rps_unlimited: bool = False
    schedule_json: str = Field(default="", max_length=12000)


class ScheduleIn(BaseModel):
    schedule_json: str = Field(default="", max_length=12000)


class PasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class EmailIn(BaseModel):
    email: EmailStr
    current_password: str


class ThemeIn(BaseModel):
    theme_preset: str = "archive"
    accent: str = "#d4894a"
    radius: str = "12"
    density: str = "comfortable"
    font_scale: float = 1.0
    grain: bool = True


class NotifyIn(BaseModel):
    notify_email: bool = True
    notify_telegram: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    notify_min_severity: str = "high"
    notify_attach_screenshots: bool = True


class SmtpIn(BaseModel):
    smtp_enabled: bool = False
    smtp_host: str = Field(default="", max_length=255)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_user: str = Field(default="", max_length=255)
    smtp_password: str = Field(default="", max_length=255)
    smtp_from: str = Field(default="", max_length=255)
    smtp_tls: bool = True


class LlmIn(BaseModel):
    llm_enabled: bool = False
    llm_base_url: str = Field(default="", max_length=255)
    llm_api_path: str = Field(default="/v1/chat/completions", max_length=120)
    llm_model: str = Field(default="", max_length=160)
    llm_api_key: str = Field(default="", max_length=255)
    llm_temperature: float = Field(default=0.2, ge=0, le=2)
    llm_max_tokens: int = Field(default=1200, ge=16, le=8000)
    llm_timeout: int = Field(default=180, ge=10, le=600)
