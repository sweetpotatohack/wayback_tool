from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from app import DATA_DIR, DB_FILE, SECRET_FILE


def _ensure_secret_key(explicit: str) -> str:
    if explicit:
        return explicit
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    import secrets

    key = secrets.token_hex(32)
    SECRET_FILE.write_text(key, encoding="utf-8")
    return key


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="GHOSTINDEX_",
        extra="ignore",
    )

    app_name: str = "GhostIndex"
    secret_key: str = ""
    database_url: str = ""
    host: str = "0.0.0.0"
    port: int = 8787
    keep_admin: bool = False
    cookie_secure: bool = False
    session_hours: int = 72
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: bool = True
    wayback_delay_ms: int = 400
    wayback_user_agent: str = "GhostIndex/1.0 (authorized archive review; +https://web.archive.org/)"
    wayback_timeout: float = 30.0
    bbot_bin: str = "bbot"
    bbot_flags: str = "subdomain-enum,email-enum,cloud-enum,web-basic"
    bbot_modules: str = "http,portscan,gowitness,nuclei"
    bbot_output_modules: str = "csv,json,txt,subdomains,emails"
    bbot_timeout_seconds: int = 7200
    bbot_allow_deadly: bool = True
    http_proxy: str = ""
    https_proxy: str = ""
    telegram_api_base: str = "https://api.telegram.org"

    def resolved_secret(self) -> str:
        return _ensure_secret_key(self.secret_key)

    def resolved_db_url(self) -> str:
        if self.database_url:
            return self.database_url
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{DB_FILE.as_posix()}"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Path(DATA_DIR / "avatars").mkdir(parents=True, exist_ok=True)
    return settings
