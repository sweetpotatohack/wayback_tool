from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _engine():
    url = get_settings().resolved_db_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args, future=True)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


engine = _engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _migrate_sqlite_columns()


def _migrate_sqlite_columns() -> None:
    url = get_settings().resolved_db_url()
    if not url.startswith("sqlite"):
        return
    wanted = {
        "users": {
            "llm_enabled": "BOOLEAN DEFAULT 0",
            "llm_base_url": "VARCHAR(255) DEFAULT ''",
            "llm_api_path": "VARCHAR(120) DEFAULT '/v1/chat/completions'",
            "llm_model": "VARCHAR(160) DEFAULT ''",
            "llm_api_key": "VARCHAR(255) DEFAULT ''",
            "llm_temperature": "FLOAT DEFAULT 0.2",
            "llm_max_tokens": "INTEGER DEFAULT 1200",
            "llm_timeout": "INTEGER DEFAULT 180",
            "smtp_enabled": "BOOLEAN DEFAULT 0",
            "smtp_host": "VARCHAR(255) DEFAULT ''",
            "smtp_port": "INTEGER DEFAULT 587",
            "smtp_user": "VARCHAR(255) DEFAULT ''",
            "smtp_password": "VARCHAR(255) DEFAULT ''",
            "smtp_from": "VARCHAR(255) DEFAULT ''",
            "smtp_tls": "BOOLEAN DEFAULT 1",
            "notify_attach_screenshots": "BOOLEAN DEFAULT 1",
        },
        "projects": {
            "date_from": "VARCHAR(14) DEFAULT ''",
            "date_to": "VARCHAR(14) DEFAULT ''",
            "extra_keywords": "TEXT DEFAULT ''",
            "extra_extensions": "TEXT DEFAULT ''",
            "scan_javascript": "BOOLEAN DEFAULT 1",
            "follow_robots": "BOOLEAN DEFAULT 1",
            "include_non200": "BOOLEAN DEFAULT 0",
            "include_recon": "BOOLEAN DEFAULT 1",
            "use_llm": "BOOLEAN DEFAULT 1",
            "llm_extract": "BOOLEAN DEFAULT 1",
            "llm_review": "BOOLEAN DEFAULT 1",
            "llm_max_calls": "INTEGER DEFAULT 25",
            "url_allow_pattern": "TEXT DEFAULT ''",
            "url_deny_pattern": "TEXT DEFAULT ''",
            "include_commoncrawl": "BOOLEAN DEFAULT 1",
            "crawl_html_links": "BOOLEAN DEFAULT 1",
            "multi_snapshot_disclosure": "BOOLEAN DEFAULT 1",
            "enable_dorks": "BOOLEAN DEFAULT 1",
            "dork_tier": "VARCHAR(16) DEFAULT 'stable500'",
            "enable_live_probe": "BOOLEAN DEFAULT 0",
            "enable_live_crawl": "BOOLEAN DEFAULT 0",
            "live_auth_type": "VARCHAR(16) DEFAULT 'none'",
            "live_auth_user": "VARCHAR(120) DEFAULT ''",
            "live_auth_pass": "VARCHAR(255) DEFAULT ''",
            "live_auth_cookie": "TEXT DEFAULT ''",
            "live_auth_header": "TEXT DEFAULT ''",
            "live_crawl_max_pages": "INTEGER DEFAULT 80",
            "live_crawl_max_depth": "INTEGER DEFAULT 3",
            "enable_osint": "BOOLEAN DEFAULT 1",
            "enable_bbot": "BOOLEAN DEFAULT 0",
            "bbot_allow_deadly": "BOOLEAN DEFAULT 0",
            "llm_unlimited": "BOOLEAN DEFAULT 0",
            "live_crawl_pages_unlimited": "BOOLEAN DEFAULT 0",
            "live_crawl_depth_unlimited": "BOOLEAN DEFAULT 0",
            "live_crawl_rps": "INTEGER DEFAULT 30",
            "live_crawl_rps_unlimited": "BOOLEAN DEFAULT 0",
            "max_urls_unlimited": "BOOLEAN DEFAULT 0",
            "max_snapshot_fetches_unlimited": "BOOLEAN DEFAULT 0",
            "schedule_json": "TEXT DEFAULT ''",
        },
    }
    with engine.begin() as conn:
        for table, cols in wanted.items():
            existing = {
                row[1]
                for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
            }
            for name, ddl in cols.items():
                if name in existing:
                    continue
                conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
