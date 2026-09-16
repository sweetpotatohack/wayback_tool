from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import Project

_JWT = re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


@dataclass(frozen=True)
class LiveAuth:
    auth_type: str = "none"
    username: str = ""
    password: str = ""
    cookie: str = ""
    header_blob: str = ""

    @property
    def active(self) -> bool:
        return self.auth_type not in {"", "none"}

    def _jwt_token(self) -> str:
        for blob in (self.header_blob, self.password, self.cookie):
            text = (blob or "").strip()
            if not text:
                continue
            if text.lower().startswith("authorization:"):
                text = text.split(":", 1)[1].strip()
            if text.lower().startswith("bearer "):
                return text
            if _JWT.match(text):
                return f"Bearer {text}"
        return ""

    def request_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.auth_type == "cookie" and self.cookie:
            headers["Cookie"] = parse_cookie_blob(self.cookie)
        if self.auth_type == "header" and self.header_blob:
            headers.update(parse_header_blob(self.header_blob))
        jwt = self._jwt_token()
        if jwt:
            headers["Authorization"] = jwt
        if self.auth_type == "header" or jwt:
            headers.setdefault("Accept", "application/json, text/plain, */*")
        return headers

    def basic_auth(self) -> tuple[str, str] | None:
        if self.auth_type != "basic" or not self.username:
            return None
        if self._jwt_token():
            return None
        return self.username, self.password

    def effective_mode(self) -> str:
        if self._jwt_token():
            return "bearer"
        if self.auth_type == "basic" and self.username:
            return "basic"
        if self.auth_type == "cookie" and self.cookie:
            return "cookie"
        if self.auth_type == "header" and self.header_blob:
            return "header"
        return self.auth_type


def parse_header_blob(blob: str) -> dict[str, str]:
    """Parse Authorization / custom headers from user paste or Burp raw."""
    headers: dict[str, str] = {}
    text = (blob or "").strip()
    if not text:
        return headers
    skip = {"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "priority"}
    for line in re.split(r"[\n\r]+", text):
        line = line.strip()
        if not line or line.startswith("HTTP/") or line.startswith("POST ") or line.startswith("GET "):
            continue
        if ":" in line:
            name, value = line.split(":", 1)
            key = name.strip()
            if key.lower() in skip or key.lower().startswith("sec-"):
                continue
            headers[key] = value.strip()
        elif _JWT.match(line):
            headers["Authorization"] = f"Bearer {line}"
        elif line.lower().startswith("bearer "):
            headers["Authorization"] = line
        else:
            headers["Authorization"] = line
    return headers


def parse_cookie_blob(blob: str) -> str:
    text = (blob or "").strip()
    if text.lower().startswith("cookie:"):
        return text.split(":", 1)[1].strip()
    return text


def build_live_auth(project: Project) -> LiveAuth:
    auth_type = (getattr(project, "live_auth_type", "") or "none").strip().lower()
    if auth_type not in {"none", "basic", "cookie", "header"}:
        auth_type = "none"
    header = (getattr(project, "live_auth_header", "") or "").strip()
    password = getattr(project, "live_auth_pass", "") or ""
    cookie = parse_cookie_blob(getattr(project, "live_auth_cookie", "") or "")
    if auth_type == "basic" and not header and (_JWT.match(password.strip()) if password else False):
        header = password.strip()
    return LiveAuth(
        auth_type=auth_type,
        username=(getattr(project, "live_auth_user", "") or "").strip(),
        password=password,
        cookie=cookie,
        header_blob=header,
    )
