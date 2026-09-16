"""Persist discovered hosts (BBOT subdomains, CDX, archive) for NetWay and recon."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.models import ArchiveUrl, Finding, Project, ProjectHost, Scan
from app.services.bbot import BBOT_ROOT, parse_bbot_output, scan_output_dir
from app.services.wayback import apex_domain, normalize_target


def _host_from_url(url: str) -> str:
    from urllib.parse import urlparse

    if not url:
        return ""
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw.lstrip("/")
    try:
        host = urlparse(raw).netloc.lower().split("@")[-1].split(":")[0]
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


def _read_bbot_subdomains(scan_id: str) -> list[str]:
    out_dir = scan_output_dir(scan_id)
    if not out_dir.is_dir():
        return []
    for sub_path in (out_dir / "subdomains.txt", out_dir / "scan" / "subdomains.txt"):
        if sub_path.is_file():
            hosts = []
            for line in sub_path.read_text(encoding="utf-8", errors="replace").splitlines():
                host = normalize_target(line.strip())
                if host and "." in host:
                    hosts.append(host)
            if hosts:
                return sorted(set(hosts))
    try:
        parsed = parse_bbot_output(out_dir, scan_id=scan_id)
        return list(parsed.subdomains)
    except Exception:
        return []


def collect_hosts_for_project(db: Session, project_id: str) -> dict[str, str]:
    """Return host -> source (bbot, cdx, archive, seed)."""
    found: dict[str, str] = {}
    project = db.get(Project, project_id)
    if project and project.targets:
        from app.services.wayback import parse_targets

        for h in parse_targets(project.targets):
            host = normalize_target(h)
            if host:
                found[host] = "seed"

    for row in db.query(ArchiveUrl.original_url).filter(ArchiveUrl.project_id == project_id).all():
        host = _host_from_url(row[0])
        if host and host not in found:
            found[host] = "archive"

    scans = (
        db.query(Scan.id)
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )
    for (scan_id,) in scans:
        for host in _read_bbot_subdomains(scan_id):
            if host not in found or found[host] != "bbot":
                found[host] = "bbot"

    for f in db.query(Finding).filter(
        Finding.project_id == project_id,
        Finding.category.in_(("bbot-dns", "exposed-mail", "exposed-service", "exposed-db")),
    ):
        host = _host_from_url(f.original_url or f.title.replace("Subdomain:", ""))
        if not host and ":" in (f.title or ""):
            import re

            m = re.search(r"([a-z0-9._-]+):(\d+)", f.title or "", re.I)
            if m:
                host = m.group(1).lower()
        if host and host not in found:
            found[host] = f.source or "finding"

    return found


def sync_project_hosts(db: Session, project_id: str, scan_id: str | None = None) -> int:
    hosts = collect_hosts_for_project(db, project_id)
    db.query(ProjectHost).filter(ProjectHost.project_id == project_id).delete()
    rows: list[ProjectHost] = []
    for host, source in sorted(hosts.items()):
        rows.append(
            ProjectHost(
                project_id=project_id,
                scan_id=scan_id,
                host=host,
                source=source,
                apex=apex_domain(host),
            )
        )
    if rows:
        db.bulk_save_objects(rows)
    db.commit()
    return len(rows)


def ensure_subdomain_findings(db: Session, project_id: str, scan_id: str | None = None) -> int:
    """Add info-level bbot-dns findings for hosts not yet in findings table."""
    from app.models import Project

    project = db.get(Project, project_id)
    if not project:
        return 0
    from app.services.wayback import parse_targets

    scope_apexes = {apex_domain(h) for h in parse_targets(project.targets or "")}
    hosts = collect_hosts_for_project(db, project_id)
    existing = {
        canonical_url(f.original_url)
        for f in db.query(Finding.original_url).filter(
            Finding.project_id == project_id,
            Finding.category == "bbot-dns",
        )
    }
    added = 0
    sid = scan_id or (
        db.query(Scan.id)
        .filter(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .limit(1)
        .scalar()
    )
    for sf in subdomain_findings_from_hosts(
        hosts,
        project_id=project_id,
        scan_id=sid or "",
        scope_apexes=scope_apexes,
    ):
        key = canonical_url(sf.original_url)
        if key in existing:
            continue
        db.add(sf)
        existing.add(key)
        added += 1
    if added:
        db.commit()
    return added


def canonical_url(url: str) -> str:
    from app.services.classifier import canonical_url as _cu

    return _cu(url)


def subdomain_findings_from_hosts(
    hosts: dict[str, str],
    *,
    project_id: str,
    scan_id: str,
    scope_apexes: set[str],
) -> list:
    from app.models import Finding

    out: list[Finding] = []
    for host, source in hosts.items():
        if not any(host == ap or host.endswith("." + ap) for ap in scope_apexes):
            continue
        if host in scope_apexes:
            continue
        src = "bbot" if source == "bbot" else "recon"
        out.append(
            Finding(
                project_id=project_id,
                scan_id=scan_id,
                severity="info",
                category="bbot-dns",
                title=f"Subdomain: {host}",
                original_url=f"https://{host}/",
                archive_url=f"https://{host}/",
                capture_ts="",
                evidence=f"источник: {source}",
                pattern="bbot-dns_name",
                source=src,
            )
        )
    return out
