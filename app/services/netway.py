from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlparse

from app.models import ArchiveUrl, Finding, Project
from app.services.finding_display import display_title, is_hidden_finding
from app.services.wayback import apex_domain, normalize_target, parse_targets

_EMAIL_IN_TITLE = re.compile(r"(?i)^email:\s*(.+)$")
_PHONE_IN_TITLE = re.compile(r"(?i)^телефон:\s*(.+)$")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


_BBOT_URL = re.compile(r"^bbot://", re.I)


def _host_from_url(url: str) -> str:
    if not url or _BBOT_URL.match(url.strip()):
        return ""
    raw = url.strip()
    if " → " in raw:
        raw = raw.split(" → ", 1)[0]
    if raw.startswith("mailto:"):
        return ""
    if not raw.startswith(("http://", "https://")):
        if re.match(r"^[a-z0-9._-]+:\d{1,5}$", raw, re.I):
            return raw.split(":", 1)[0].lower()
        return ""
    try:
        host = urlparse(raw).netloc.lower().split("@")[-1].split(":")[0]
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    if host in {"bbot", "localhost"} or "." not in host:
        return ""
    return host


def _node(
    nodes: dict[str, dict],
    nid: str,
    *,
    ntype: str,
    label: str,
    severity: str = "",
    group: str = "",
    **meta,
) -> str:
    if nid not in nodes:
        nodes[nid] = {
            "id": nid,
            "type": ntype,
            "label": label[:120],
            "severity": severity or "",
            "group": group or ntype,
            **meta,
        }
    else:
        for key, val in meta.items():
            if val and not nodes[nid].get(key):
                nodes[nid][key] = val
    return nid


def _edge(edges: list[dict], src: str, tgt: str, kind: str) -> None:
    if src == tgt or not src or not tgt:
        return
    edges.append({"source": src, "target": tgt, "kind": kind})


def _finding_value(f: Finding) -> str:
    if f.masked_secret:
        return f.masked_secret.strip()
    m = _EMAIL_IN_TITLE.match(f.title or "")
    if m:
        return m.group(1).strip()
    m = _PHONE_IN_TITLE.match(f.title or "")
    if m:
        return m.group(1).strip()
    return ""


def _in_scope_host(host: str, scope_apexes: set[str]) -> bool:
    if not host or not scope_apexes:
        return False
    h = host.lower()
    if h.startswith("www."):
        h = h[4:]
    return any(h == ap or h.endswith("." + ap) for ap in scope_apexes)


def _scope_apex_from_finding(f: Finding, scope_apexes: set[str]) -> str:
    """Map a BBOT/scan finding back to the project target apex (e.g. terem.ru)."""
    if not scope_apexes:
        return ""
    blob = " ".join(
        x for x in (f.evidence or "", f.title or "", f.original_url or "", f.masked_secret or "") if x
    ).lower()
    for ap in sorted(scope_apexes, key=len, reverse=True):
        if ap in blob:
            return ap
    m = re.search(r"(?i)(?:storage bucket|bucket|git repo):\s*([a-z0-9._-]+)", f.title or "")
    if m:
        token = m.group(1).lower().strip(".")
        for ap in scope_apexes:
            if token == ap or token == ap.split(".")[0] or ap.startswith(f"{token}."):
                return ap
    return ""


def _ensure_apex_node(
    nodes: dict[str, dict],
    apex_ids: dict[str, str],
    ap: str,
    *,
    external: bool = False,
) -> str:
    if ap not in apex_ids:
        apex_ids[ap] = _node(
            nodes,
            f"apex:{ap}",
            ntype="apex",
            label=ap,
            group="domain",
            external=external,
        )
    return apex_ids[ap]


def _link_finding_to_scope(
    f: Finding,
    fid: str,
    hid: str,
    host: str,
    *,
    nodes: dict[str, dict],
    edges: list[dict],
    apex_ids: dict[str, str],
    scope_apexes: set[str],
) -> None:
    """Attach scan findings to the target domain, including external infra (GCS, Shodan, etc.)."""
    source = (f.source or "").lower()
    cat = (f.category or "").lower()
    if source not in {"bbot", "recon"} and not cat.startswith("bbot"):
        return
    scope_ap = _scope_apex_from_finding(f, scope_apexes)
    if not scope_ap:
        return

    scope_nid = _ensure_apex_node(nodes, apex_ids, scope_ap)
    _edge(edges, scope_nid, fid, "discovered_on")

    if host and not _in_scope_host(host, scope_apexes):
        ext_ap = apex_domain(host)
        if ext_ap and ext_ap != scope_ap:
            ext_nid = _ensure_apex_node(nodes, apex_ids, ext_ap, external=True)
            _edge(edges, scope_nid, ext_nid, "via_scan")
            if hid:
                _edge(edges, ext_nid, hid, "infra")
    elif hid and _in_scope_host(host, scope_apexes):
        ap = apex_domain(host)
        if ap in apex_ids and apex_ids[ap] != hid:
            _edge(edges, apex_ids[ap], hid, "subdomain")


def build_netway_graph(
    project: Project,
    findings: list[Finding],
    archive_rows: list[ArchiveUrl],
    project_hosts: list | None = None,
    *,
    max_hosts: int = 200,
    max_url_nodes: int = 80,
) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    targets = parse_targets(project.targets or "")

    apex_ids: dict[str, str] = {}
    scope_apexes: set[str] = set()
    for raw in targets:
        base = normalize_target(raw)
        if not base:
            continue
        ap = apex_domain(base)
        scope_apexes.add(ap)
        aid = _node(nodes, f"apex:{ap}", ntype="apex", label=ap, group="domain")
        apex_ids[ap] = aid
        if base != ap:
            hid = _node(nodes, f"host:{base}", ntype="host", label=base, group="domain", scoped=True)
            _edge(edges, aid, hid, "scope")
        else:
            _node(nodes, f"host:{base}", ntype="host", label=base, group="domain", scoped=True)

    host_url_counts: Counter[str] = Counter()
    for row in archive_rows:
        host = _host_from_url(row.original_url)
        if host:
            host_url_counts[host] += 1

    host_sources: dict[str, str] = {}
    for ph in project_hosts or []:
        host = (ph.host or "").lower().strip()
        if host:
            host_sources[host] = ph.source or "scan"
            host_url_counts[host] += 1

    for host, count in host_url_counts.most_common(max_hosts):
        hid = _node(
            nodes,
            f"host:{host}",
            ntype="host",
            label=host,
            group="domain",
            url_count=count,
            source=host_sources.get(host, ""),
        )
        ap = apex_domain(host)
        if ap in apex_ids:
            _edge(edges, apex_ids[ap], hid, "subdomain")
        elif ap:
            aid = _node(nodes, f"apex:{ap}", ntype="apex", label=ap, group="domain")
            _edge(edges, aid, hid, "subdomain")

    url_nodes_added = 0
    for row in archive_rows:
        if url_nodes_added >= max_url_nodes:
            break
        if not getattr(row, "interesting", False):
            continue
        host = _host_from_url(row.original_url)
        if not host:
            continue
        path = urlparse(row.original_url).path or "/"
        uid = _node(
            nodes,
            f"url:{row.original_url[:200]}",
            ntype="url",
            label=path[:80] or row.original_url[:80],
            group="url",
            full_url=row.original_url,
            mimetype=(row.mimetype or "").split(";")[0],
            source=getattr(row, "source", "") or "",
        )
        _edge(edges, f"host:{host}", uid, "serves")
        url_nodes_added += 1

    for f in findings:
        if is_hidden_finding(f):
            continue
        host = _host_from_url(f.original_url or "")
        if not host and (f.title or "").lower().startswith("port:"):
            m = re.search(r"([a-z0-9._-]+):(\d{1,5})", f.title, re.I)
            host = m.group(1).lower() if m else ""
        hid = f"host:{host}" if host else ""
        if hid and host != "bbot":
            _node(nodes, hid, ntype="host", label=host, group="domain")

        fid = _node(
            nodes,
            f"finding:{f.id}",
            ntype="finding",
            label=display_title(f.title or "finding")[:100],
            group="finding",
            severity=f.severity,
            category=f.category or "",
            pattern=f.pattern or "",
            source=f.source or "",
            original_url=f.original_url or "",
            archive_url=f.archive_url or "",
            evidence=(f.evidence or "")[:500],
            value=_finding_value(f),
        )
        if hid:
            _edge(edges, hid, fid, "finding")

        cat = (f.category or "").lower()
        val = _finding_value(f)
        pattern = (f.pattern or "").lower()

        if cat == "bbot-email" or pattern == "bbot-email_address":
            email = val.lower() or (f.title or "").replace("Email:", "").strip().lower()
            if email and "@" in email:
                eid = _node(
                    nodes,
                    f"email:{email}",
                    ntype="email",
                    label=email,
                    group="contact",
                    severity=f.severity,
                    source="scan",
                )
                _edge(edges, eid, fid, "instance")
                if hid:
                    _edge(edges, eid, hid, "seen_on")
                dom = email.rsplit("@", 1)[-1]
                ap = apex_domain(dom)
                if ap:
                    aid = _node(nodes, f"apex:{ap}", ntype="apex", label=ap, group="domain")
                    _edge(edges, eid, aid, "domain_of")

        elif cat == "bbot-shodan" or pattern.startswith("shodan"):
            raw = f.title or val or f.evidence or ""
            sh_host = _host_from_url(f.original_url or "")
            if not sh_host:
                m = re.search(r":\s*([a-z0-9._-]+\.[a-z0-9.-]+)", raw, re.I)
                sh_host = m.group(1).lower() if m else ""
            if sh_host:
                sid = _node(
                    nodes,
                    f"shodan:{sh_host}",
                    ntype="shodan",
                    label=f"Shodan: {sh_host}",
                    group="shodan",
                    severity=f.severity,
                    source="scan",
                    evidence=(f.evidence or "")[:300],
                )
                host_nid = _node(nodes, f"host:{sh_host}", ntype="host", label=sh_host, group="domain")
                ap = apex_domain(sh_host)
                if ap in apex_ids:
                    _edge(edges, apex_ids[ap], host_nid, "subdomain")
                _edge(edges, host_nid, sid, "shodan")
                _edge(edges, sid, fid, "finding")

        elif cat == "bbot-dns" or pattern == "bbot-dns_name":
            sub = _host_from_url(f.original_url or f.title.replace("Subdomain:", ""))
            if sub:
                sid = _node(
                    nodes,
                    f"host:{sub}",
                    ntype="host",
                    label=sub,
                    group="domain",
                    source="scan",
                )
                ap = apex_domain(sub)
                if ap in apex_ids:
                    _edge(edges, apex_ids[ap], sid, "subdomain")
                elif ap:
                    aid = _node(nodes, f"apex:{ap}", ntype="apex", label=ap, group="domain")
                    _edge(edges, aid, sid, "subdomain")
                _edge(edges, sid, fid, "finding")

        elif cat == "bbot-port" or pattern == "bbot-open_tcp_port" or pattern.startswith("open-"):
            raw = val or f.title.replace("Port:", "").strip() or f.evidence or ""
            m = re.search(r"([a-z0-9._-]+):(\d{1,5})", raw, re.I)
            if m:
                host, port = m.group(1).lower(), m.group(2)
                pid = _node(
                    nodes,
                    f"port:{host}:{port}",
                    ntype="port",
                    label=f"{host}:{port}",
                    group="service",
                    severity=f.severity,
                    source="scan",
                )
                host_nid = _node(
                    nodes,
                    f"host:{host}",
                    ntype="host",
                    label=host,
                    group="domain",
                    source="scan",
                )
                ap = apex_domain(host)
                if ap in apex_ids:
                    _edge(edges, apex_ids[ap], host_nid, "subdomain")
                _edge(edges, host_nid, pid, "port")
                _edge(edges, pid, fid, "finding")

        elif cat == "exposed-mail" or pattern.startswith("mail-"):
            raw = f.title or val or f.evidence or ""
            m = re.search(r"([a-z0-9._-]+):(\d{1,5})", raw, re.I)
            if m:
                host, port = m.group(1).lower(), m.group(2)
                mid = _node(
                    nodes,
                    f"mail:{host}:{port}",
                    ntype="mail",
                    label=f"{host}:{port}",
                    group="service",
                    severity=f.severity,
                    source=f.source or "scan",
                )
                host_nid = _node(nodes, f"host:{host}", ntype="host", label=host, group="domain")
                ap = apex_domain(host)
                if ap in apex_ids:
                    _edge(edges, apex_ids[ap], host_nid, "subdomain")
                _edge(edges, host_nid, mid, "mail")
                _edge(edges, mid, fid, "finding")
            elif hid:
                _edge(edges, hid, fid, "finding")

        elif cat == "auth-panel" or pattern.startswith("auth-"):
            auth_url = f.original_url if f.original_url.startswith(("http://", "https://")) else ""
            auth_host = _host_from_url(auth_url or f.title)
            if auth_host:
                aid = _node(
                    nodes,
                    f"auth:{auth_host}:{pattern}",
                    ntype="auth",
                    label=urlparse(auth_url).path[:40] if auth_url else (f.title or "auth")[:40],
                    group="auth",
                    severity=f.severity,
                    source=f.source or "scan",
                    full_url=auth_url,
                )
                ap = apex_domain(auth_host)
                if ap in apex_ids:
                    _edge(edges, apex_ids[ap], aid, "auth")
                if hid:
                    _edge(edges, hid, aid, "auth")
                _edge(edges, aid, fid, "finding")

        elif cat == "osint-email" or pattern.startswith("osint-email") or pattern == "osint-email-scope":
            email = val.lower() or (f.title or "").replace("Email:", "").strip().lower()
            if email and "@" in email:
                eid = _node(
                    nodes,
                    f"email:{email}",
                    ntype="email",
                    label=email,
                    group="contact",
                    severity=f.severity,
                )
                _edge(edges, eid, fid, "instance")
                if hid:
                    _edge(edges, eid, hid, "seen_on")
                dom = email.rsplit("@", 1)[-1]
                ap = apex_domain(dom)
                if ap:
                    aid = _node(nodes, f"apex:{ap}", ntype="apex", label=ap, group="domain")
                    _edge(edges, eid, aid, "domain_of")

        elif cat == "osint-phone" or pattern == "osint-phone":
            phone = val or (f.title or "").replace("Телефон:", "").strip()
            if phone:
                key = re.sub(r"\D", "", phone)[:20]
                pid = _node(
                    nodes,
                    f"phone:{key}",
                    ntype="phone",
                    label=phone[:40],
                    group="contact",
                    severity=f.severity,
                )
                _edge(edges, pid, fid, "instance")
                if hid:
                    _edge(edges, pid, hid, "seen_on")

        elif val and (
            cat in {"content-secret", "llm-secret"}
            or pattern in {
                "aws-akid",
                "github-pat",
                "jwt",
                "stripe",
                "openai",
                "dburi",
            }
        ):
            sid = _node(
                nodes,
                f"secret:{f.id}",
                ntype="secret",
                label=(f.title or pattern or "secret")[:80],
                group="secret",
                severity=f.severity,
                value=val[:400],
                pattern=pattern,
            )
            _edge(edges, sid, fid, "from_finding")
            if hid:
                _edge(edges, sid, hid, "exposed_on")

        for ip_match in _IP_RE.finditer(f.evidence or ""):
            ip = ip_match.group(0)
            if ip.startswith(("127.", "0.", "255.")):
                continue
            iid = _node(nodes, f"ip:{ip}", ntype="ip", label=ip, group="infra")
            _edge(edges, iid, fid, "mentioned")
            if hid:
                _edge(edges, iid, hid, "linked")

        _link_finding_to_scope(
            f,
            fid,
            hid,
            host,
            nodes=nodes,
            edges=edges,
            apex_ids=apex_ids,
            scope_apexes=scope_apexes,
        )

    node_list = list(nodes.values())
    stats = Counter(n["type"] for n in node_list)
    return {
        "nodes": node_list,
        "links": edges,
        "stats": dict(stats),
        "counts": {
            "nodes": len(node_list),
            "links": len(edges),
            "domains": stats.get("host", 0) + stats.get("apex", 0),
            "emails": stats.get("email", 0),
            "phones": stats.get("phone", 0),
            "secrets": stats.get("secret", 0),
            "ports": stats.get("port", 0) + stats.get("mail", 0),
            "shodan": stats.get("shodan", 0),
            "findings": stats.get("finding", 0),
            "urls": stats.get("url", 0),
            "ips": stats.get("ip", 0),
        },
    }
