/**
 * NetWay — interactive ASM-style graph (D3 force layout)
 */
(function () {
  const TYPE_LABELS = {
    apex: "Apex",
    host: "Домен",
    url: "URL",
    email: "Email",
    phone: "Телефон",
    secret: "Секрет",
    port: "Порт",
    mail: "Почта",
    shodan: "Shodan",
    auth: "Auth",
    finding: "Находка",
    ip: "IP",
    target: "Цель",
  };

  function themeVar(name, fallback) {
    const el = document.documentElement;
    const v = getComputedStyle(el).getPropertyValue(name).trim();
    return v || fallback;
  }

  function buildPalette() {
    return {
      type: {
        apex: themeVar("--accent", "#d4894a"),
        host: themeVar("--med", "#7a9a6a"),
        url: themeVar("--low", "#6a8aaa"),
        email: themeVar("--low", "#6a8aaa"),
        phone: themeVar("--high", "#d4a04a"),
        secret: themeVar("--accent", "#d4894a"),
        port: themeVar("--high", "#d4a04a"),
        mail: themeVar("--high", "#d4a04a"),
        shodan: themeVar("--med", "#7a9a6a"),
        auth: themeVar("--crit", "#c45c4a"),
        finding: themeVar("--crit", "#c45c4a"),
        ip: themeVar("--high", "#d4a04a"),
        target: themeVar("--med", "#7a9a6a"),
      },
      sev: {
        critical: themeVar("--crit", "#c45c4a"),
        high: themeVar("--high", "#d4a04a"),
        medium: themeVar("--med", "#7a9a6a"),
        low: themeVar("--low", "#6a8aaa"),
        info: themeVar("--muted", "#9a8f7c"),
      },
      link: themeVar("--accent", "#d4894a"),
      linkHot: themeVar("--crit", "#c45c4a"),
      select: themeVar("--ink", "#f0e6d4"),
    };
  }

  function nodeRadius(d) {
    if (d.type === "apex") return 10;
    if (d.type === "host") return 6 + Math.min(6, Math.log2((d.url_count || 1) + 1));
    if (d.type === "finding" || d.type === "secret") return 5;
    if (d.type === "email" || d.type === "phone") return 7;
    return 4;
  }

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function shortLabel(d, max = 36) {
    const text = String(d.label || d.value || d.id || "").trim();
    if (text.length <= max) return text;
    return `${text.slice(0, max - 1)}…`;
  }

  function linkEndpoints(l) {
    return [l.source.id || l.source, l.target.id || l.target];
  }

  function edgeKey(l) {
    const [s, t] = linkEndpoints(l);
    return `${s}|${t}|${l.kind}`;
  }

  const PATH_KINDS = new Set([
    "domain_of",
    "seen_on",
    "instance",
    "from_finding",
    "finding",
    "exposed_on",
    "subdomain",
    "scope",
    "mentioned",
    "linked",
  ]);

  /** Highlight only the semantic chain (not the whole connected subgraph). */
  function traceHighlightPath(startId, links, nodeMap) {
    const start = nodeMap.get(startId);
    const startType = start?.type || "";
    const pathNodes = new Set([startId]);
    const pathEdges = [];
    const seen = new Set();

    function include(l) {
      const key = edgeKey(l);
      if (seen.has(key)) return;
      seen.add(key);
      const [s, t] = linkEndpoints(l);
      pathNodes.add(s);
      pathNodes.add(t);
      pathEdges.push(l);
    }

    function skipLink(l, nodeId) {
      const [s, t] = linkEndpoints(l);
      const other = s === nodeId ? t : s;
      const otherNode = nodeMap.get(other);
      if (!otherNode) return true;
      if (otherNode.type === "url" || otherNode.type === "ip") return true;
      const nodeType = nodeMap.get(nodeId)?.type;
      if (nodeType === "host" && l.kind === "serves") return true;
      if (nodeType === "apex" && l.kind === "subdomain") return true;
      return false;
    }

    links.forEach((l) => {
      const [s, t] = linkEndpoints(l);
      if (s !== startId && t !== startId) return;
      if (skipLink(l, startId)) return;
      include(l);
    });

    const bridgeTypes = new Set(["email", "phone", "finding", "secret"]);
    [...pathNodes]
      .filter((id) => bridgeTypes.has(nodeMap.get(id)?.type || ""))
      .forEach((nid) => {
        links.forEach((l) => {
          if (!PATH_KINDS.has(l.kind)) return;
          const [s, t] = linkEndpoints(l);
          if (s !== nid && t !== nid) return;
          if (skipLink(l, nid)) return;
          include(l);
        });
      });

    if (startType !== "url") {
      [...pathNodes].forEach((id) => {
        if (nodeMap.get(id)?.type === "url") pathNodes.delete(id);
      });
    }
    if (startType !== "ip") {
      [...pathNodes].forEach((id) => {
        if (nodeMap.get(id)?.type === "ip") pathNodes.delete(id);
      });
    }

    return { nodes: pathNodes, edges: pathEdges };
  }

  let fsBackdrop = null;
  let netwayRootAnchor = null;

  function getNetwayRoot() {
    return document.getElementById("netway-root");
  }

  function isDetailFullscreen() {
    return document.body.classList.contains("netway-detail-fs-open");
  }

  function ensureFsBackdrop() {
    if (fsBackdrop) return fsBackdrop;
    fsBackdrop = document.getElementById("netway-detail-backdrop");
    if (!fsBackdrop) {
      fsBackdrop = document.createElement("div");
      fsBackdrop.id = "netway-detail-backdrop";
      fsBackdrop.hidden = true;
      fsBackdrop.setAttribute("role", "dialog");
      fsBackdrop.setAttribute("aria-modal", "true");
      fsBackdrop.setAttribute("aria-label", "NetWay");
      document.body.appendChild(fsBackdrop);
    } else if (!isDetailFullscreen()) {
      fsBackdrop.hidden = true;
    }
    return fsBackdrop;
  }

  function syncFsButtons(on) {
    document.querySelectorAll("[data-netway-detail-fs]").forEach((btn) => {
      btn.classList.toggle("is-on", on);
      const inToolbar = btn.closest(".netway-zoom");
      if (inToolbar) {
        btn.textContent = on ? "✕" : "⛶";
      } else {
        btn.textContent = on ? "Свернуть" : "На весь экран";
      }
      btn.title = on ? "Свернуть" : "Граф и детали на весь экран";
    });
  }

  function rememberNetwayRootAnchor(root) {
    if (netwayRootAnchor || !root) return;
    if (root.parentElement?.id === "netway-detail-backdrop") return;
    netwayRootAnchor = { parent: root.parentElement, next: root.nextSibling };
  }

  function setDetailFullscreen(on) {
    const root = getNetwayRoot();
    if (!root) return;
    const want = typeof on === "boolean" ? on : !isDetailFullscreen();
    const backdrop = ensureFsBackdrop();

    if (want) {
      if (isDetailFullscreen()) return;
      rememberNetwayRootAnchor(root);
      backdrop.hidden = false;
      backdrop.appendChild(root);
      root.classList.add("is-fullscreen");
      document.body.classList.add("netway-detail-fs-open");
    } else {
      if (!isDetailFullscreen()) return;
      root.classList.remove("is-fullscreen");
      if (netwayRootAnchor?.parent) {
        netwayRootAnchor.parent.insertBefore(root, netwayRootAnchor.next);
      }
      backdrop.hidden = true;
      document.body.classList.remove("netway-detail-fs-open");
    }
    syncFsButtons(want);
    root.__netwayResize?.();
    window.setTimeout(() => root.__netwayResize?.(), 80);
  }

  function toggleDetailFullscreen() {
    setDetailFullscreen(!isDetailFullscreen());
  }

  if (!window.__netwayFsClickBound) {
    window.__netwayFsClickBound = true;
    document.addEventListener(
      "click",
      (e) => {
        const btn = e.target.closest("[data-netway-detail-fs]");
        if (!btn) return;
        e.preventDefault();
        e.stopPropagation();
        toggleDetailFullscreen();
      },
      true
    );
  }

  if (!window.__netwayFsEscBound) {
    window.__netwayFsEscBound = true;
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && isDetailFullscreen()) setDetailFullscreen(false);
    });
  }

  window.initNetWay = function initNetWay(projectId) {
    const root = document.getElementById("netway-root");
    if (!root || !window.d3) return;
    root.__netwayToggleFs = toggleDetailFullscreen;
    root.__netwayCloseFs = () => setDetailFullscreen(false);

    if (root.dataset.netwayProject === projectId && root.__netwayReload) {
      root.__netwayReload();
      return;
    }
    root.dataset.netwayProject = projectId;

    const canvasWrap = root.querySelector(".netway-canvas-wrap");
    const detailEl = root.querySelector(".netway-detail");
    const loadingEl = root.querySelector(".netway-loading");

    let graph = { nodes: [], links: [] };
    let simulation = null;
    let selectedId = null;
    let highlightNodes = null;
    let highlightEdgeKeys = null;
    let activeFilters = new Set(["all"]);
    let palette = buildPalette();
    let svg = null;
    let gZoom = null;
    let gLinks = null;
    let gNodes = null;
    let zoomBehavior = null;
    let viewTransform = d3.zoomIdentity;
    let starfield = null;
    let nodeDrag = null;

    function nodeMap() {
      return new Map(graph.nodes.map((n) => [n.id, n]));
    }

    function computeHighlight(startId) {
      if (!startId) return { nodes: null, edgeKeys: null };
      const traced = traceHighlightPath(startId, graph.links, nodeMap());
      return {
        nodes: traced.nodes,
        edgeKeys: new Set(traced.edges.map(edgeKey)),
      };
    }

    function api(path) {
      return fetch(path, { credentials: "same-origin" }).then(async (r) => {
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
        return r.json();
      });
    }

    function nodeColor(d) {
      if (d.severity && palette.sev[d.severity]) return palette.sev[d.severity];
      return palette.type[d.type] || palette.type.host;
    }

    function filteredNodes() {
      if (activeFilters.has("all")) return graph.nodes;
      return graph.nodes.filter((n) => {
        if (activeFilters.has("domain") && (n.type === "host" || n.type === "apex")) return true;
        if (activeFilters.has("contact") && (n.type === "email" || n.type === "phone")) return true;
        if (activeFilters.has("secret") && (n.type === "secret" || n.severity === "critical")) return true;
        if (activeFilters.has("port") && (n.type === "port" || n.type === "mail")) return true;
        if (activeFilters.has("shodan") && n.type === "shodan") return true;
        if (activeFilters.has("finding") && n.type === "finding") return true;
        if (activeFilters.has("url") && n.type === "url") return true;
        return false;
      });
    }

    function visibleGraph() {
      const nodes = filteredNodes();
      const ids = new Set(nodes.map((n) => n.id));
      const links = graph.links.filter((l) => {
        const [s, t] = linkEndpoints(l);
        return ids.has(s) && ids.has(t);
      });
      return { nodes, links };
    }

    function neighbors(id) {
      const out = [];
      graph.links.forEach((l) => {
        const [s, t] = linkEndpoints(l);
        if (s === id) out.push({ id: t, kind: l.kind });
        if (t === id) out.push({ id: s, kind: l.kind });
      });
      const seen = new Set();
      return out
        .filter((x) => {
          if (seen.has(x.id)) return false;
          seen.add(x.id);
          return true;
        })
        .slice(0, 24);
    }

    function displaySource(s) {
      if (!s) return "";
      if (s === "bbot") return "скан";
      return s;
    }

    function displayCategory(c) {
      if (!c) return "";
      return c.replace(/^bbot-/, "");
    }

    function renderDetail(node) {
      if (!detailEl) return;
      if (!node) {
        const items = filteredNodes()
          .filter((n) => n.type !== "target")
          .slice()
          .sort((a, b) => String(a.label || "").localeCompare(String(b.label || ""), "ru"));
        if (items.length) {
          const list = items
            .slice(0, 250)
            .map(
              (n) =>
                `<button type="button" class="netway-browse-btn" data-goto="${escapeHtml(n.id)}">
                  <span class="netway-browse-type">${escapeHtml(TYPE_LABELS[n.type] || n.type)}</span>
                  <span class="netway-browse-label">${escapeHtml(n.label)}</span>
                </button>`
            )
            .join("");
          detailEl.innerHTML = `
            <p class="netway-empty">Кликните узел на графе или выберите из списка (${items.length}):</p>
            <div class="netway-browse">${list}</div>`;
          detailEl.querySelectorAll("[data-goto]").forEach((btn) => {
            btn.addEventListener("click", () => {
              const id = btn.dataset.goto;
              const n = graph.nodes.find((x) => x.id === id);
              if (n) selectNode(n);
            });
          });
          return;
        }
        detailEl.innerHTML = `<p class="netway-empty">Кликните на узел графа — домен, email, телефон, секрет или находку. Связи показывают, где данные пересекаются между инстансами.</p>`;
        return;
      }
      const rows = [];
      const push = (k, v) => {
        if (v) rows.push(`<dt>${escapeHtml(k)}</dt><dd>${v}</dd>`);
      };
      push("Тип", TYPE_LABELS[node.type] || node.type);
      push("Метка", escapeHtml(node.label));
      if (node.severity) push("Severity", `<span class="stamp-sev ${node.severity}">${node.severity}</span>`);
      if (node.value) push("Значение", `<code>${escapeHtml(node.value)}</code>`);
      if (node.category) push("Категория", escapeHtml(displayCategory(node.category)));
      if (node.pattern) push("Pattern", escapeHtml(String(node.pattern).replace(/^bbot-/, "")));
      if (node.source) push("Источник", escapeHtml(displaySource(node.source)));
      if (node.url_count) push("URL в индексе", String(node.url_count));
      if (node.mimetype) push("MIME", escapeHtml(node.mimetype));
      if (node.full_url) {
        push("URL", `<a href="${escapeHtml(node.full_url)}" target="_blank" rel="noopener">${escapeHtml(node.full_url)}</a>`);
      }
      if (node.original_url) {
        push(
          "Страница",
          `<a href="${escapeHtml(node.original_url)}" target="_blank" rel="noopener">${escapeHtml(node.original_url)}</a>`
        );
      }
      if (node.archive_url) {
        push("Архив", `<a href="${escapeHtml(node.archive_url)}" target="_blank" rel="noopener">Wayback</a>`);
      }
      if (node.evidence) push("Контекст", `<code>${escapeHtml(node.evidence)}</code>`);

      const nb = neighbors(node.id)
        .map(({ id, kind }) => {
          const n = graph.nodes.find((x) => x.id === id);
          if (!n) return "";
          return `<button type="button" class="netway-neighbor-btn" data-goto="${escapeHtml(id)}">${escapeHtml(TYPE_LABELS[n.type] || n.type)} · ${escapeHtml(n.label)} <span class="muted">(${kind})</span></button>`;
        })
        .join("");

      detailEl.innerHTML = `
        <div class="netway-card">
          <h4>${escapeHtml(node.label)}</h4>
          <dl class="netway-kv">${rows.join("")}</dl>
          ${nb ? `<div class="netway-neighbors"><h5>Связанные узлы</h5>${nb}</div>` : ""}
        </div>`;

      detailEl.querySelectorAll("[data-goto]").forEach((btn) => {
        btn.addEventListener("click", () => {
          const id = btn.dataset.goto;
          const n = graph.nodes.find((x) => x.id === id);
          if (n) selectNode(n);
        });
      });
    }

    function updateHighlight() {
      if (!gLinks || !gNodes) return;
      const hotNodes = highlightNodes;
      const hotEdges = highlightEdgeKeys;

      gLinks
        .selectAll("line")
        .classed("is-hot", (l) => Boolean(hotEdges?.has(edgeKey(l))))
        .classed("is-dim", (l) => Boolean(hotEdges && !hotEdges.has(edgeKey(l))))
        .attr("stroke", (l) => (hotEdges?.has(edgeKey(l)) ? palette.linkHot : palette.link));

      gNodes
        .selectAll("g.node")
        .classed("is-selected", (d) => d.id === selectedId)
        .classed("is-connected", (d) => hotNodes?.has(d.id) && d.id !== selectedId)
        .classed("is-dimmed", (d) => hotNodes && !hotNodes.has(d.id));

      gNodes.selectAll("circle").attr("stroke-width", (d) => {
        if (d.id === selectedId) return 3;
        if (hotNodes?.has(d.id)) return 2;
        return 1;
      });
      gNodes.selectAll("circle").attr("stroke", (d) => {
        if (d.id === selectedId) return palette.select;
        if (hotNodes?.has(d.id)) return palette.linkHot;
        return "rgba(0,0,0,0.35)";
      });
    }

    function selectNode(node) {
      selectedId = node?.id ?? null;
      const hi = computeHighlight(selectedId);
      highlightNodes = hi.nodes;
      highlightEdgeKeys = hi.edgeKeys;
      renderDetail(node || null);
      updateHighlight();
    }

    function clearSelection() {
      selectNode(null);
    }

    function getSvgEl() {
      return canvasWrap.querySelector("svg.netway-graph");
    }

    function canvasSize() {
      return {
        w: canvasWrap.clientWidth || 800,
        h: canvasWrap.clientHeight || 520,
      };
    }

    function buildExportText() {
      const domains = new Set();
      const emails = new Set();
      const phones = new Set();
      for (const n of graph.nodes || []) {
        const val = String(n.value || n.label || "").trim();
        if (!val) continue;
        if (n.type === "host" || n.type === "apex") domains.add(val);
        else if (n.type === "email") emails.add(val);
        else if (n.type === "phone") phones.add(val);
      }
      const sort = (items) => [...items].sort((a, b) => a.localeCompare(b, "ru"));
      const stamp = new Date().toISOString().slice(0, 19).replace("T", " ");
      return [
        "NetWay export",
        `Project: ${projectId}`,
        `Generated: ${stamp}`,
        "",
        "=== Subdomains / Domains ===",
        ...(sort(domains).length ? sort(domains) : ["(нет данных)"]),
        "",
        "=== Email ===",
        ...(sort(emails).length ? sort(emails) : ["(нет данных)"]),
        "",
        "=== Phone ===",
        ...(sort(phones).length ? sort(phones) : ["(нет данных)"]),
        "",
      ].join("\n");
    }

    function downloadTextExport() {
      if (!graph.nodes?.length) return;
      const blob = new Blob([buildExportText()], { type: "text/plain;charset=utf-8" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `netway-${projectId.slice(0, 8)}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(a.href);
    }

    function initStarfield() {
      let canvas = canvasWrap.querySelector(".netway-stars");
      if (!canvas) {
        canvas = document.createElement("canvas");
        canvas.className = "netway-stars";
        canvas.setAttribute("aria-hidden", "true");
        canvasWrap.insertBefore(canvas, canvasWrap.firstChild);
      }

      const stars = Array.from({ length: 140 }, () => ({
        x: Math.random(),
        y: Math.random(),
        r: Math.random() * 1.3 + 0.25,
        vx: (Math.random() - 0.5) * 0.00012,
        vy: (Math.random() - 0.5) * 0.00012,
        tw: Math.random() * Math.PI * 2,
        twSpeed: 0.008 + Math.random() * 0.015,
        base: 0.15 + Math.random() * 0.45,
      }));

      let raf = 0;

      function resize() {
        const dpr = window.devicePixelRatio || 1;
        const w = canvasWrap.clientWidth || 800;
        const h = canvasWrap.clientHeight || 520;
        canvas.width = Math.floor(w * dpr);
        canvas.height = Math.floor(h * dpr);
        canvas.style.width = `${w}px`;
        canvas.style.height = `${h}px`;
      }

      function frame() {
        const ctx = canvas.getContext("2d");
        if (!ctx) return;
        const dpr = window.devicePixelRatio || 1;
        const w = canvas.width / dpr;
        const h = canvas.height / dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, w, h);

        const accent = palette.type.apex;
        stars.forEach((s) => {
          s.x += s.vx;
          s.y += s.vy;
          s.tw += s.twSpeed;
          if (s.x < 0) s.x = 1;
          if (s.x > 1) s.x = 0;
          if (s.y < 0) s.y = 1;
          if (s.y > 1) s.y = 0;
          const alpha = s.base + Math.sin(s.tw) * 0.18;
          ctx.fillStyle = accent;
          ctx.globalAlpha = alpha;
          ctx.beginPath();
          ctx.arc(s.x * w, s.y * h, s.r, 0, Math.PI * 2);
          ctx.fill();
        });
        ctx.globalAlpha = 1;
        raf = requestAnimationFrame(frame);
      }

      resize();
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(frame);

      return {
        resize,
        stop: () => cancelAnimationFrame(raf),
        refresh: () => {
          palette = buildPalette();
        },
      };
    }

    function applyZoom(action) {
      const svgEl = getSvgEl();
      if (!svgEl || !gZoom) return;
      const zb = svgEl.__netwayZoom || zoomBehavior;
      if (!zb) return;

      const sel = d3.select(svgEl);
      const w = Number(sel.attr("width")) || canvasSize().w;
      const h = Number(sel.attr("height")) || canvasSize().h;
      let next = viewTransform;

      if (action === "reset") {
        next = d3.zoomIdentity;
      } else {
        const factor = action === "in" ? 1.35 : 1 / 1.35;
        next = viewTransform.translate(w / 2, h / 2).scale(viewTransform.k * factor).translate(-w / 2, -h / 2);
      }

      const dur = action === "reset" ? 350 : 250;
      sel.transition().duration(dur).call(zb.transform, next);
    }

    function syncFilterChips() {
      root.querySelectorAll(".netway-chip[data-filter]").forEach((chip) => {
        const f = chip.dataset.filter;
        chip.classList.toggle("is-on", activeFilters.has("all") ? f === "all" : activeFilters.has(f));
      });
      root.querySelectorAll(".netway-type-tabs .netway-chip[data-type]").forEach((tab) => {
        const t = tab.dataset.type;
        if (activeFilters.has("all")) {
          tab.classList.toggle("is-on", t === "all");
        } else if (activeFilters.size === 1) {
          tab.classList.toggle("is-on", activeFilters.has(t));
        } else {
          tab.classList.toggle("is-on", false);
        }
      });
    }

    function setFilter(next) {
      activeFilters = next;
      syncFilterChips();
      if (selectedId) {
        const stillVisible = filteredNodes().some((n) => n.id === selectedId);
        if (!stillVisible) clearSelection();
        else {
          const hi = computeHighlight(selectedId);
          highlightNodes = hi.nodes;
          highlightEdgeKeys = hi.edgeKeys;
        }
      }
      draw();
      if (!selectedId) renderDetail(null);
    }

    function handleFilterChip(chip) {
      const f = chip.dataset.filter;
      if (!f) return;
      if (f === "all") {
        setFilter(new Set(["all"]));
        return;
      }
      const next = new Set(activeFilters);
      next.delete("all");
      if (next.has(f)) next.delete(f);
      else next.add(f);
      if (!next.size) next.add("all");
      setFilter(next);
    }

    function handleTypeTab(tab) {
      const t = tab.dataset.type;
      if (!t) return;
      setFilter(t === "all" ? new Set(["all"]) : new Set([t]));
    }

    function bindControls() {
      if (root.dataset.controlsBound) return;
      root.dataset.controlsBound = "1";

      const zoomIn = root.querySelector("[data-zoom-in]");
      const zoomOut = root.querySelector("[data-zoom-out]");
      const zoomReset = root.querySelector("[data-zoom-reset]");

      zoomIn?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        applyZoom("in");
      });
      zoomOut?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        applyZoom("out");
      });
      zoomReset?.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        applyZoom("reset");
      });

      root.addEventListener("click", (e) => {
        const chip = e.target.closest(".netway-chip[data-filter]");
        if (chip && root.contains(chip)) {
          e.preventDefault();
          e.stopPropagation();
          handleFilterChip(chip);
          return;
        }

        const tab = e.target.closest(".netway-type-tabs .netway-chip[data-type]");
        if (tab && root.contains(tab)) {
          e.preventDefault();
          e.stopPropagation();
          handleTypeTab(tab);
          return;
        }

        const exportBtn = e.target.closest("[data-netway-export]");
        if (exportBtn && root.contains(exportBtn)) {
          e.preventDefault();
          downloadTextExport();
        }
      });
    }

    function makeNodeDrag() {
      return d3
        .drag()
        .clickDistance(4)
        .on("start", (event, d) => {
          event.sourceEvent?.stopPropagation?.();
          if (!event.active) simulation?.alphaTarget(0.25).restart();
          d3.select(event.sourceEvent?.target?.closest?.("g.node") || event.sourceEvent?.target).classed("is-dragging", true);
          d.fx = d.x;
          d.fy = d.y;
        })
        .on("drag", (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", (event, d) => {
          d3.select(event.sourceEvent?.target?.closest?.("g.node") || event.sourceEvent?.target).classed("is-dragging", false);
          if (!event.active) simulation?.alphaTarget(0.02);
          d.fx = null;
          d.fy = null;
        });
    }

    function initCanvas() {
      palette = buildPalette();
      starfield?.refresh?.();

      const { w, h } = canvasSize();
      let svgSel = d3.select(canvasWrap).select("svg.netway-graph");

      if (svgSel.empty()) {
        svg = svgSel = d3
          .select(canvasWrap)
          .append("svg")
          .attr("class", "netway-graph")
          .attr("width", w)
          .attr("height", h);
        gZoom = svg.append("g").attr("class", "netway-zoom-layer");
        gLinks = gZoom.append("g").attr("class", "netway-links");
        gNodes = gZoom.append("g").attr("class", "netway-nodes");

        zoomBehavior = d3
          .zoom()
          .scaleExtent([0.15, 4])
          .filter((event) => {
            if (event.type === "wheel") return true;
            if (event.button && event.button !== 0) return false;
            const target = event.target;
            if (target?.closest?.("g.node")) return false;
            if (target?.closest?.(".netway-toolbar")) return false;
            return true;
          })
          .on("zoom", (event) => {
            viewTransform = event.transform;
            gZoom.attr("transform", event.transform);
          });

        svg.call(zoomBehavior);
        svg.node().__netwayZoom = zoomBehavior;

        svg.on("click", (event) => {
          if (event.target.closest?.("g.node")) return;
          clearSelection();
        });

        nodeDrag = makeNodeDrag();
      } else {
        svg = svgSel;
        gZoom = svg.select(".netway-zoom-layer");
        gLinks = gZoom.select(".netway-links");
        gNodes = gZoom.select(".netway-nodes");
        zoomBehavior = svg.node().__netwayZoom;
        svgSel.attr("width", w).attr("height", h);
      }
    }

    function draw() {
      initCanvas();
      if (!svg || !gLinks || !gNodes) return;

      const { w, h } = canvasSize();
      const { nodes, links } = visibleGraph();

      if (simulation) simulation.stop();

      simulation = d3
        .forceSimulation(nodes)
        .force(
          "link",
          d3
            .forceLink(links)
            .id((d) => d.id)
            .distance((l) => (l.kind === "subdomain" ? 62 : 96))
            .strength(0.42)
        )
        .force("charge", d3.forceManyBody().strength(-140))
        .force("center", d3.forceCenter(w / 2, h / 2))
        .force("collision", d3.forceCollide().radius((d) => nodeRadius(d) + 10))
        .force("x", d3.forceX(w / 2).strength(0.025))
        .force("y", d3.forceY(h / 2).strength(0.025))
        .velocityDecay(0.32)
        .alpha(0.9)
        .alphaDecay(0.018)
        .alphaTarget(0.02);

      const link = gLinks.selectAll("line").data(links, (d) => `${linkEndpoints(d).join("-")}`);
      link.exit().remove();
      link
        .enter()
        .append("line")
        .attr("stroke", palette.link)
        .attr("stroke-opacity", 0.35)
        .attr("stroke-width", 0.9)
        .merge(link);

      const node = gNodes.selectAll("g.node").data(nodes, (d) => d.id);
      node.exit().remove();
      const enter = node
        .enter()
        .append("g")
        .attr("class", "node")
        .style("cursor", "grab")
        .call(nodeDrag);
      enter
        .append("circle")
        .attr("class", "node-core")
        .attr("r", nodeRadius)
        .attr("fill", nodeColor)
        .attr("stroke", "rgba(0,0,0,0.35)")
        .attr("stroke-width", 1);
      enter
        .append("text")
        .attr("class", "node-label")
        .attr("text-anchor", "middle")
        .attr("dy", (d) => nodeRadius(d) + 12)
        .text((d) => shortLabel(d));
      enter.append("title").text((d) => `${TYPE_LABELS[d.type] || d.type}: ${d.label}`);
      enter.on("click", (event, d) => {
        event.stopPropagation();
        selectNode(d);
      });

      const merged = enter.merge(node);
      merged.call(nodeDrag);
      merged.select("circle.node-core").attr("r", nodeRadius).attr("fill", nodeColor);
      merged
        .select("text.node-label")
        .attr("dy", (d) => nodeRadius(d) + 12)
        .text((d) => shortLabel(d));

      simulation.on("tick", () => {
        gLinks
          .selectAll("line")
          .attr("x1", (d) => d.source.x)
          .attr("y1", (d) => d.source.y)
          .attr("x2", (d) => d.target.x)
          .attr("y2", (d) => d.target.y);
        merged.attr("transform", (d) => `translate(${d.x},${d.y})`);
      });

      updateHighlight();
    }

    function updateStats(counts) {
      root.querySelectorAll("[data-stat]").forEach((el) => {
        const k = el.dataset.stat;
        if (counts && counts[k] != null) el.textContent = counts[k];
      });
    }

    bindControls();
    starfield = initStarfield();

    async function load() {
      if (loadingEl) loadingEl.hidden = false;
      try {
        graph = await api(`/api/projects/${projectId}/netway`);
        graph.links = (graph.links || []).map((l) => ({ ...l }));
        updateStats(graph.counts || {});
        selectedId = null;
        highlightNodes = null;
        highlightEdgeKeys = null;
        viewTransform = d3.zoomIdentity;
        initCanvas();
        const svgEl = getSvgEl();
        if (svgEl?.__netwayZoom) {
          d3.select(svgEl).call(svgEl.__netwayZoom.transform, d3.zoomIdentity);
        }
        draw();
        renderDetail(null);
      } catch (err) {
        if (detailEl) detailEl.innerHTML = `<p class="netway-empty">Ошибка загрузки графа: ${escapeHtml(err.message)}</p>`;
      } finally {
        if (loadingEl) loadingEl.hidden = true;
      }
    }

    root.__netwayReload = load;

    function relayoutGraph() {
      starfield?.resize?.();
      if (!graph.nodes?.length) return;
      const { w, h } = canvasSize();
      d3.select(getSvgEl())?.attr("width", w).attr("height", h);
      simulation?.force("center", d3.forceCenter(w / 2, h / 2));
      simulation?.force("x", d3.forceX(w / 2).strength(0.025));
      simulation?.force("y", d3.forceY(h / 2).strength(0.025));
      simulation?.alphaTarget(0.05).restart();
    }
    root.__netwayResize = relayoutGraph;

    let resizeTimer;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(relayoutGraph, 200);
    });

    load();
  };
})();
