async function api(url, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== "string") {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(url, { credentials: "same-origin", ...opts, headers });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
  if (!res.ok) {
    const detail = data && data.detail;
    const msg = typeof detail === "string" ? detail : (detail && detail[0] && detail[0].msg) || res.statusText;
    throw new Error(msg);
  }
  return data;
}

function toast(msg) {
  let el = document.getElementById("toast");
  if (!el) {
    el = document.createElement("p");
    el.id = "toast";
    el.className = "toast";
    document.body.appendChild(el);
  }
  el.hidden = false;
  el.textContent = msg;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3200);
}

function bindProjectDeletes(redirect) {
  document.querySelectorAll("[data-delete-project]").forEach((btn) => {
    if (btn.dataset.bound) return;
    btn.dataset.bound = "1";
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();
      const id = btn.dataset.deleteProject;
      const name = btn.dataset.name || "этот проект";
      if (!confirm(`Удалить проект «${name}»?\nНаходки, проходы и расписание тоже будут стёрты.`)) return;
      btn.disabled = true;
      try {
        await api(`/api/projects/${id}`, { method: "DELETE" });
        location.href = redirect || "/projects";
      } catch (err) {
        btn.disabled = false;
        toast(err.message);
      }
    });
  });
}


function bindLimitFields(root) {
  const scope = root || document;
  scope.querySelectorAll(".limit-unlim").forEach((box) => {
    if (box.dataset.boundLimit) return;
    box.dataset.boundLimit = "1";
    const wrapId = (box.dataset.hide || box.dataset.target || "").replace(/^#/, "");
    const wrap = wrapId ? document.getElementById(wrapId) : null;
    const sync = () => {
      if (!wrap) return;
      const hide = box.checked;
      wrap.hidden = hide;
      wrap.setAttribute("aria-hidden", hide ? "true" : "false");
      wrap.querySelectorAll("input, select, textarea").forEach((el) => {
        el.disabled = hide;
      });
    };
    box.addEventListener("change", sync);
    box.addEventListener("input", sync);
    sync();
  });
}


function ready(fn) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fn);
  } else {
    fn();
  }
}


function bindSettingsNav() {
  const nav = document.getElementById("settings-nav");
  if (!nav || nav.dataset.boundNav) return;
  nav.dataset.boundNav = "1";
  const links = nav.querySelectorAll("a[href^='#']");
  const sections = [...links].map((a) => document.querySelector(a.getAttribute("href"))).filter(Boolean);
  if (!sections.length) return;
  const obs = new IntersectionObserver(
    (entries) => {
      entries.forEach((e) => {
        if (!e.isIntersecting) return;
        links.forEach((a) => a.classList.toggle("is-on", a.getAttribute("href") === `#${e.target.id}`));
      });
    },
    { rootMargin: "-30% 0px -55% 0px", threshold: 0 }
  );
  sections.forEach((s) => obs.observe(s));
}


function bindLiveAuthFields() {
  const sel = document.getElementById("live-auth-type");
  if (!sel || sel.dataset.boundAuth) return;
  sel.dataset.boundAuth = "1";
  const basic = document.getElementById("live-auth-basic");
  const cookie = document.getElementById("live-auth-cookie");
  const header = document.getElementById("live-auth-header");
  const sync = () => {
    const v = sel.value || "none";
    if (basic) basic.hidden = v !== "basic";
    if (cookie) cookie.hidden = v !== "cookie";
    if (header) header.hidden = v !== "header";
  };
  sel.addEventListener("change", sync);
  sync();
}


function initProjectSettingsForm() {
  const form = document.getElementById("project-form");
  if (!form || form.dataset.boundSettings) return;
  form.dataset.boundSettings = "1";
  bindProjectForm();
  bindProjectDeletes("/projects");
  bindLimitFields(form);
  bindSettingsNav();
  bindLiveAuthFields();
  bindScheduleEditor({
    hidden: "#schedule-json",
    summary: "#schedule-summary",
    open: "#btn-schedule-edit",
  });
}


function openScheduleModal(modal) {
  if (!modal) return;
  if (modal.parentElement !== document.body) {
    document.body.appendChild(modal);
  }
  modal.classList.add("is-open");
  modal.removeAttribute("hidden");
  document.body.classList.add("modal-open");
}


function closeScheduleModal(modal) {
  if (!modal) return;
  modal.classList.remove("is-open");
  modal.setAttribute("hidden", "");
  document.body.classList.remove("modal-open");
}


function scheduleRuleTypeLabel(type) {
  return { every: "Интервал", daily: "Ежедневно", weekly: "По дням недели" }[type] || type;
}


function scheduleRuleLabel(rule) {
  const days = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"];
  if (rule.type === "every") {
    const m = Number(rule.minutes || 0);
    if (m % 1440 === 0) return `Каждые ${m / 1440} д.`;
    if (m % 60 === 0) return `Каждые ${m / 60} ч.`;
    return `Каждые ${m} мин.`;
  }
  if (rule.type === "daily") {
    return `Каждый день в ${String(rule.hour).padStart(2, "0")}:${String(rule.minute).padStart(2, "0")}`;
  }
  if (rule.type === "weekly") {
    const ds = (rule.weekdays || []).map((d) => days[d]).join(", ");
    return `${ds} в ${String(rule.hour).padStart(2, "0")}:${String(rule.minute).padStart(2, "0")}`;
  }
  return rule.type || "Правило";
}


function scheduleSummaryClient(cfg) {
  if (!cfg || !cfg.enabled || !cfg.rules || !cfg.rules.length) return "Только вручную";
  return cfg.rules.map((rule) => scheduleRuleLabel(rule)).join(" · ");
}


let _scheduleEditor = null;


function bindScheduleEditor(opts) {
  const modal = document.getElementById("schedule-modal");
  const hidden = document.querySelector(opts.hidden);
  const summary = document.querySelector(opts.summary);
  const openBtn = document.querySelector(opts.open);
  if (!modal || !hidden || !openBtn) {
    return;
  }

  const enabledEl = modal.querySelector("#schedule-enabled");
  const rulesEl = modal.querySelector("#schedule-rules");
  let draft = { enabled: false, rules: [] };

  if (modal.parentElement !== document.body) {
    document.body.appendChild(modal);
  }

  function openEditor() {
    readHidden();
    if (enabledEl) enabledEl.checked = !!draft.enabled;
    renderRules();
    openScheduleModal(modal);
  }

  function readHidden() {
    let parsed;
    try {
      const raw = hidden.value || "";
      parsed = raw ? JSON.parse(raw) : { enabled: false, rules: [] };
    } catch {
      parsed = { enabled: false, rules: [] };
    }
    draft.enabled = !!parsed.enabled;
    draft.rules = Array.isArray(parsed.rules) ? parsed.rules : [];
  }

  function writeHidden() {
    hidden.value = JSON.stringify(draft);
    if (summary) summary.textContent = scheduleSummaryClient(draft);
    renderSchedulePreview();
  }

  function renderSchedulePreview() {
    const previewEl = document.getElementById("schedule-rules-preview");
    if (!previewEl) return;
    if (!draft.enabled || !draft.rules.length) {
      previewEl.innerHTML = `<p class="schedule-empty">Автозапуск не настроен — добавьте правило через кнопку выше.</p>`;
      return;
    }
    previewEl.innerHTML = draft.rules
      .map(
        (rule, idx) => `
      <article class="schedule-item" data-rule-id="${escapeAttr(rule.id || idx)}">
        <div class="schedule-item-body">
          <span class="schedule-item-type">${escapeHtml(scheduleRuleTypeLabel(rule.type))}</span>
          <strong class="schedule-item-label">${escapeHtml(scheduleRuleLabel(rule))}</strong>
        </div>
        <div class="schedule-item-actions">
          <button type="button" class="btn ghost sm" data-schedule-edit-rule="${idx}">Изменить</button>
          <button type="button" class="btn ghost sm danger" data-schedule-del-rule="${idx}">Удалить</button>
        </div>
      </article>`
      )
      .join("");

    previewEl.querySelectorAll("[data-schedule-del-rule]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.scheduleDelRule);
        if (Number.isNaN(idx)) return;
        draft.rules.splice(idx, 1);
        if (!draft.rules.length) draft.enabled = false;
        if (enabledEl) enabledEl.checked = !!draft.enabled;
        writeHidden();
        renderRules();
      });
    });
    previewEl.querySelectorAll("[data-schedule-edit-rule]").forEach((btn) => {
      btn.addEventListener("click", () => openEditor());
    });
  }

  function ruleRow(rule, idx) {
    const row = document.createElement("div");
    row.className = "schedule-rule panel";
    row.dataset.idx = String(idx);
    if (rule.type === "every") {
      row.innerHTML = `<strong>Интервал</strong>
        <label>Каждые <input type="number" min="5" max="10080" data-k="minutes" value="${rule.minutes || 60}" /> мин.</label>
        <button type="button" class="btn ghost sm" data-del-rule>Удалить</button>`;
    } else if (rule.type === "daily") {
      row.innerHTML = `<strong>Ежедневно</strong>
        <label>Время <input type="time" data-k="time" value="${String(rule.hour).padStart(2, "0")}:${String(rule.minute).padStart(2, "0")}" /></label>
        <button type="button" class="btn ghost sm" data-del-rule>Удалить</button>`;
    } else {
      const days = (rule.weekdays || [0, 1, 2, 3, 4]).map(String);
      row.innerHTML = `<strong>По дням недели</strong>
        <div class="weekday-picks">${["пн", "вт", "ср", "чт", "пт", "сб", "вс"].map((l, i) =>
          `<label class="check sm"><input type="checkbox" data-day="${i}" ${days.includes(String(i)) ? "checked" : ""}/> ${l}</label>`).join("")}</div>
        <label>Время <input type="time" data-k="time" value="${String(rule.hour).padStart(2, "0")}:${String(rule.minute).padStart(2, "0")}" /></label>
        <button type="button" class="btn ghost sm" data-del-rule>Удалить</button>`;
    }
    row.querySelector("[data-del-rule]")?.addEventListener("click", () => {
      draft.rules.splice(idx, 1);
      if (!draft.rules.length) {
        draft.enabled = false;
        if (enabledEl) enabledEl.checked = false;
      }
      writeHidden();
      renderRules();
    });
    return row;
  }

  function renderRules() {
    if (!rulesEl) return;
    rulesEl.innerHTML = "";
    draft.rules.forEach((rule, idx) => rulesEl.appendChild(ruleRow(rule, idx)));
  }

  function collectRules() {
    if (!rulesEl) return;
    const out = [];
    rulesEl.querySelectorAll(".schedule-rule").forEach((row, idx) => {
      const base = draft.rules[idx] || {};
      if (base.type === "every") {
        const minutes = Number(row.querySelector('[data-k="minutes"]')?.value || 60);
        out.push({ id: base.id || uid(), type: "every", minutes: Math.max(5, minutes) });
      } else if (base.type === "daily") {
        const [h, m] = (row.querySelector('[data-k="time"]')?.value || "09:00").split(":").map(Number);
        out.push({ id: base.id || uid(), type: "daily", hour: h, minute: m });
      } else if (base.type === "weekly") {
        const days = [...row.querySelectorAll("[data-day]:checked")].map((el) => Number(el.dataset.day));
        const [h, m] = (row.querySelector('[data-k="time"]')?.value || "09:00").split(":").map(Number);
        out.push({ id: base.id || uid(), type: "weekly", hour: h, minute: m, weekdays: days.length ? days : [0] });
      }
    });
    draft.rules = out;
  }

  function uid() {
    return Math.random().toString(36).slice(2, 12);
  }

  _scheduleEditor = {
    open: openEditor,
    modal,
    hidden,
    summary,
    opts,
    readHidden,
    writeHidden,
    draft,
    renderRules,
    renderSchedulePreview,
    collectRules,
  };

  openBtn._scheduleOpen = openEditor;
  if (!openBtn.dataset.boundScheduleOpen) {
    openBtn.dataset.boundScheduleOpen = "1";
    openBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      openBtn._scheduleOpen?.();
    });
  }

  if (!modal.dataset.boundSchedule) {
    modal.dataset.boundSchedule = "1";

    modal.querySelectorAll("[data-schedule-close]").forEach((el) => {
      el.addEventListener("click", () => closeScheduleModal(modal));
    });

    modal.querySelector("#schedule-add-every")?.addEventListener("click", () => {
      const ed = _scheduleEditor;
      if (!ed) return;
      ed.draft.rules.push({ id: uid(), type: "every", minutes: 360 });
      ed.renderRules();
    });
    modal.querySelector("#schedule-add-daily")?.addEventListener("click", () => {
      const ed = _scheduleEditor;
      if (!ed) return;
      ed.draft.rules.push({ id: uid(), type: "daily", hour: 9, minute: 0 });
      ed.renderRules();
    });
    modal.querySelector("#schedule-add-weekly")?.addEventListener("click", () => {
      const ed = _scheduleEditor;
      if (!ed) return;
      ed.draft.rules.push({ id: uid(), type: "weekly", hour: 9, minute: 0, weekdays: [0, 1, 2, 3, 4] });
      ed.renderRules();
    });

    modal.querySelector("#schedule-save")?.addEventListener("click", async () => {
      const ed = _scheduleEditor;
      if (!ed) return;
      collectRules();
      ed.draft.enabled = enabledEl ? enabledEl.checked && ed.draft.rules.length > 0 : ed.draft.rules.length > 0;
      ed.writeHidden();
      closeScheduleModal(modal);
      if (ed.opts.onSaveApi) {
        try {
          const r = await ed.opts.onSaveApi(ed.hidden.value);
          if (ed.summary && r.schedule_summary) ed.summary.textContent = r.schedule_summary;
          toast("Расписание сохранено");
        } catch (err) {
          toast(err.message);
        }
      }
    });
  }

  readHidden();
  writeHidden();
}


function bindProjectForm() {
  const form = document.getElementById("project-form");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    const payload = {
      name: fd.get("name"),
      description: fd.get("description") || "",
      targets: fd.get("targets"),
      include_subdomains: fd.get("include_subdomains") === "on",
      inspect_snapshots: fd.get("inspect_snapshots") === "on",
      scan_javascript: fd.get("scan_javascript") === "on",
      follow_robots: fd.get("follow_robots") === "on",
      include_non200: fd.get("include_non200") === "on",
      include_recon: fd.get("include_recon") === "on",
      use_llm: fd.get("use_llm") === "on",
      llm_extract: fd.get("use_llm") === "on",
      llm_review: fd.get("llm_review") === "on",
      max_urls: Number(fd.get("max_urls") || 8000),
      max_urls_unlimited: fd.get("max_urls_unlimited") === "on",
      max_snapshot_fetches: Number(fd.get("max_snapshot_fetches") || 80),
      max_snapshot_fetches_unlimited: fd.get("max_snapshot_fetches_unlimited") === "on",
      llm_max_calls: Number(fd.get("llm_max_calls") || 40),
      llm_unlimited: fd.get("llm_unlimited") === "on",
      date_from: (fd.get("date_from") || "").replace(/\D/g, ""),
      date_to: (fd.get("date_to") || "").replace(/\D/g, ""),
      extra_keywords: fd.get("extra_keywords") || "",
      extra_extensions: fd.get("extra_extensions") || "",
      url_allow_pattern: fd.get("url_allow_pattern") || "",
      url_deny_pattern: fd.get("url_deny_pattern") || "",
      include_commoncrawl: fd.get("include_commoncrawl") === "on",
      dork_tier: fd.get("dork_tier") || "stable500",
      enable_live_probe: fd.get("enable_live_probe") === "on",
      enable_live_crawl: fd.get("enable_live_crawl") === "on",
      enable_osint: fd.get("enable_osint") === "on",
      enable_bbot: fd.get("enable_bbot") === "on",
      bbot_allow_deadly: fd.get("bbot_allow_deadly") === "on",
      live_auth_type: fd.get("live_auth_type") || "none",
      live_auth_user: fd.get("live_auth_user") || "",
      live_auth_pass: fd.get("live_auth_pass") || "",
      live_auth_cookie: fd.get("live_auth_cookie") || "",
      live_auth_header: fd.get("live_auth_header") || "",
      live_crawl_max_pages: Number(fd.get("live_crawl_max_pages") || 80),
      live_crawl_max_depth: Number(fd.get("live_crawl_max_depth") || 3),
      live_crawl_pages_unlimited: fd.get("live_crawl_pages_unlimited") === "on",
      live_crawl_depth_unlimited: fd.get("live_crawl_depth_unlimited") === "on",
      live_crawl_rps: Number(fd.get("live_crawl_rps") || 30),
      live_crawl_rps_unlimited: fd.get("live_crawl_rps_unlimited") === "on",
      schedule_json: fd.get("schedule_json") || "",
      crawl_html_links: fd.get("crawl_html_links") === "on",
      multi_snapshot_disclosure: fd.get("multi_snapshot_disclosure") === "on",
      authorized: fd.get("authorized") === "on" || fd.get("authorized") === "1",
    };
    const msg = form.querySelector(".form-msg");
    try {
      const id = form.dataset.id;
      if (id) {
        await api(`/api/projects/${id}`, { method: "PUT", body: payload });
        location.href = `/projects/${id}`;
      } else {
        const created = await api("/api/projects", { method: "POST", body: payload });
        location.href = `/projects/${created.id}`;
      }
    } catch (err) {
      msg.hidden = false;
      msg.textContent = err.message;
      msg.className = "form-msg banner err";
    }
  });
}

function bootProjectDetail(id) {
  const bar = document.getElementById("bar");
  const stage = document.getElementById("stage");
  const log = document.getElementById("log");
  const meta = document.getElementById("scan-meta");
  const tbody = document.querySelector("#findings tbody");
  const filter = document.getElementById("filter");
  const sevFilter = document.getElementById("sev-filter");
  const btn = document.getElementById("btn-scan");
  let findings = [];
  let pollTimer = null;
  let activeScanId = null;
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const LIVE = new Set(["queued", "running"]);

  function setScanButton(live) {
    if (!btn) return;
    btn.dataset.live = live ? "1" : "";
    if (live) {
      btn.textContent = "Прервать";
      btn.classList.remove("copper");
      btn.classList.add("danger");
    } else {
      btn.textContent = "Запустить проход";
      btn.classList.remove("danger");
      btn.classList.add("copper");
    }
  }

  const hideRecon = document.getElementById("hide-recon");
  const presetButtons = document.querySelectorAll(".finding-preset");
  let activePreset = "";
  const mimeSummary = document.getElementById("mime-summary");
  const urlTotal = document.getElementById("url-total");
  const lightbox = document.getElementById("shot-lightbox");
  const shotImg = document.getElementById("shot-full");
  const shotStage = document.getElementById("shot-stage");
  const shotCaption = document.getElementById("shot-caption");
  let shotScale = 1;
  let shotX = 0;
  let shotY = 0;
  let dragging = false;
  let dragStart = { x: 0, y: 0, ox: 0, oy: 0 };

  function applyShotTransform() {
    if (!shotImg) return;
    shotImg.style.transform = `translate(${shotX}px, ${shotY}px) scale(${shotScale})`;
  }

  function closeShot() {
    if (!lightbox) return;
    lightbox.hidden = true;
    document.body.style.overflow = "";
  }

  function openShot(f) {
    if (!lightbox || !shotImg) return;
    const src = f.shot_url || f.thumb_url;
    if (!src) return;
    shotScale = 1;
    shotX = 0;
    shotY = 0;
    shotImg.src = src;
    if (shotCaption) shotCaption.textContent = f.original_url || "";
    applyShotTransform();
    lightbox.hidden = false;
    document.body.style.overflow = "hidden";
  }

  lightbox?.querySelectorAll("[data-shot]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const act = btn.dataset.shot;
      if (act === "close") closeShot();
      if (act === "in") shotScale = Math.min(5, shotScale + 0.25);
      if (act === "out") shotScale = Math.max(0.4, shotScale - 0.25);
      if (act === "reset") {
        shotScale = 1;
        shotX = 0;
        shotY = 0;
      }
      applyShotTransform();
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && lightbox && !lightbox.hidden) closeShot();
  });
  shotStage?.addEventListener("wheel", (e) => {
    if (lightbox?.hidden) return;
    e.preventDefault();
    shotScale = e.deltaY < 0 ? Math.min(5, shotScale + 0.15) : Math.max(0.4, shotScale - 0.15);
    applyShotTransform();
  }, { passive: false });
  shotStage?.addEventListener("pointerdown", (e) => {
    if (lightbox?.hidden) return;
    dragging = true;
    dragStart = { x: e.clientX, y: e.clientY, ox: shotX, oy: shotY };
    shotStage.setPointerCapture(e.pointerId);
  });
  shotStage?.addEventListener("pointermove", (e) => {
    if (!dragging) return;
    shotX = dragStart.ox + (e.clientX - dragStart.x);
    shotY = dragStart.oy + (e.clientY - dragStart.y);
    applyShotTransform();
  });
  shotStage?.addEventListener("pointerup", () => { dragging = false; });

  function matchesPreset(f, preset) {
    if (!preset) return true;
    const cat = (f.category || "").toLowerCase();
    const title = (f.title || "").toLowerCase();
    const pat = (f.pattern || "").toLowerCase();
    if (preset === "ports") {
      return cat.includes("port") || cat.includes("shodan") || cat.includes("exposed-")
        || title.startsWith("port:") || pat.includes("open") || pat.startsWith("mail-");
    }
    if (preset === "subdomains") {
      return cat === "bbot-dns" || title.startsWith("subdomain:") || pat.includes("dns");
    }
    if (preset === "emails") {
      return cat.includes("email") || title.startsWith("email:");
    }
    return true;
  }

  function renderResourceCell(f) {
    const kind = f.resource_kind || "text";
    const href = f.resource_href || "";
    const label = f.original_url || f.title || "—";
    if (kind === "mailto" && href) {
      return `<a href="${escapeAttr(href)}">${escapeHtml(label)}</a>`;
    }
    if (kind === "http" && href) {
      return `<a href="${escapeAttr(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
    }
    return `<span class="resource-text">${escapeHtml(label)}</span>`;
  }

  function renderArchiveCell(f) {
    const liveSources = new Set(["live", "live-crawl", "bbot"]);
    if (liveSources.has(f.source) && (f.resource_kind === "http" || f.resource_kind === "mailto")) {
      return f.resource_href
        ? `<a href="${escapeAttr(f.resource_href)}" target="_blank" rel="noopener noreferrer">live</a>`
        : "live";
    }
    if (f.archive_url) {
      return `<a href="${escapeAttr(f.archive_url)}" target="_blank" rel="noopener noreferrer">Wayback</a>`;
    }
    if (f.resource_href && f.resource_href.startsWith("http")) {
      return `<a href="${escapeAttr(f.resource_href)}" target="_blank" rel="noopener noreferrer">live</a>`;
    }
    return "—";
  }

  function renderFindings() {
    const q = (filter.value || "").toLowerCase();
    const sev = sevFilter ? sevFilter.value : "";
    const skipRecon = hideRecon?.checked;
    tbody.innerHTML = "";
    findings
      .slice()
      .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
      .filter((f) => {
        if (sev && f.severity !== sev) return false;
        if (skipRecon && (f.pattern === "robots" || f.pattern === "sitemap" || f.category === "recon")) return false;
        if (!matchesPreset(f, activePreset)) return false;
        return !q || `${f.title} ${f.original_url} ${f.meta || ""} ${f.source}`.toLowerCase().includes(q);
      }).forEach((f) => {
      const tr = document.createElement("tr");
      const thumb = f.thumb_url
        ? `<button type="button" class="shot-open" data-shot-open="${escapeAttr(f.id)}"><img class="shot-mini" src="${escapeAttr(f.thumb_url)}" alt="" /></button>`
        : `<span class="shot-mini shot-empty">нет</span>`;
      const loc = f.evidence_file
        ? `<div class="evidence-loc"><strong>Файл:</strong> ${escapeHtml(f.evidence_file)}${f.evidence_line ? ` · <strong>стр.</strong> ${escapeHtml(f.evidence_line)}:${escapeHtml(f.evidence_col || "1")}` : ""}</div>`
        : "";
      const snippet = f.evidence_snippet || f.evidence || "";
      tr.innerHTML = `
        <td>${thumb}</td>
        <td><span class="stamp-sev ${f.severity}">${f.severity}</span></td>
        <td>
          <strong>${escapeHtml(f.title)}</strong>
          ${f.meta ? `<div class="finding-meta muted">${escapeHtml(f.meta)}</div>` : ""}
          ${loc}
          ${snippet ? `<div class="evidence"><code>${escapeHtml(snippet)}</code></div>` : ""}
          ${f.masked_secret ? `<div class="evidence"><strong>Значение:</strong> <code>${escapeHtml(f.masked_secret)}</code></div>` : ""}
        </td>
        <td class="url">${renderResourceCell(f)}</td>
        <td>${renderArchiveCell(f)}</td>`;
      tbody.appendChild(tr);
      tr.querySelector("[data-shot-open]")?.addEventListener("click", () => openShot(f));
    });
  }

  function paint(data) {
    const c = data.counts || {};
    document.querySelectorAll("#counts [data-k]").forEach((el) => {
      el.textContent = c[el.dataset.k] || 0;
    });
    const schedHidden = document.getElementById("schedule-json");
    const schedSummary = document.getElementById("schedule-summary");
    if (schedSummary && data.schedule_summary) schedSummary.textContent = data.schedule_summary;
    if (schedHidden && data.schedule_json) schedHidden.value = JSON.stringify(data.schedule_json);
    findings = data.findings || [];
    renderFindings();
    if (mimeSummary && data.mime_summary?.length) {
      mimeSummary.textContent = data.mime_summary
        .slice(0, 6)
        .map((m) => `${m.mimetype}: ${m.count}`)
        .join(" · ");
    }
    if (urlTotal && data.url_inventory_count != null) {
      urlTotal.textContent = `${data.url_inventory_count} URL`;
      const urlsTab = document.querySelector('#project-tabs .tab[data-tab="urls"]');
      if (urlsTab && data.url_inventory_count > 0) {
        urlsTab.textContent = `Архив URLs (${data.url_inventory_count})`;
      }
    }
    const last = data.last_scan;
    if (last) {
      bar.style.width = `${last.progress || 0}%`;
      stage.textContent = last.stage || last.status;
      log.textContent = last.log || "";
      meta.textContent = `URL: ${last.urls_seen} · снимки: ${last.snapshots_fetched} · находки: ${last.findings_count} · ${last.status}`;
      const live = LIVE.has(last.status);
      setScanButton(live);
      activeScanId = live ? last.id : null;
      if (live) pollScan(last.id);
    } else {
      setScanButton(false);
      activeScanId = null;
    }
  }

  async function refresh() {
    const data = await api(`/api/projects/${id}`);
    paint(data);
  }

  function pollScan(scanId) {
    clearInterval(pollTimer);
    const tick = async () => {
      try {
        const s = await api(`/api/scans/${scanId}`);
        bar.style.width = `${s.progress || 0}%`;
        stage.textContent = s.stage || s.status;
        log.textContent = s.log || "";
        meta.textContent = `URL: ${s.urls_seen} · снимки: ${s.snapshots_fetched} · находки: ${s.findings_count} · ${s.status}`;
        const live = LIVE.has(s.status);
        setScanButton(live);
        activeScanId = live ? scanId : null;
        if (s.status === "done" || s.status === "failed" || s.status === "cancelled") {
          clearInterval(pollTimer);
          refresh().then(() => {
            const urlsPanel = document.querySelector('.tab-panel[data-panel="urls"]');
            if (urlsPanel && !urlsPanel.hidden) loadUrls(true).catch(() => {});
            netwayLoaded = false;
            const netPanel = document.querySelector('.tab-panel[data-panel="netway"]');
            if (netPanel && !netPanel.hidden && window.initNetWay) {
              netwayLoaded = true;
              initNetWay(id);
            }
          });
        }
      } catch {
        clearInterval(pollTimer);
      }
    };
    tick();
    pollTimer = setInterval(tick, 1600);
  }

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      if (btn.dataset.live === "1") {
        const s = await api(`/api/projects/${id}/abort`, { method: "POST" });
        toast("Проход прерывается");
        pollScan(s.id);
      } else {
        const s = await api(`/api/projects/${id}/scan`, { method: "POST" });
        setScanButton(true);
        activeScanId = s.id;
        pollScan(s.id);
        toast(s.already ? "Проход уже идёт" : "Проход поставлен в очередь");
      }
    } catch (err) {
      toast(err.message);
    } finally {
      btn.disabled = false;
    }
  });

  filter.addEventListener("input", renderFindings);
  sevFilter?.addEventListener("change", renderFindings);
  hideRecon?.addEventListener("change", renderFindings);
  presetButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      activePreset = btn.dataset.preset || "";
      presetButtons.forEach((b) => b.classList.toggle("is-on", b === btn));
      renderFindings();
    });
  });

  const tabs = document.querySelectorAll("#project-tabs .tab");
  const panels = document.querySelectorAll(".tab-panel");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.toggle("is-on", t === tab));
      panels.forEach((p) => {
        const on = p.dataset.panel === tab.dataset.tab;
        p.hidden = !on;
        p.classList.toggle("is-on", on);
      });
      if (tab.dataset.tab !== "netway") {
        document.getElementById("netway-root")?.__netwayCloseFs?.();
      }
      if (tab.dataset.tab === "urls" && !urlLoaded) loadUrls(true);
      if (tab.dataset.tab === "netway" && !netwayLoaded && window.initNetWay) {
        netwayLoaded = true;
        initNetWay(id);
      }
    });
  });

  const urlTbody = document.querySelector("#url-table tbody");
  const urlFilter = document.getElementById("url-filter");
  const mimeFilter = document.getElementById("mime-filter");
  const urlInteresting = document.getElementById("url-interesting");
  const urlArchived = document.getElementById("url-archived");
  const urlMore = document.getElementById("url-more");
  let urlOffset = 0;
  let urlLoaded = false;
  let urlItems = [];
  let netwayLoaded = false;

  async function downloadCsv(path, filename) {
    const res = await fetch(path, { credentials: "same-origin" });
    if (!res.ok) throw new Error("Не удалось скачать CSV");
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  document.getElementById("btn-export-findings")?.addEventListener("click", () => {
    downloadCsv(`/api/projects/${id}/export.csv`, "findings.csv").catch((e) => toast(e.message));
  });
  document.getElementById("btn-export-urls")?.addEventListener("click", () => {
    downloadCsv(`/api/projects/${id}/urls/export.csv`, "urls.csv").catch((e) => toast(e.message));
  });

  function renderUrls(append) {
    if (!urlTbody) return;
    if (!append) urlTbody.innerHTML = "";
    urlItems.forEach((row) => {
      const tr = document.createElement("tr");
      if (row.interesting) tr.classList.add("url-hot");
      const ts = row.capture_ts ? row.capture_ts.slice(0, 8) : "—";
      tr.innerHTML = `
        <td class="url">${row.open_url ? `<a href="${escapeAttr(row.open_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(row.url)}</a>` : escapeHtml(row.url)}</td>
        <td>${escapeHtml((row.mimetype || "—").split(";")[0])}</td>
        <td>${ts}</td>
        <td>${escapeHtml(row.source || "")}${row.candidate ? " · кандидат" : ""}</td>
        <td>${
          row.archive_url
            ? `<a href="${escapeAttr(row.archive_url)}" target="_blank" rel="noopener">Wayback</a>`
            : row.open_url
              ? `<a href="${escapeAttr(row.open_url)}" target="_blank" rel="noopener">live</a>`
              : "—"
        }</td>`;
      urlTbody.appendChild(tr);
    });
    urlItems = [];
  }

  async function loadUrls(reset) {
    if (reset) urlOffset = 0;
    const params = new URLSearchParams({
      offset: String(urlOffset),
      limit: "100",
      q: urlFilter?.value || "",
      mime: mimeFilter?.value || "",
    });
    if (urlInteresting?.checked) params.set("interesting", "true");
    if (urlArchived?.checked) params.set("archived_only", "true");
    const data = await api(`/api/projects/${id}/urls?${params}`);
    if (urlTotal) urlTotal.textContent = `${data.total} URL`;
    urlItems = data.items || [];
    renderUrls(!reset);
    urlOffset += data.items?.length || 0;
    urlLoaded = true;
    if (urlMore) urlMore.disabled = urlOffset >= data.total;
  }

  let urlTimer;
  const scheduleUrlLoad = () => {
    clearTimeout(urlTimer);
    urlTimer = setTimeout(() => loadUrls(true).catch((e) => toast(e.message)), 350);
  };
  urlFilter?.addEventListener("input", scheduleUrlLoad);
  mimeFilter?.addEventListener("input", scheduleUrlLoad);
  urlInteresting?.addEventListener("change", scheduleUrlLoad);
  urlArchived?.addEventListener("change", scheduleUrlLoad);
  urlMore?.addEventListener("click", () => loadUrls(false).catch((e) => toast(e.message)));

  refresh().catch((err) => toast(err.message));
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}
function escapeAttr(s) {
  return escapeHtml(s).replaceAll('"', "&quot;");
}

function bindCabinet() {
  const toastEl = (m) => toast(m);

  const avatarForm = document.getElementById("avatar-form");
  avatarForm?.querySelector('input[type="file"]')?.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    try {
      await api("/api/profile/avatar", { method: "POST", body: fd });
      location.reload();
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("email-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/profile/email", { method: "POST", body: Object.fromEntries(fd) });
      toastEl("Почта обновлена");
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("password-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/profile/password", { method: "POST", body: Object.fromEntries(fd) });
      e.target.reset();
      toastEl("Пароль изменён");
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("theme-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/profile/theme", {
        method: "POST",
        body: {
          theme_preset: fd.get("theme_preset"),
          accent: fd.get("accent"),
          radius: String(fd.get("radius")),
          density: fd.get("density"),
          font_scale: Number(fd.get("font_scale")),
          grain: fd.get("grain") === "on",
        },
      });
      location.reload();
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("notify-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/profile/notify", {
        method: "POST",
        body: {
          notify_email: fd.get("notify_email") === "on",
          notify_telegram: fd.get("notify_telegram") === "on",
          telegram_bot_token: fd.get("telegram_bot_token") || "",
          telegram_chat_id: fd.get("telegram_chat_id") || "",
          notify_min_severity: fd.get("notify_min_severity"),
          notify_attach_screenshots: fd.get("notify_attach_screenshots") === "on",
        },
      });
      toastEl("Оповещения сохранены");
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("smtp-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/profile/smtp", {
        method: "POST",
        body: {
          smtp_enabled: fd.get("smtp_enabled") === "on",
          smtp_host: fd.get("smtp_host") || "",
          smtp_port: Number(fd.get("smtp_port") || 587),
          smtp_user: fd.get("smtp_user") || "",
          smtp_password: fd.get("smtp_password") || "",
          smtp_from: fd.get("smtp_from") || "",
          smtp_tls: fd.get("smtp_tls") === "on",
        },
      });
      toastEl("SMTP сохранён");
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("btn-smtp-test")?.addEventListener("click", async () => {
    try {
      const r = await api("/api/profile/smtp/test", { method: "POST" });
      toastEl("SMTP: " + (r.detail || "ok"));
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("btn-tg-test")?.addEventListener("click", async () => {
    try {
      await api("/api/profile/notify/test-telegram", { method: "POST" });
      toastEl("Тест ушёл в Telegram");
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("llm-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/profile/llm", {
        method: "POST",
        body: {
          llm_enabled: fd.get("llm_enabled") === "on",
          llm_base_url: fd.get("llm_base_url") || "",
          llm_api_path: fd.get("llm_api_path") || "/v1/chat/completions",
          llm_model: fd.get("llm_model") || "",
          llm_api_key: fd.get("llm_api_key") || "",
          llm_temperature: Number(fd.get("llm_temperature") || 0.2),
          llm_max_tokens: Number(fd.get("llm_max_tokens") || 1200),
          llm_timeout: Number(fd.get("llm_timeout") || 180),
        },
      });
      toastEl("LLM сохранён");
    } catch (err) { toastEl(err.message); }
  });

  document.getElementById("btn-llm-test")?.addEventListener("click", async () => {
    try {
      const r = await api("/api/profile/llm/test", { method: "POST" });
      toastEl("LLM: " + (r.detail || "ok"));
    } catch (err) { toastEl(err.message); }
  });
}

function bindAdmin() {
  document.querySelectorAll("[data-act]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/admin/users/${btn.dataset.id}/${btn.dataset.act}`, { method: "POST" });
        location.reload();
      } catch (err) { toast(err.message); }
    });
  });
}


ready(() => {
  initProjectSettingsForm();
  const scanBtn = document.getElementById("btn-scan");
  const projectId = scanBtn?.dataset.projectId;
  if (projectId) {
    bootProjectDetail(projectId);
    bindProjectDeletes("/projects");
    bindScheduleEditor({
      hidden: "#schedule-json",
      summary: "#schedule-summary",
      open: "#btn-schedule-edit",
      onSaveApi: (json) => api(`/api/projects/${projectId}/schedule`, { method: "POST", body: { schedule_json: json } }),
    });
  }
});
