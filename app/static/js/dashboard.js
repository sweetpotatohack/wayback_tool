/**
 * Dashboard — period filters, charts, live scan status, wire feed.
 */
(function () {
  const SEV = [
    { key: "critical", label: "Critical", cls: "c" },
    { key: "high", label: "High", cls: "h" },
    { key: "medium", label: "Medium", cls: "m" },
    { key: "low", label: "Low", cls: "l" },
    { key: "info", label: "Info", cls: "i" },
  ];

  const LIVE = new Set(["queued", "running"]);

  function esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function qs(sel) {
    return document.querySelector(sel);
  }

  function getPeriodParams() {
    const mode = document.querySelector('input[name="period_mode"]:checked')?.value || "all";
    const params = new URLSearchParams({ period: mode });
    if (mode === "day") {
      const d = qs("#period-day")?.value;
      if (d) params.set("date", d);
    }
    if (mode === "range") {
      const f = qs("#period-from")?.value;
      const t = qs("#period-to")?.value;
      if (f) params.set("date_from", f);
      if (t) params.set("date_to", t);
    }
    return params;
  }

  function setPeriodFields() {
    const mode = document.querySelector('input[name="period_mode"]:checked')?.value || "all";
    const range = qs("#period-fields-range");
    const day = qs("#period-fields-day");
    if (range) range.hidden = mode !== "range";
    if (day) day.hidden = mode !== "day";
  }

  function renderSeverityChart(sev) {
    const host = qs("#chart-severity");
    const legend = qs("#legend-severity");
    if (!host || !legend) return;
    const max = Math.max(1, ...SEV.map((s) => sev[s.key] || 0));
    host.innerHTML = SEV.map((s) => {
      const n = sev[s.key] || 0;
      const pct = Math.round((n / max) * 100);
      return `<div class="sev-row"><span class="sev-row-label">${s.label}</span><div class="sev-row-track"><i class="${s.cls}" style="width:${pct}%"></i></div><span class="sev-row-num">${n}</span></div>`;
    }).join("");
    legend.innerHTML = SEV.map((s) => `<li><i class="${s.cls}"></i>${s.label}</li>`).join("");
  }

  function renderTimeline(timeline, mode) {
    const svg = qs("#chart-timeline");
    const hint = qs("#timeline-hint");
    const totalEl = qs("#timeline-total");
    if (!svg) return;

    const w = 640;
    const h = 180;
    const pad = { t: 16, r: 12, b: 32, l: 36 };
    const innerW = w - pad.l - pad.r;
    const innerH = h - pad.t - pad.b;

    const hasData = timeline.some((d) => (d.total || 0) > 0);
    const sum = timeline.reduce((acc, d) => acc + (d.total || 0), 0);
    if (totalEl) totalEl.textContent = hasData ? `${sum} за период` : "";

    if (!timeline.length || !hasData) {
      svg.innerHTML = `<text x="${w / 2}" y="${h / 2}" text-anchor="middle" class="chart-empty">Нет данных за период</text>`;
      if (hint) hint.textContent = "Нет находок за выбранный период";
      return;
    }

    const max = Math.max(1, ...timeline.map((d) => d.total || 0));
    const n = timeline.length;
    const xAt = (i) => pad.l + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
    const yAt = (v) => pad.t + innerH - (v / max) * innerH;

    const points = timeline.map((d, i) => ({ x: xAt(i), y: yAt(d.total || 0), d, i }));
    const linePath = points.map((p, i) => `${i ? "L" : "M"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");
    const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${(pad.t + innerH).toFixed(1)} L ${points[0].x.toFixed(1)} ${(pad.t + innerH).toFixed(1)} Z`;

    const gridLines = [0, 0.25, 0.5, 0.75, 1]
      .map((t) => {
        const y = pad.t + innerH * (1 - t);
        const val = Math.round(max * t);
        return `<line x1="${pad.l}" y1="${y}" x2="${w - pad.r}" y2="${y}" class="tl-grid" />
          <text x="${pad.l - 6}" y="${y + 3}" text-anchor="end" class="tl-axis">${val}</text>`;
      })
      .join("");

    const dots = points
      .map((p) => {
        const crit = p.d.critical || 0;
        const high = p.d.high || 0;
        const hot = crit + high;
        const cls = hot > 0 ? "tl-dot tl-dot--hot" : "tl-dot";
        return `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${hot ? 4 : 3}" class="${cls}">
          <title>${esc(p.d.label)}: ${p.d.total}${crit ? ` · C:${crit}` : ""}${high ? ` H:${high}` : ""}</title>
        </circle>`;
      })
      .join("");

    const labelStep = Math.max(1, Math.ceil(n / 7));
    const labels = points
      .filter((_, i) => i % labelStep === 0 || i === n - 1)
      .map(
        (p) =>
          `<text x="${p.x.toFixed(1)}" y="${h - 8}" text-anchor="middle" class="tl-label">${esc(p.d.label)}</text>`
      )
      .join("");

    svg.innerHTML = `
      <defs>
        <linearGradient id="tl-area-grad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.45" />
          <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.02" />
        </linearGradient>
      </defs>
      ${gridLines}
      <path d="${areaPath}" class="tl-area" fill="url(#tl-area-grad)" />
      <path d="${linePath}" class="tl-line" fill="none" />
      ${dots}
      ${labels}`;

    if (hint) {
      hint.textContent =
        mode === "day"
          ? "Почасовое распределение · линия — всего находок"
          : mode === "all"
            ? "Последние 30 дней (сводка «всё время» по находкам за период)"
            : "Находки по дням выбранного отрезка";
    }
  }

  function renderProjects(byProject) {
    const host = qs("#chart-projects");
    if (!host) return;
    if (!byProject.length) {
      host.innerHTML = '<p class="chart-empty">Нет находок по проектам</p>';
      return;
    }
    const max = Math.max(1, ...byProject.map((p) => p.total || 0));
    host.innerHTML = byProject
      .slice(0, 8)
      .map((p) => {
        const pct = Math.round(((p.total || 0) / max) * 100);
        return `<div class="proj-row"><span class="proj-name">${esc(p.name)}</span><div class="proj-track"><i style="width:${pct}%"></i></div><span class="proj-num">${p.total}</span></div>`;
      })
      .join("");
  }

  function formatScanTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    const pad = (n) => String(n).padStart(2, "0");
    return `${pad(d.getDate())}.${pad(d.getMonth() + 1)}.${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function renderCard(card) {
    const live = card.active_scan && LIVE.has(card.active_scan.status);
    const counts = card.counts || {};
    const statusChip = live
      ? `<span class="chip chip-live file-status">${esc(card.active_scan.stage || "В работе")}</span>`
      : card.last_scan?.status === "failed"
        ? '<span class="chip chip-err file-status">ошибка</span>'
        : card.last_scan?.status === "done"
          ? '<span class="chip chip-ok file-status">готово</span>'
          : "";
    const progress = live
      ? `<div class="file-scan-track" aria-hidden="true"><div class="file-scan-bar" style="width:${card.active_scan.progress || 0}%"></div></div>`
      : "";
    const footTime = live
      ? `<span class="scan-live-text">${card.active_scan.progress || 0}% · ${esc(card.active_scan.stage || card.active_scan.status)}</span>`
      : card.last_scan_label
        ? `Последний проход · ${esc(card.last_scan_label)}`
        : card.last_scan?.finished_at
          ? `Последний проход · ${formatScanTime(card.last_scan.finished_at)}`
          : "Проход не выполнялся";

    return `
      <a class="bureau-file${live ? " bureau-file--live" : ""}" href="/projects/${esc(card.id)}" data-project-id="${esc(card.id)}">
        <div class="file-tab">
          <span class="file-id">GI-${esc((card.id || "").slice(0, 8).toUpperCase())}</span>
          <span class="file-tab-status">${statusChip}<span class="chip file-schedule">${card.schedule && card.schedule !== "off" ? esc(card.schedule) : "вручную"}</span></span>
        </div>
        ${progress}
        <div class="file-body">
          <h3>${esc(card.name)}</h3>
          <p class="file-desc">${esc(card.description || "Описание не заполнено — откройте дело для редактирования.")}</p>
          <div class="file-chart" title="Распределение по severity">
            <span class="file-chart-label">Шкала риска</span>
            <div class="sev-bar sev-bar--paper card-sev-bar">
              <i class="c" style="flex:${counts.critical || 0.01}"></i>
              <i class="h" style="flex:${counts.high || 0.01}"></i>
              <i class="m" style="flex:${counts.medium || 0.01}"></i>
              <i class="l" style="flex:${counts.low || 0.01}"></i>
            </div>
          </div>
          <footer class="file-foot">
            <span class="file-stats card-sev-stats">
              <em>C</em> <span class="v-c">${counts.critical || 0}</span>
              <em>H</em> <span class="v-h">${counts.high || 0}</span>
              <em>M</em> <span class="v-m">${counts.medium || 0}</span>
              <em>L</em> <span class="v-l">${counts.low || 0}</span>
            </span>
            <time class="file-time card-scan-time">${footTime}</time>
          </footer>
        </div>
      </a>`;
  }

  function renderCards(cards) {
    const host = qs("#project-cards");
    const countEl = qs("#cards-count");
    const statProjects = qs("#stat-projects");
    if (countEl) countEl.textContent = String(cards.length);
    if (statProjects) statProjects.textContent = String(cards.length);
    if (!host) return;
    if (!cards.length) {
      host.innerHTML =
        '<div class="bureau-empty"><p class="bureau-empty-title">Картотека пуста</p><p>Заведите первое дело.</p><a class="btn copper" href="/projects/new">Создать первое дело</a></div>';
      return;
    }
    host.innerHTML = cards.map(renderCard).join("");
  }

  function updateLedger(data) {
    const map = {
      "#stat-findings": data.total_findings,
      "#stat-critical": data.sev?.critical || 0,
      "#stat-high": data.sev?.high || 0,
      "#stat-running": data.scans_running || 0,
    };
    Object.entries(map).forEach(([sel, val]) => {
      const el = qs(sel);
      if (el) el.textContent = String(val);
    });
    const ledger = qs("#ledger-running");
    if (ledger) ledger.classList.toggle("is-active", (data.scans_running || 0) > 0);
  }

  function updateExportProjects(cards) {
    const sel = qs("#export-project");
    if (!sel) return;
    const cur = sel.value;
    const opts = (cards || [])
      .map((c) => `<option value="${esc(c.id)}">${esc(c.name)}</option>`)
      .join("");
    sel.innerHTML = `<option value="all">Все проекты</option>${opts}`;
    if ([...sel.options].some((o) => o.value === cur)) sel.value = cur;
  }

  let exportPollTimer = 0;
  let exportActive = false;

  const FMT_LABELS = { csv: "CSV", txt: "TXT", html: "HTML", pdf: "PDF" };

  function setExportProgress(pct, stage, state) {
    const box = qs("#export-progress");
    const bar = qs("#export-progress-bar");
    const track = qs("#export-progress-track");
    const label = qs("#export-progress-label");
    const pctEl = qs("#export-progress-pct");
    if (!box || !bar) return;
    box.hidden = false;
    box.classList.remove("is-error", "is-done");
    if (state === "error") box.classList.add("is-error");
    if (state === "done") box.classList.add("is-done");
    const val = Math.max(0, Math.min(100, Number(pct) || 0));
    bar.style.width = `${val}%`;
    if (track) {
      track.setAttribute("aria-valuenow", String(val));
      track.setAttribute("aria-valuetext", `${val}% — ${stage || ""}`);
    }
    if (label) label.textContent = stage || "Формирование отчёта…";
    if (pctEl) pctEl.textContent = `${val}%`;
  }

  function hideExportProgress(delayMs = 1800) {
    clearTimeout(exportPollTimer);
    window.setTimeout(() => {
      const box = qs("#export-progress");
      if (box && !exportActive) box.hidden = true;
    }, delayMs);
  }

  function setExportBusy(busy) {
    exportActive = busy;
    document.querySelectorAll(".export-btn").forEach((btn) => {
      btn.disabled = busy;
    });
    const sel = qs("#export-project");
    if (sel) sel.disabled = busy;
  }

  async function pollExportJob(jobId, fmt) {
    const res = await fetch(`/api/dashboard/export/jobs/${jobId}`, { credentials: "same-origin" });
    if (!res.ok) throw new Error("Не удалось получить статус выгрузки");
    const data = await res.json();
    setExportProgress(data.progress, data.stage, data.status);

    if (data.status === "done") {
      const fileRes = await fetch(`/api/dashboard/export/jobs/${jobId}/file`, { credentials: "same-origin" });
      if (!fileRes.ok) throw new Error("Файл отчёта недоступен");
      const blob = await fileRes.blob();
      const name = data.filename || `ghostindex-export.${fmt}`;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      URL.revokeObjectURL(a.href);
      setExportProgress(100, "Скачивание завершено", "done");
      setExportBusy(false);
      hideExportProgress(2400);
      return;
    }

    if (data.status === "error") {
      throw new Error(data.error || "Ошибка формирования отчёта");
    }

    exportPollTimer = window.setTimeout(() => {
      pollExportJob(jobId, fmt).catch((err) => {
        setExportProgress(0, err.message || "Ошибка", "error");
        setExportBusy(false);
        hideExportProgress(5000);
      });
    }, 450);
  }

  async function triggerExport(fmt) {
    if (exportActive) return;
    const params = getPeriodParams();
    params.set("format", fmt);
    params.set("project_id", qs("#export-project")?.value || "all");
    setExportBusy(true);
    setExportProgress(0, `Запуск ${FMT_LABELS[fmt] || fmt.toUpperCase()}…`, "running");
    try {
      const res = await fetch(`/api/dashboard/export/jobs?${params.toString()}`, {
        method: "POST",
        credentials: "same-origin",
      });
      if (!res.ok) {
        let msg = `Ошибка ${res.status}`;
        try {
          const data = await res.json();
          if (data.detail) msg = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
        } catch (_) {
          msg = (await res.text()).slice(0, 200) || msg;
        }
        throw new Error(msg);
      }
      const data = await res.json();
      setExportProgress(data.progress || 2, data.stage || "Старт", data.status || "running");
      await pollExportJob(data.job_id, fmt);
    } catch (err) {
      setExportProgress(0, err.message || "Не удалось выгрузить отчёт", "error");
      setExportBusy(false);
      hideExportProgress(5000);
    }
  }

  function initExport() {
    document.querySelectorAll(".export-btn").forEach((btn) => {
      btn.addEventListener("click", () => triggerExport(btn.dataset.export || "csv"));
    });
  }

  function applyStats(data) {
    const label = data.period?.label || "Всё время";
    const labelEl = qs("#period-label");
    const chartsMeta = qs("#charts-meta");
    if (labelEl) labelEl.textContent = label;
    if (chartsMeta) chartsMeta.textContent = label;
    updateLedger(data);
    renderSeverityChart(data.sev || {});
    renderTimeline(data.timeline || [], data.period?.mode || "all");
    renderProjects(data.by_project || []);
    renderCards(data.cards || []);
    updateExportProjects(data.cards || []);
    scheduleStatusPoll(data.scans_running || 0);
  }

  async function fetchStats() {
    const params = getPeriodParams();
    const res = await fetch(`/api/dashboard/stats?${params}`, { credentials: "same-origin" });
    if (!res.ok) throw new Error("stats fetch failed");
    return res.json();
  }

  async function refreshDashboard() {
    try {
      const data = await fetchStats();
      applyStats(data);
      await refreshWireFeed();
    } catch (_) {
      /* ignore */
    }
  }

  function renderWireItems(items) {
    const body = qs("#wire-feed-body");
    if (!body) return;
    if (!items.length) {
      body.innerHTML =
        '<div class="wire-empty"><p>Лента пуста — запустите архивный проход по одному из дел.</p></div>';
      return;
    }
    const rows = items
      .map((item) => {
        const sev = esc(item.severity || "info");
        const title = esc(item.title);
        const project = esc(item.project_name);
        const pid = esc(item.project_id);
        const url = item.original_url ? `<span class="wire-url">${esc(item.original_url)}</span>` : "";
        const tag = item.category ? `<span class="wire-tag">${esc(item.category)}</span>` : "";
        return `
          <li class="wire-item">
            <a class="wire-link" href="/projects/${pid}">
              <div class="wire-head">
                <span class="stamp-sev ${sev}">${sev}</span>
                ${project ? `<span class="wire-case">${project}</span>` : ""}
              </div>
              <strong class="wire-title">${title}</strong>
              ${url}
              ${tag}
            </a>
          </li>`;
      })
      .join("");
    body.innerHTML = `<ul class="wire-feed wire-feed--live">${rows}</ul>`;
  }

  async function refreshWireFeed() {
    const body = qs("#wire-feed-body");
    if (!body) return;
    try {
      const params = getPeriodParams();
      const res = await fetch(`/api/dashboard/wire-feed?${params}`, { credentials: "same-origin" });
      if (!res.ok) return;
      const data = await res.json();
      body.classList.add("is-refreshing");
      renderWireItems(data.items || []);
      requestAnimationFrame(() => body.classList.remove("is-refreshing"));
    } catch (_) {
      /* ignore */
    }
  }

  let wireTimer = 0;
  let statusTimer = 0;

  function randomDelayMs() {
    return 10000 + Math.floor(Math.random() * 20001);
  }

  function scheduleWireRefresh() {
    clearTimeout(wireTimer);
    wireTimer = window.setTimeout(async () => {
      await refreshWireFeed();
      scheduleWireRefresh();
    }, randomDelayMs());
  }

  function scheduleStatusPoll(running) {
    clearTimeout(statusTimer);
    const ms = running > 0 ? 4000 : 30000;
    statusTimer = window.setTimeout(async () => {
      try {
        const data = await fetchStats();
        updateLedger(data);
        renderCards(data.cards || []);
        scheduleStatusPoll(data.scans_running || 0);
      } catch (_) {
        scheduleStatusPoll(0);
      }
    }, ms);
  }

  function initPeriodForm() {
    const form = qs("#period-form");
    if (!form) return;
    form.querySelectorAll('input[name="period_mode"]').forEach((el) => {
      el.addEventListener("change", setPeriodFields);
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      await refreshDashboard();
    });
    const today = new Date();
    const iso = today.toISOString().slice(0, 10);
    const dayInput = qs("#period-day");
    const fromInput = qs("#period-from");
    const toInput = qs("#period-to");
    if (dayInput && !dayInput.value) dayInput.value = iso;
    if (toInput && !toInput.value) toInput.value = iso;
    if (fromInput && !fromInput.value) {
      const past = new Date(today);
      past.setDate(past.getDate() - 30);
      fromInput.value = past.toISOString().slice(0, 10);
    }
    setPeriodFields();
  }

  function initDashboard() {
    if (!qs("#bureau-dashboard")) return;
    initPeriodForm();
    initExport();
    fetchStats()
      .then(applyStats)
      .catch(() => {
        const sev = {};
        SEV.forEach((s) => {
          const el = qs(`#stat-${s.key}`);
          if (el) sev[s.key] = Number(el.textContent || 0);
        });
        renderSeverityChart(sev);
      });
    scheduleWireRefresh();

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        clearTimeout(wireTimer);
        clearTimeout(statusTimer);
        return;
      }
      refreshDashboard();
      scheduleWireRefresh();
    });

    window.addEventListener("pagehide", () => {
      clearTimeout(wireTimer);
      clearTimeout(statusTimer);
      clearTimeout(exportPollTimer);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initDashboard);
  } else {
    initDashboard();
  }
})();
