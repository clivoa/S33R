/* ============================================================
   S33R Trends — analytics engine (ported for WARDEN redesign)
   Theme-aware via CSS custom properties (s33r-pages.css maps the
   legacy chart vars onto WARDEN tokens). Chart clicks open the
   redesigned feed with a ?q= search.
   ============================================================ */
const trendsUrl = ((window.S33R && window.S33R.data) || "data") + "/trends.json";
const newsUrl = (window.S33R && window.S33R.base) || "S33R Feed.html";

let trendsData = null;
let curatedOnly = false;
const WINDOW_DAYS = { "24h": 1, "7d": 7, "30d": 30, "90d": 90 };
let currentWindow = "7d";

let volumeChart = null, categoryChart = null, keywordsChart = null, vendorChart = null,
    trendChart = null, cveChart = null, threatActorChart = null, keywordVelocityChart = null;

function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

function chartTheme() {
  return {
    text: cssVar("--text"),
    muted: cssVar("--chart-axis") || cssVar("--muted"),
    grid: cssVar("--chart-grid"),
    surface: cssVar("--surface"),
    border: cssVar("--line"),
    fillSoft: cssVar("--chart-fill-soft"),
    palette: [cssVar("--chart-series-1"), cssVar("--chart-series-2"), cssVar("--chart-series-3"), cssVar("--chart-series-4"), cssVar("--primary"), cssVar("--secondary")].filter(Boolean),
  };
}

function withThemeScale(scale, theme) {
  const cfg = scale ? { ...scale } : {};
  cfg.grid = { color: theme.grid, ...cfg.grid };
  cfg.border = { color: theme.grid, ...cfg.border };
  cfg.ticks = { color: theme.muted, ...cfg.ticks };
  return cfg;
}

function themeChartConfig(type, data, options) {
  const theme = chartTheme();
  const datasets = (data.datasets || []).map((ds, idx) => {
    const color = theme.palette[idx % theme.palette.length] || theme.palette[0] || "#c9790a";
    const next = { ...ds };
    if (type === "line") {
      next.borderColor = next.borderColor || color;
      next.backgroundColor = next.backgroundColor || theme.fillSoft;
      next.pointBackgroundColor = next.pointBackgroundColor || color;
      next.pointBorderColor = next.pointBorderColor || color;
      next.tension = next.tension ?? 0.25;
      next.borderWidth = next.borderWidth ?? 2;
      next.pointRadius = next.pointRadius ?? 2;
    } else {
      next.backgroundColor = next.backgroundColor || color;
      next.borderColor = next.borderColor || color;
      next.borderWidth = next.borderWidth ?? 1;
      next.maxBarThickness = next.maxBarThickness ?? 16;
    }
    return next;
  });
  const basePlugins = {
    legend: { labels: { color: theme.muted } },
    tooltip: { backgroundColor: theme.surface, titleColor: theme.text, bodyColor: theme.text, borderColor: theme.border, borderWidth: 1 },
  };
  const mergedOptions = {
    ...options, color: theme.muted,
    scales: { x: {}, y: {}, ...(options.scales || {}) },
    plugins: {
      ...basePlugins, ...(options.plugins || {}),
      legend: { ...basePlugins.legend, ...((options.plugins || {}).legend || {}), labels: { ...(basePlugins.legend.labels || {}), ...((((options.plugins || {}).legend || {}).labels) || {}) } },
      tooltip: { ...basePlugins.tooltip, ...((options.plugins || {}).tooltip || {}) },
    },
  };
  mergedOptions.scales.x = withThemeScale(mergedOptions.scales.x, theme);
  mergedOptions.scales.y = withThemeScale(mergedOptions.scales.y, theme);
  return { data: { ...data, datasets }, options: mergedOptions };
}

function createOrUpdateChart(chartRef, ctx, type, data, options = {}) {
  if (chartRef && chartRef.destroy) chartRef.destroy();
  const themed = themeChartConfig(type, data, options);
  return new Chart(ctx, { type, data: themed.data, options: themed.options });
}

function getWindowSafe(win) {
  if (!trendsData) return "7d";
  if (trendsData.windows && trendsData.windows.includes(win)) return win;
  return (trendsData.windows && trendsData.windows[0]) || "7d";
}

function updateVolumeChart(win) {
  const ctx = document.getElementById("volumeChart").getContext("2d");
  const series = trendsData.daily_volume || [];
  const generatedAt = trendsData.generated_at ? new Date(trendsData.generated_at) : new Date();
  const days = WINDOW_DAYS[win] || 90;
  const cutoff = new Date(generatedAt); cutoff.setDate(cutoff.getDate() - (days - 1));
  const filtered = series.filter((d) => new Date(d.date + "T00:00:00Z") >= cutoff);
  const dataToUse = filtered.length > 0 ? filtered : series;
  const labels = dataToUse.map((d) => d.date);
  const counts = dataToUse.map((d) => d.count);
  const rollingAvg = counts.map((_, i) => { const s = counts.slice(Math.max(0, i - 6), i + 1); return Math.round((s.reduce((a, b) => a + b, 0) / s.length) * 10) / 10; });
  volumeChart = createOrUpdateChart(volumeChart, ctx, "line",
    { labels, datasets: [{ label: "News per day", data: counts, fill: false }, { label: "7-day avg", data: rollingAvg, fill: false, borderDash: [5, 4], pointRadius: 0, borderWidth: 1.5 }] },
    { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { maxTicksLimit: 10 } }, y: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { display: true, position: "top" }, tooltip: { callbacks: { afterLabel: (ctx) => { if (ctx.datasetIndex === 0) { const avg = rollingAvg[ctx.dataIndex] || 0, val = counts[ctx.dataIndex] || 0; if (avg > 0 && val > avg * 1.5) return "⚠ Spike vs 7-day avg"; } return undefined; } } } } });
}

function updateCategoryChart(win) {
  const ctx = document.getElementById("categoryChart").getContext("2d");
  const dataObj = (trendsData.categories || {})[win] || {};
  const entries = Object.entries(dataObj).filter(([name]) => name.toLowerCase() !== "curated");
  categoryChart = createOrUpdateChart(categoryChart, ctx, "bar",
    { labels: entries.map(([n]) => n), datasets: [{ label: "Mentions", data: entries.map(([, v]) => v) }] },
    { indexAxis: "y", responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } } });
}

function updateKeywordsChart(win) {
  const ctx = document.getElementById("keywordsChart").getContext("2d");
  const top = ((trendsData.top_keywords || {})[win] || []).slice(0, 15);
  keywordsChart = createOrUpdateChart(keywordsChart, ctx, "bar",
    { labels: top.map((p) => p[0]), datasets: [{ label: "Count", data: top.map((p) => p[1]) }] },
    { indexAxis: "y", responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } },
      onClick: (_, els, chart) => { if (!els.length) return; window.open(`${newsUrl}?q=${encodeURIComponent(chart.data.labels[els[0].index])}`, "_self"); } });
  document.getElementById("keywordsChart").classList.add("chart-clickable");
}

function updateVendorChart(win) {
  const ctx = document.getElementById("vendorChart").getContext("2d");
  const top = ((trendsData.vendors || {})[win] || []).slice(0, 10);
  vendorChart = createOrUpdateChart(vendorChart, ctx, "bar",
    { labels: top.map((p) => p[0]), datasets: [{ label: "Mentions", data: top.map((p) => p[1]) }] },
    { indexAxis: "y", responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } },
      onClick: (_, els, chart) => { if (!els.length) return; window.open(`${newsUrl}?q=${encodeURIComponent(chart.data.labels[els[0].index])}`, "_self"); } });
  document.getElementById("vendorChart").classList.add("chart-clickable");
}

function updateTrendChart(win) {
  const ctx = document.getElementById("trendChart").getContext("2d");
  const tt = trendsData.trending_terms || {};
  const labels = [], values = [];
  Object.keys(tt).forEach((key) => { const e = tt[key]; labels.push(e.label || key); values.push((e.counts || {})[win] || 0); });
  trendChart = createOrUpdateChart(trendChart, ctx, "bar",
    { labels, datasets: [{ label: `Mentions (${win})`, data: values }] },
    { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } } });
}

function updateCveChart(win) {
  const ctx = document.getElementById("cveChart").getContext("2d");
  const top = ((trendsData.top_cves || {})[win] || []).slice(0, 20);
  cveChart = createOrUpdateChart(cveChart, ctx, "bar",
    { labels: top.map((p) => p[0]), datasets: [{ label: "Mentions", data: top.map((p) => p[1]) }] },
    { indexAxis: "y", responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } },
      onClick: (_, els, chart) => { if (!els.length) return; window.open(`${newsUrl}?q=${encodeURIComponent(chart.data.labels[els[0].index])}`, "_self"); } });
  document.getElementById("cveChart").classList.add("chart-clickable");
}

function updateThreatActorTimeline(win) {
  const ctx = document.getElementById("threatActorChart").getContext("2d");
  const series = trendsData.threat_actor_daily || [];
  const generatedAt = trendsData.generated_at ? new Date(trendsData.generated_at) : new Date();
  const days = WINDOW_DAYS[win] || 90;
  const cutoff = new Date(generatedAt); cutoff.setDate(cutoff.getDate() - (days - 1));
  const filtered = series.filter((d) => new Date(d.date + "T00:00:00Z") >= cutoff);
  const dataToUse = filtered.length > 0 ? filtered : series;
  const counts = dataToUse.map((d) => d.count);
  const actorDetails = dataToUse.map((d) => d.top_actors || []);
  threatActorChart = createOrUpdateChart(threatActorChart, ctx, "line",
    { labels: dataToUse.map((d) => d.date), datasets: [{ label: "Threat actor mentions per day", data: counts, fill: false }] },
    { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { maxTicksLimit: 10 } }, y: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => { const actors = actorDetails[c.dataIndex] || []; const lines = [`Mentions: ${c.formattedValue}`]; if (actors.length) { lines.push("Top actors:"); actors.slice(0, 3).forEach(([n, ct]) => lines.push(`- ${n} (${ct})`)); } return lines; } } } } });
}

function setActiveWindowButton(win) {
  document.querySelectorAll("#windowSelector button").forEach((b) => b.classList.toggle("active", b.dataset.win === win));
}

function renderDeltaList(id, rows) {
  const el = document.getElementById(id); if (!el) return; el.innerHTML = "";
  const top = Array.isArray(rows) ? rows.slice(0, 8) : [];
  if (!top.length) { el.innerHTML = '<li class="delta-item">No data</li>'; return; }
  top.forEach((row) => {
    const li = document.createElement("li"); li.className = "delta-item";
    const name = document.createElement("span"); name.textContent = row.name || "N/A";
    const delta = Number(row.delta || 0);
    const score = document.createElement("span");
    score.className = delta > 0 ? "delta-up" : delta < 0 ? "delta-down" : "delta-flat";
    score.textContent = `${delta > 0 ? "+" : ""}${delta} (${row.current}/${row.previous}) ${row.status ? "[" + row.status + "]" : ""}`;
    li.appendChild(name); li.appendChild(score); el.appendChild(li);
  });
}

function updateDeltaPanels(win) {
  const d = trendsData?.delta_analytics || {};
  renderDeltaList("delta-vendors", d?.vendors?.[win] || []);
  renderDeltaList("delta-cves", d?.cves?.[win] || []);
  renderDeltaList("delta-actors", d?.threat_actors?.[win] || []);
}

function compactSignalTags(item) {
  const tags = [];
  (item?.cves || []).slice(0, 2).forEach((v) => tags.push(v));
  (item?.actors || []).slice(0, 2).forEach((v) => tags.push(v));
  (item?.vendors || []).slice(0, 2).forEach((v) => tags.push(v));
  (item?.malware || []).slice(0, 2).forEach((v) => tags.push(v));
  return Array.from(new Set(tags)).slice(0, 6);
}

function renderPriorityNowPanel(win) {
  const payload = trendsData?.priority_now?.[win] || {};
  let rows = Array.isArray(payload.items) ? payload.items : [];
  if (curatedOnly) rows = rows.filter((r) => r.curated);
  rows = rows.slice(0, 8);
  const summary = payload.summary || {};
  const summaryEl = document.getElementById("priority-now-summary"), listEl = document.getElementById("priority-now-list");
  if (!summaryEl || !listEl) return;
  summaryEl.textContent = `Items: ${summary.total_items || 0} | Critical: ${summary.critical || 0} | High: ${summary.high || 0}`;
  listEl.innerHTML = "";
  if (!rows.length) { listEl.innerHTML = '<li class="ops-item">No priority data for this window.</li>'; return; }
  rows.forEach((item) => {
    const li = document.createElement("li"); li.className = "ops-item";
    const published = item.published ? new Date(item.published).toLocaleString() : "N/A";
    li.innerHTML = `<div class="ops-head"><div><p class="ops-title"><a href="${item.link || "#"}" target="_blank" rel="noopener">${item.title || "(no title)"}</a></p><p class="ops-meta">${item.source || "Unknown"} • ${published}</p></div><span class="ops-score">${item.score ?? 0} (${item.tier || "n/a"})</span></div>`;
    const tags = compactSignalTags(item);
    if (tags.length) li.innerHTML += `<div class="ops-tags">${tags.map((t) => `<span class="ops-tag">${t}</span>`).join("")}</div>`;
    if (Array.isArray(item.drivers) && item.drivers.length) li.innerHTML += `<ul class="ops-actions">${item.drivers.slice(0, 3).map((d) => `<li>${d}</li>`).join("")}</ul>`;
    listEl.appendChild(li);
  });
}

function renderCampaignClustersPanel(win) {
  const listEl = document.getElementById("campaign-clusters-list"); if (!listEl) return;
  const rows = (trendsData?.campaign_clusters?.[win] || []).slice(0, 8); listEl.innerHTML = "";
  if (!rows.length) { listEl.innerHTML = '<li class="ops-item">No campaign clusters in this window.</li>'; return; }
  rows.forEach((row) => {
    const li = document.createElement("li"); li.className = "ops-item";
    const actor = row.top_actors?.[0]?.[0] || "Unknown actor", mal = row.top_malware?.[0]?.[0] || "Unknown malware";
    li.innerHTML = `<div class="ops-head"><div><p class="ops-title">${actor} × ${mal}</p><p class="ops-meta">Items: ${row.items_count || 0} | Prev: ${row.previous_items_count || 0} | Status: ${row.trend_status || "n/a"}</p></div><span class="ops-score">${row.campaign_score ?? 0} (${row.tier || "n/a"})</span></div>`;
    const signals = [];
    (row.top_cves || []).slice(0, 2).forEach(([n]) => signals.push(n));
    (row.top_vendors || []).slice(0, 2).forEach(([n]) => signals.push(n));
    (row.top_categories || []).slice(0, 2).forEach(([n]) => signals.push(n));
    if (signals.length) li.innerHTML += `<div class="ops-tags">${signals.map((s) => `<span class="ops-tag">${s}</span>`).join("")}</div>`;
    const actions = Array.isArray(row.recommended_actions) ? row.recommended_actions : [];
    if (actions.length) li.innerHTML += `<ul class="ops-actions">${actions.slice(0, 3).map((a) => `<li>${a}</li>`).join("")}</ul>`;
    listEl.appendChild(li);
  });
}

function updateKeywordVelocityChart(win) {
  const ctx = document.getElementById("keywordVelocityChart").getContext("2d");
  const top = ((trendsData.keyword_velocity || {})[win] || []).slice(0, 15);
  keywordVelocityChart = createOrUpdateChart(keywordVelocityChart, ctx, "bar",
    { labels: top.map((d) => (d.previous === 0 ? `${d.keyword} ★` : d.keyword)), datasets: [{ label: "Growth %", data: top.map((d) => Math.min(d.growth_pct, 500)) }] },
    { indexAxis: "y", responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, ticks: { callback: (v) => `${v}%` } } },
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => { const d = top[c.dataIndex]; if (!d) return ""; return d.previous === 0 ? `New term — ${d.current} mentions` : `+${d.growth_pct}% (${d.previous} → ${d.current})`; } } } },
      onClick: (_, els) => { if (!els.length) return; const raw = top[els[0].index]?.keyword; if (raw) window.open(`${newsUrl}?q=${encodeURIComponent(raw)}`, "_self"); } });
  document.getElementById("keywordVelocityChart").classList.add("chart-clickable");
}

function renderCooccurrencePanel(id, rows, leftKey, rightKey) {
  const el = document.getElementById(id); if (!el) return; el.innerHTML = "";
  const top = (rows || []).slice(0, 10);
  if (!top.length) { el.textContent = "No co-occurrence data for this window."; return; }
  top.forEach((row) => {
    const div = document.createElement("div"); div.className = "cooc-row";
    const tag = (text) => { const s = document.createElement("span"); s.className = "cooc-tag"; s.textContent = text; s.title = `Search feed for "${text}"`; s.addEventListener("click", () => window.open(`${newsUrl}?q=${encodeURIComponent(text)}`, "_self")); return s; };
    const pair = document.createElement("div"); pair.className = "cooc-pair";
    pair.appendChild(tag(row[leftKey] || "?"));
    const arrow = document.createElement("span"); arrow.className = "cooc-arrow"; arrow.textContent = "×"; pair.appendChild(arrow);
    pair.appendChild(tag(row[rightKey] || "?"));
    const count = document.createElement("span"); count.className = "cooc-count"; count.textContent = `${row.count}x`;
    div.appendChild(pair); div.appendChild(count); el.appendChild(div);
  });
}

function updateCooccurrencePanels(win) {
  const cooc = trendsData.cooccurrence || {};
  renderCooccurrencePanel("cooc-cve-vendor", (cooc.cve_vendor || {})[win] || [], "cve", "vendor");
  renderCooccurrencePanel("cooc-actor-malware", (cooc.actor_malware || {})[win] || [], "actor", "malware");
}

let fqSortCol = "quality_score", fqSortAsc = false;
function renderFeedQualityTable() {
  const rows = (trendsData?.source_quality || []).slice(); if (!rows.length) return;
  rows.sort((a, b) => { const av = fqSortCol === "rank" ? 0 : (a[fqSortCol] ?? 0), bv = fqSortCol === "rank" ? 0 : (b[fqSortCol] ?? 0); if (typeof av === "string") return fqSortAsc ? av.localeCompare(bv) : bv.localeCompare(av); return fqSortAsc ? av - bv : bv - av; });
  const tbody = document.getElementById("fq-tbody"); if (!tbody) return; tbody.innerHTML = "";
  rows.forEach((row, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="fq-rank">${i + 1}</td><td>${row.source}</td><td>${row.total_items}</td>` +
      `<td class="${row.curated_rate >= 0.1 ? "fq-curated-hi" : ""}">${(row.curated_rate * 100).toFixed(1)}%</td>` +
      `<td>${row.avg_priority.toFixed(1)}</td><td>${row.cve_density.toFixed(1)}</td><td>${row.topic_entropy.toFixed(2)}</td>` +
      `<td><div class="fq-score-wrap"><div class="fq-score-bar"><div class="fq-score-fill" style="width:${Math.min(row.quality_score, 100)}%"></div></div><span class="fq-score-val">${row.quality_score.toFixed(1)}</span></div></td>`;
    tbody.appendChild(tr);
  });
  document.querySelectorAll("#fq-table th").forEach((th) => th.classList.toggle("fq-sort-active", th.dataset.col === fqSortCol));
}

function updateAllCharts(win) {
  const w = getWindowSafe(win); currentWindow = w; setActiveWindowButton(w);
  updateVolumeChart(w); updateCategoryChart(w); updateKeywordsChart(w); updateVendorChart(w);
  updateTrendChart(w); updateCveChart(w); updateThreatActorTimeline(w); updateKeywordVelocityChart(w);
  updateCooccurrencePanels(w); updateDeltaPanels(w); renderPriorityNowPanel(w); renderCampaignClustersPanel(w);
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("windowSelector").addEventListener("click", (e) => { const b = e.target.closest("button[data-win]"); if (!b || !trendsData) return; updateAllCharts(b.dataset.win); });
  document.getElementById("curated-only-toggle")?.addEventListener("change", (e) => { curatedOnly = e.target.checked; if (trendsData) renderPriorityNowPanel(currentWindow); });
  document.getElementById("fq-table")?.addEventListener("click", (e) => { const th = e.target.closest("th[data-col]"); if (!th) return; const col = th.dataset.col; if (fqSortCol === col) fqSortAsc = !fqSortAsc; else { fqSortCol = col; fqSortAsc = col === "source"; } if (trendsData) renderFeedQualityTable(); });
  fetch(trendsUrl, { cache: "no-store" }).then((r) => r.json()).then((data) => { trendsData = data; updateAllCharts(currentWindow); renderFeedQualityTable(); }).catch((err) => { console.error("Failed to load trends.json", err); window.S33R_UI?.toast("Failed to load trends.json"); });
});

window.addEventListener("s33r:themechange", () => { if (trendsData) updateAllCharts(currentWindow); });
