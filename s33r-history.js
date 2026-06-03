/* ============================================================
   S33R History — historical trends engine (WARDEN redesign)
   Theme-aware via CSS custom properties. Detail links open the
   redesigned feed with a ?q= search.
   ============================================================ */
const histUrl = ((window.S33R && window.S33R.data) || "data") + "/historical_trends.json";
const newsUrl = (window.S33R && window.S33R.base) || "S33R Feed.html";

let histData = null, volumeChart = null, cveMonthChart = null, topicChart = null, cveLifecycleChart = null, cveAllTimeChart = null, selectedMonth = null;
const TOPIC_KEYS = ["ransomware", "phishing", "zero-day", "supply chain", "data breach"];
const TOPIC_LABELS = { "ransomware": "Ransomware", "phishing": "Phishing", "zero-day": "Zero-day", "supply chain": "Supply chain", "data breach": "Data breach" };

function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
function palette() { return [cssVar("--chart-series-1"), cssVar("--chart-series-2"), cssVar("--chart-series-3"), cssVar("--chart-series-4"), cssVar("--primary"), cssVar("--secondary")].filter(Boolean); }
function themeBase() { return { text: cssVar("--text"), muted: cssVar("--chart-axis") || cssVar("--muted"), grid: cssVar("--chart-grid"), border: cssVar("--line"), surface: cssVar("--surface"), fillSoft: cssVar("--chart-fill-soft") }; }

function makeChart(ref, ctx, type, data, options) {
  if (ref && ref.destroy) ref.destroy();
  const th = themeBase(), pal = palette();
  const datasets = (data.datasets || []).map((ds, i) => {
    const color = pal[i % pal.length] || "#c9790a"; const next = { ...ds };
    if (type === "line") { next.borderColor = next.borderColor || color; next.backgroundColor = next.backgroundColor || th.fillSoft; next.tension = next.tension ?? 0.25; next.borderWidth = next.borderWidth ?? 2; next.pointRadius = next.pointRadius ?? 3; }
    else { next.backgroundColor = next.backgroundColor || color; next.borderColor = next.borderColor || color; next.borderWidth = next.borderWidth ?? 1; next.maxBarThickness = next.maxBarThickness ?? 18; }
    return next;
  });
  const sd = { grid: { color: th.grid }, border: { color: th.grid }, ticks: { color: th.muted } };
  const scales = {};
  for (const [k, v] of Object.entries(options.scales || { x: {}, y: {} })) scales[k] = { ...sd, ...v, grid: { ...sd.grid, ...(v.grid || {}) }, border: { ...sd.border, ...(v.border || {}) }, ticks: { ...sd.ticks, ...(v.ticks || {}) } };
  return new Chart(ctx, { type, data: { ...data, datasets }, options: { ...options, color: th.muted, scales,
    plugins: { legend: { labels: { color: th.muted }, ...(options.plugins?.legend || {}) }, tooltip: { backgroundColor: th.surface, titleColor: th.text, bodyColor: th.text, borderColor: th.border, borderWidth: 1, ...(options.plugins?.tooltip || {}) }, ...(options.plugins || {}) } } });
}

function validMonths(data) {
  const now = new Date(); const nowMonth = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  return (data.months || []).filter((m) => { const st = data.monthly_stats[m]; return st && st.total_items >= 100 && m <= nowMonth; });
}

function renderVolumeChart(data) {
  const months = validMonths(data);
  volumeChart = makeChart(volumeChart, document.getElementById("volumeMonthChart").getContext("2d"), "bar",
    { labels: months.map((m) => data.monthly_stats[m].label), datasets: [{ label: "Total items", data: months.map((m) => data.monthly_stats[m].total_items) }, { label: "Curated", data: months.map((m) => data.monthly_stats[m].curated_items) }] },
    { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { maxTicksLimit: 12 } }, y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: true, position: "top" } } });
}

function renderCveMonthChart(data) {
  const months = validMonths(data);
  cveMonthChart = makeChart(cveMonthChart, document.getElementById("cveMonthChart").getContext("2d"), "bar",
    { labels: months.map((m) => data.monthly_stats[m].label), datasets: [{ label: "Unique CVEs", data: months.map((m) => data.monthly_stats[m].unique_cves) }] },
    { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { maxTicksLimit: 12 } }, y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } } });
}

function renderTopicChart(data) {
  const months = validMonths(data); const pal = palette();
  const datasets = TOPIC_KEYS.map((key, i) => ({ label: TOPIC_LABELS[key], data: months.map((m) => { const tt = data.monthly_stats[m]?.trending_terms || {}; return (tt[key] || tt[key + "s"] || { count: 0 }).count || 0; }), borderColor: pal[i % pal.length], backgroundColor: "transparent", pointRadius: 3, borderWidth: 2, tension: 0.3, fill: false }));
  topicChart = makeChart(topicChart, document.getElementById("topicEvolutionChart").getContext("2d"), "line",
    { labels: months.map((m) => data.monthly_stats[m].label), datasets },
    { responsive: true, maintainAspectRatio: false, scales: { x: { ticks: { maxTicksLimit: 12 } }, y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: true, position: "top" } } });
}

function renderMonthSelector(data) {
  const months = validMonths(data); const container = document.getElementById("monthSelector"); container.innerHTML = "";
  months.forEach((m) => {
    const btn = document.createElement("button"); btn.className = "month-btn"; btn.textContent = data.monthly_stats[m].label; btn.dataset.month = m;
    btn.addEventListener("click", () => { container.querySelectorAll(".month-btn").forEach((b) => b.classList.remove("active")); btn.classList.add("active"); renderMonthDetail(data, m); });
    container.appendChild(btn);
  });
}

function renderMonthDetail(data, month) {
  selectedMonth = month; const stats = data.monthly_stats[month]; const grid = document.getElementById("monthDetailGrid");
  if (!stats) { grid.innerHTML = "<p class='cve-empty'>No data.</p>"; return; }
  const makeList = (title, rows, onClick) => {
    const block = document.createElement("div"); block.className = "detail-block";
    const h3 = document.createElement("h3"); h3.textContent = title; block.appendChild(h3);
    const ul = document.createElement("ul"); ul.className = "detail-list";
    rows.slice(0, 10).forEach(([name, count]) => {
      const li = document.createElement("li"); li.className = "detail-item";
      const a = document.createElement("a"); a.textContent = name;
      if (onClick) a.addEventListener("click", () => onClick(name)); else a.href = `${newsUrl}?q=${encodeURIComponent(name)}`;
      const cnt = document.createElement("span"); cnt.className = "detail-count"; cnt.textContent = count;
      li.appendChild(a); li.appendChild(cnt); ul.appendChild(li);
    });
    block.appendChild(ul); return block;
  };
  grid.innerHTML = "";
  grid.appendChild(makeList("Top CVEs", stats.top_cves, (cve) => populateCveTracker(data, cve)));
  grid.appendChild(makeList("Top Vendors", stats.top_vendors));
  grid.appendChild(makeList("Top Smart Groups", stats.top_smart_groups));
}

function renderCveAllTimeChart(data) {
  const top20 = (data.top_cves_all_time || []).slice(0, 20);
  cveAllTimeChart = makeChart(cveAllTimeChart, document.getElementById("cveAllTimeChart").getContext("2d"), "bar",
    { labels: top20.map((r) => r.cve), datasets: [{ label: "Total mentions", data: top20.map((r) => r.total) }] },
    { indexAxis: "y", responsive: true, maintainAspectRatio: false, scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { display: false }, tooltip: { callbacks: { afterLabel: (ctx) => { const r = top20[ctx.dataIndex]; return r ? `Months active: ${r.months_active} | First: ${r.first_seen} | Last: ${r.last_seen}` : ""; } } } },
      onClick: (_, els, chart) => { if (!els.length) return; populateCveTracker(data, chart.data.labels[els[0].index]); } });
  document.getElementById("cveAllTimeChart").classList.add("chart-clickable");
}

function populateCveTracker(data, cveId) { const input = document.getElementById("cve-search-input"); input.value = cveId; renderCveLifecycle(data, cveId); input.scrollIntoView({ behavior: "smooth", block: "center" }); }

function renderCveLifecycle(data, cveId) {
  const upper = (cveId || "").toUpperCase().trim(); const lifecycle = data.cve_lifecycle[upper];
  const metaRow = document.getElementById("cve-meta-row"); const ctx = document.getElementById("cveLifecycleChart").getContext("2d");
  if (!lifecycle) { metaRow.style.display = "none"; cveLifecycleChart = makeChart(cveLifecycleChart, ctx, "bar", { labels: [], datasets: [{ label: "Mentions", data: [] }] }, { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }); return; }
  const allMonths = Object.keys(lifecycle.monthly_counts).sort();
  metaRow.style.display = "flex";
  metaRow.replaceChildren();
  const chips = [
    { label: "", value: upper },
    { label: "Total: ", value: lifecycle.total },
    { label: "Months active: ", value: lifecycle.months_active },
    { label: "First: ", value: lifecycle.first_seen },
    { label: "Last: ", value: lifecycle.last_seen }
  ];
  chips.forEach((chip) => {
    const span = document.createElement("span");
    span.className = "cve-meta-chip";
    if (chip.label) span.append(document.createTextNode(chip.label));
    const strong = document.createElement("strong");
    strong.textContent = String(chip.value ?? "");
    span.appendChild(strong);
    metaRow.appendChild(span);
  });
  cveLifecycleChart = makeChart(cveLifecycleChart, ctx, "bar",
    { labels: allMonths.map((m) => { const st = data.monthly_stats[m]; return st ? st.label : m; }), datasets: [{ label: "Mentions", data: allMonths.map((m) => lifecycle.monthly_counts[m] || 0) }] },
    { responsive: true, maintainAspectRatio: false, scales: { x: {}, y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false }, tooltip: { callbacks: { title: (items) => items[0] ? `${upper} – ${items[0].label}` : upper } } } });
}

function buildCveDatalist(data) { const dl = document.getElementById("cve-datalist"); (data.top_cves_all_time || []).slice(0, 100).forEach((r) => { const opt = document.createElement("option"); opt.value = r.cve; dl.appendChild(opt); }); }

function initPage(data) {
  histData = data; const months = validMonths(data);
  const oldest = months[0] ? data.monthly_stats[months[0]].label : "?";
  const newest = months[months.length - 1] ? data.monthly_stats[months[months.length - 1]].label : "?";
  document.getElementById("history-meta").textContent = `${months.length} months · ${oldest} – ${newest} · ${(data.top_cves_all_time || []).length} unique CVEs tracked`;
  renderVolumeChart(data); renderCveMonthChart(data); renderTopicChart(data); renderMonthSelector(data); renderCveAllTimeChart(data); buildCveDatalist(data);
  if (months.length) { const lastBtn = document.querySelector(`.month-btn[data-month="${months[months.length - 1]}"]`); if (lastBtn) lastBtn.click(); }
  const input = document.getElementById("cve-search-input"); let debounce = null;
  input.addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(() => renderCveLifecycle(data, input.value), 250); });
}

document.addEventListener("DOMContentLoaded", () => {
  fetch(histUrl, { cache: "no-store" }).then((r) => r.json()).then(initPage).catch((err) => { console.error("Failed to load historical_trends.json", err); document.getElementById("history-meta").textContent = "Failed to load historical data."; });
});

window.addEventListener("s33r:themechange", () => {
  if (!histData) return;
  renderVolumeChart(histData); renderCveMonthChart(histData); renderTopicChart(histData); renderCveAllTimeChart(histData);
  const input = document.getElementById("cve-search-input"); if (input.value) renderCveLifecycle(histData, input.value);
});
