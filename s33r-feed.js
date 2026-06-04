/* ============================================================
   S33R Feed — application logic (redesign "WARDEN")
   Vanilla JS. Depends only on window.S33R_UI (ui.js).
   ============================================================ */
(function () {
  const DATA_URL = (window.S33R && window.S33R.feed) || "feed_data.json";

  const CATS = [
    ["all", "All"], ["curated", "Curated"], ["crypto", "Crypto"],
    ["cybercrime", "Cybercrime, Darknet"], ["dfir", "DFIR"], ["general", "General Security"],
    ["government", "Government, CERT"], ["leaks", "Leaks"], ["malware", "Malware"],
    ["threat_intel", "Threat Intel"], ["malware_analysis", "Malware Analysis"],
    ["osint", "OSINT, Communities"], ["podcasts", "Podcasts"], ["vendors", "Vendors"],
    ["vulns", "Vulnerabilities, CVEs"], ["exploits", "Exploits"], ["vuln_advisories", "Vulnerability Advisories"],
  ];
  const TYPE_SHORT = {
    crypto: "Crypto", cybercrime: "Cybercrime", dfir: "DFIR", general: "General",
    government: "Gov / CERT", leaks: "Leaks", malware: "Malware", threat_intel: "Threat Intel",
    malware_analysis: "Mal. Analysis", osint: "OSINT", podcasts: "Podcast",
    vendors: "Vendor", vulns: "Vuln / CVE", exploits: "Exploit", vuln_advisories: "Advisory",
  };
  const CATEGORY_SMARTGROUP_RULES = {
    vulns: ["cve-", "vulnerability", "vulnerabilities", "remote code execution", "rce", "privilege escalation", "buffer overflow", "out-of-bounds write", "sql injection", "authentication bypass", "zero-day", "0day"],
    exploits: ["exploit", "poc released", "proof-of-concept", "exploit code", "weaponized", "exploit available", "exploit toolkit", "exploit released"],
    vuln_advisories: ["security advisory", "security bulletin", "patch tuesday", "security update", "cumulative update", "vendor advisory"],
    crypto: ["blockchain", "web3", "smart contract", "defi", "dex", "exchange", "wallet", "token", "nft", "airdrops", "rug pull", "bridge exploit"],
    cybercrime: ["darknet", "dark web", "marketplace", "ransomware gang", "ransom gang", "initial access broker", "data leak site", "leak site", "underground forum", "crimeware", "credential stuffing"],
    dfir: ["dfir", "forensics", "memory analysis", "timeline analysis", "incident response", "artifact", "mft", "prefetch", "dfrws"],
    general: ["cybersecurity", "information security", "infosec", "security posture", "security program", "risk management"],
    government: ["cert-", "csirt", "gov", "government", "cisa", "enisa", "nist", "nsa", "national cyber"],
    leaks: ["data breach", "breach", "customer data", "stolen data", "leaked database", "leaked data", "breached records", "database leak", "compromised data"],
    malware: ["malware", "ransomware", "trojan", "backdoor", "botnet", "infostealer", "loader", "wiper", "remote access trojan", "rat ", "payload", "locker"],
    threat_intel: ["apt ", "nation-state", "state-sponsored", "threat actor", "actor group", "campaign", "ttp", "ioc", "indicator of compromise", "mitre att&ck"],
    malware_analysis: ["reverse engineering", "static analysis", "dynamic analysis", "sandbox analysis", "yara rule", "unpack", "disassembly", "debugger", "emulation"],
    osint: ["osint", "open-source intelligence", "community project", "github repo", "threat hunting community", "slack workspace", "discord community"],
    podcasts: ["podcast", "episode", "listen", "audio only", "show notes"],
    vendors: ["vendor", "product update", "security appliance", "endpoint security", "siem", "xdr", "edr", "ngfw", "cloud security product", "microsoft", "google cloud", "aws", "azure", "palo alto", "crowdstrike", "cisco", "fortinet", "checkpoint"],
  };
  const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  const $ = (s, r = document) => r.querySelector(s);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const cvesOf = (t) => [...new Set((String(t || "").match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((m) => m.toUpperCase()))];
  const cvesItem = (it) => cvesOf((it.title || "") + " " + (it.summary || ""));
  const signalScore = (it) => Number(it.signal_score ?? it.priority_score ?? 0) || 0;
  const signalTier = (it) => String(it.signal_tier || "").toLowerCase();
  const isHighSignal = (it) => {
    const tier = signalTier(it);
    if (tier) return tier === "critical" || tier === "high";
    return signalScore(it) >= 90 && !!it.curated;
  };

  function heat(it) {
    const tier = signalTier(it);
    if (tier === "critical") return "hot";
    if (tier === "high") return "warm";
    return "";
  }
  const pct = (s) => Math.max(6, Math.min(100, s));

  function tparts(ts) {
    if (!ts) return { t: "--:--", d: "—", ago: "" };
    const x = new Date(ts * 1000);
    const t = String(x.getHours()).padStart(2, "0") + ":" + String(x.getMinutes()).padStart(2, "0");
    const d = MON[x.getMonth()] + " " + String(x.getDate()).padStart(2, "0");
    const mins = Math.max(0, Math.floor((Date.now() - x.getTime()) / 60000));
    const ago = mins < 60 ? mins + "m" : mins < 1440 ? Math.floor(mins / 60) + "h" : Math.floor(mins / 1440) + "d";
    return { t, d, ago };
  }
  function fullDate(ts) {
    if (!ts) return "Unknown";
    return new Date(ts * 1000).toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  }

  const state = {
    all: [], filtered: [], visible: 0, batch: 30,
    category: "all", search: "", sort: "priority", windowHours: 24, highOnly: false,
    generatedAt: null,
  };

  /* ---------- matching ---------- */
  function matchCat(it, cat) {
    if (cat === "all") return true;
    if (cat === "curated") return !!it.curated;
    if (it.type === cat) return true;
    const rules = CATEGORY_SMARTGROUP_RULES[cat];
    if (rules) {
      const hay = ((it.smart_groups || []).join(" ") + " " + (it.title || "") + " " + (it.summary || "")).toLowerCase();
      if (rules.some((kw) => hay.includes(kw))) return true;
    }
    return false;
  }

  /* ---------- categories sidebar ---------- */
  function renderCategories() {
    const host = $("#cat-list");
    host.innerHTML = "";
    CATS.forEach(([key, label]) => {
      const count = key === "all" ? state.all.length : state.all.filter((it) => matchCat(it, key)).length;
      const b = document.createElement("button");
      b.className = "cat" + (key === state.category ? " on" : "");
      b.dataset.cat = key;
      b.innerHTML = `<span class="ci"></span><span class="cl">${esc(label)}</span><span class="cn">${count}</span>`;
      host.appendChild(b);
    });
  }

  /* ---------- war room ---------- */
  function renderWarRoom() {
    const now = Date.now() / 1000;
    const items24 = state.all.filter((i) => (i.published_ts || 0) > now - 86400).length;
    const items7 = state.all.filter((i) => (i.published_ts || 0) > now - 7 * 86400).length;
    const hot = state.all.filter(isHighSignal).length;
    const cveSet = new Set(); state.all.forEach((i) => cvesItem(i).forEach((c) => cveSet.add(c)));

    const hour = new Date().getHours();
    const greet = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
    $("#wr-title").innerHTML = `${greet}, <span>Analyst.</span>`;

    const set = (id, v) => { const e = $(id); e.textContent = Number(v).toLocaleString(); e.classList.remove("is-loading"); };
    set("#m-24h", items24); set("#m-7d", items7); set("#m-hot", hot); set("#m-cve", cveSet.size);
    $("#m-24h-sub").textContent = `of ${state.all.length.toLocaleString()} total`;

    /* threat level from hot ratio */
    const ratio = state.all.length ? hot / state.all.length : 0;
    const levels = [["GUARDED", 2], ["ELEVATED", 3], ["HIGH", 4], ["SEVERE", 5]];
    const idx = ratio > 0.45 ? 3 : ratio > 0.3 ? 2 : ratio > 0.15 ? 1 : 0;
    $("#threat-lvl").textContent = levels[idx][0];
    $("#threat-bars").innerHTML = Array.from({ length: 5 }, (_, i) => `<i class="${i < levels[idx][1] ? "a" : ""}"></i>`).join("");

    if (state.generatedAt) {
      const diff = Math.floor((Date.now() - new Date(state.generatedAt).getTime()) / 60000);
      const lab = diff < 60 ? diff + "m ago" : Math.floor(diff / 60) + "h ago";
      document.querySelectorAll(".js-updated").forEach((e) => (e.textContent = lab));
    }
  }

  /* ---------- intel rail (computed) ---------- */
  function renderIntel() {
    /* top CVEs */
    const cnt = {};
    state.all.forEach((i) => cvesItem(i).forEach((c) => (cnt[c] = (cnt[c] || 0) + 1)));
    const top = Object.entries(cnt).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const max = top.length ? top[0][1] : 1;
    $("#intel-cves").innerHTML = top.length ? top.map(([id, n]) =>
      `<div class="icve"><span class="id">${id}</span><span class="bar"><i style="width:${Math.max(14, (n / max) * 100)}%"></i></span><span class="ct">${n}</span></div>`).join("")
      : `<div class="imv" style="color:var(--faint)">No CVEs in window</div>`;
    $("#intel-cve-ct").textContent = Object.keys(cnt).length;

    /* smart groups */
    const sg = {};
    state.all.forEach((i) => (i.smart_groups || []).forEach((g) => { if (/^curated$/i.test(g)) return; sg[g] = (sg[g] || 0) + 1; }));
    const tg = Object.entries(sg).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const dots = ["var(--red)", "var(--brand)", "var(--cyan)", "var(--teal)", "var(--dim)"];
    const tot = state.all.length || 1;
    $("#intel-groups").innerHTML = tg.length ? tg.map(([g, n], i) =>
      `<div class="imv"><span class="dot" style="background:${dots[i]}"></span>${esc(g)}<span class="pct up">${Math.round((n / tot) * 100)}%</span></div>`).join("")
      : `<div class="imv" style="color:var(--faint)">—</div>`;

    /* top sources by count + grade from avg quality */
    const acc = {};
    state.all.forEach((i) => { const s = i.source || "?"; (acc[s] = acc[s] || { n: 0, q: 0, qn: 0 }); acc[s].n++; if (i.source_quality_score != null) { acc[s].q += i.source_quality_score; acc[s].qn++; } });
    const grade = (q) => q >= 60 ? "A" : q >= 45 ? "B" : q >= 30 ? "C" : "D";
    const ts = Object.entries(acc).sort((a, b) => b[1].n - a[1].n).slice(0, 5);
    $("#intel-src").innerHTML = ts.map(([s, o]) => {
      const q = o.qn ? o.q / o.qn : 0; const g = grade(q);
      return `<div class="isrc"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s)}</span><span class="g ${g}">${g} · ${Math.round(q) || o.n}</span></div>`;
    }).join("");
  }

  /* ---------- row ---------- */
  function rowHTML(it) {
    const h = heat(it); const tp = tparts(it.published_ts);
    const cv = cvesItem(it); const sg = (it.smart_groups || []).filter((g) => !/^curated$/i.test(g));
    const ss = signalScore(it);
    const tier = signalTier(it);
    const label = tier === "critical" ? "CRITICAL" : tier === "high" ? "HIGH" : tier === "watch" ? "WATCH" : "SIGNAL";
    const chips = [];
    cv.slice(0, 3).forEach((c) => chips.push(`<span class="rchip cve">${c}</span>`));
    if (cv.length > 3) chips.push(`<span class="rchip more">+${cv.length - 3} CVE</span>`);
    sg.slice(0, 2).forEach((g) => chips.push(`<span class="rchip sg">${esc(g)}</span>`));
    const link = esc(it.link || "#");
    return `<article class="row ${h}" data-link="${link}">
      <div class="sev"></div>
      <div class="when"><div class="t">${tp.t}</div><div class="d">${tp.d}</div><div class="ago">${tp.ago} ago</div></div>
      <div class="body">
        <div class="rmeta">
          <span class="src">${esc(it.source || "Unknown")}</span>
          <span class="typ">${esc(TYPE_SHORT[it.type] || it.type || "feed")}</span>
          ${it.curated ? `<span class="cur">CURATED</span>` : ""}
        </div>
        <h2 class="ttl"><a href="${link}" target="_blank" rel="noopener noreferrer">${esc(it.title || "Untitled")}</a></h2>
        <p class="dsc">${esc(it.summary || "No summary available.")}</p>
        ${chips.length ? `<div class="chips">${chips.join("")}</div>` : ""}
        <div class="rfoot">
          <button class="rlink js-copy" data-link="${link}">Copy link</button>
          <a class="rlink" href="${link}" target="_blank" rel="noopener noreferrer">Read full ↗</a>
        </div>
      </div>
      <div class="score"><div class="n">${Math.round(ss)}</div><div class="lab">${label}</div><div class="track"><i style="width:${pct(ss)}%"></i></div></div>
    </article>`;
  }

  /* ---------- filtering ---------- */
  function applyFilters(reset) {
    const s = state.search.trim().toLowerCase();
    const now = Date.now() / 1000;
    const cutoff = state.windowHours > 0 ? now - state.windowHours * 3600 : 0;
    let r = state.all.filter((it) => {
      if (!matchCat(it, state.category)) return false;
      if (cutoff > 0 && (it.published_ts || 0) < cutoff) return false;
      if (state.highOnly && !isHighSignal(it)) return false;
      if (s) {
        const hay = ((it.title || "") + " " + (it.summary || "") + " " + (it.source || "")).toLowerCase();
        if (!hay.includes(s)) return false;
      }
      return true;
    });
    if (state.sort === "latest") r.sort((a, b) => (b.published_ts || 0) - (a.published_ts || 0));
    else if (state.sort === "oldest") r.sort((a, b) => (a.published_ts || 0) - (b.published_ts || 0));
    else if (state.sort === "source") r.sort((a, b) => (a.source || "").localeCompare(b.source || ""));
    else r.sort((a, b) => signalScore(b) - signalScore(a) || (b.priority_score || 0) - (a.priority_score || 0));
    state.filtered = r;
    if (reset) state.visible = Math.min(state.batch, r.length);
    renderList(); updateStatus();
  }

  function renderList() {
    const host = $("#feed");
    const total = state.filtered.length;
    if (!total) {
      host.innerHTML = `<div class="state"><h3>No results</h3><p>Try another keyword, widen the time window, or pick a different category.</p></div>`;
      return;
    }
    const limit = Math.min(state.visible, total);
    let html = "";
    for (let i = 0; i < limit; i++) html += rowHTML(state.filtered[i]);
    host.innerHTML = html;
  }

  function updateStatus() {
    const total = state.filtered.length;
    const shown = Math.min(state.visible, total);
    $("#status-count").innerHTML = total ? `Showing <b>${shown}</b> / ${total.toLocaleString()} items` : "No results";
    const visCves = collectVisibleCves().length;
    $("#status-meta").textContent = `window ${state.windowHours || "ALL"}h · ${visCves} CVEs in view`;
    ["#t-links", "#t-csv", "#t-md"].forEach((id) => { const b = $(id); if (b) b.disabled = shown === 0; });
    const cb = $("#t-cves"); if (cb) cb.disabled = visCves === 0;
  }

  const visibleItems = () => state.filtered.slice(0, Math.min(state.visible, state.filtered.length));
  function collectVisibleCves() { const s = new Set(); visibleItems().forEach((i) => cvesItem(i).forEach((c) => s.add(c))); return [...s].sort(); }

  /* ---------- exports ---------- */
  function escCsv(v) { return `"${String(v ?? "").replace(/"/g, '""')}"`; }
  function exportCsv() {
    const its = visibleItems(); if (!its.length) return S33R_UI.toast("No visible items");
    const rows = [["title", "source", "published", "type", "smart_groups", "signal_tier", "signal_score", "priority_score", "curated", "link", "summary"].map(escCsv).join(",")];
    its.forEach((i) => rows.push([i.title || "", i.source || "", i.published_ts ? fullDate(i.published_ts) : "", i.type || "", (i.smart_groups || []).join("; "), i.signal_tier || "", i.signal_score ?? "", i.priority_score ?? "", i.curated ? "yes" : "no", i.link || "", i.summary || ""].map(escCsv).join(",")));
    S33R_UI.downloadText(`s33r_${new Date().toISOString().slice(0, 10)}.csv`, rows.join("\n"), "text/csv;charset=utf-8");
    S33R_UI.toast("CSV exported");
  }
  function exportMd() {
    const its = visibleItems(); if (!its.length) return S33R_UI.toast("No visible items");
    const lines = [`# S33R Intelligence Brief — ${new Date().toISOString().slice(0, 10)}`, "", `- Items: ${its.length}`, `- Category: ${state.category}`, `- Window: ${state.windowHours || "All"}h`, ""];
    its.forEach((it, i) => {
      lines.push(`## ${i + 1}. ${it.title || "Untitled"}`);
      lines.push(`- Source: ${it.source || "Unknown"} · ${it.published_ts ? fullDate(it.published_ts) : "Unknown"}`);
      lines.push(`- Signal: ${it.signal_tier || "n/a"} (${Math.round(signalScore(it))})`);
      const cv = cvesItem(it); if (cv.length) lines.push(`- CVEs: ${cv.join(", ")}`);
      lines.push(`- Link: ${it.link || "#"}`);
      if (it.summary) lines.push(`- ${it.summary}`);
      lines.push("");
    });
    S33R_UI.downloadText(`s33r_brief_${new Date().toISOString().slice(0, 10)}.md`, lines.join("\n"), "text/markdown;charset=utf-8");
    S33R_UI.toast("Brief exported (.md)");
  }
  async function copyLinks() { const its = visibleItems(); if (!its.length) return S33R_UI.toast("No visible items"); await S33R_UI.copyText(its.map((i) => i.link).filter(Boolean).join("\n"), `${its.length} links copied`); }
  async function copyCves() { const c = collectVisibleCves(); if (!c.length) return S33R_UI.toast("No CVEs in view"); await S33R_UI.copyText(c.join("\n"), `${c.length} CVEs copied`); }

  /* ---------- events ---------- */
  function bind() {
    $("#cat-list").addEventListener("click", (e) => {
      const b = e.target.closest(".cat"); if (!b) return;
      state.category = b.dataset.cat;
      document.querySelectorAll(".cat").forEach((c) => c.classList.toggle("on", c === b));
      applyFilters(true);
    });

    const input = $("#search-input"), clear = $("#search-clear");
    let deb;
    const doSearch = () => { state.search = input.value || ""; clear.classList.toggle("hidden", !input.value); applyFilters(true); };
    input.addEventListener("input", () => { clear.classList.toggle("hidden", !input.value); clearTimeout(deb); deb = setTimeout(doSearch, 220); });
    input.addEventListener("keydown", (e) => { if (e.key === "Escape" && input.value) { input.value = ""; doSearch(); } });
    clear.addEventListener("click", () => { input.value = ""; input.focus(); doSearch(); });

    $("#twin").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; document.querySelectorAll("#twin button").forEach((x) => x.classList.toggle("on", x === b)); state.windowHours = parseInt(b.dataset.h, 10) || 0; applyFilters(true); });
    $("#sort").addEventListener("change", (e) => { state.sort = e.target.value; applyFilters(true); });
    $("#high").addEventListener("change", (e) => { state.highOnly = !!e.target.checked; applyFilters(true); });

    $("#quick").addEventListener("click", (e) => {
      const b = e.target.closest(".chip"); if (!b) return;
      const kw = b.dataset.kw || "";
      input.value = (input.value || "").trim().toLowerCase() === kw.toLowerCase() ? "" : kw;
      doSearch();
      document.querySelectorAll("#quick .chip").forEach((c) => c.classList.toggle("on", (c.dataset.kw || "").toLowerCase() === (input.value || "").toLowerCase() && input.value));
    });

    $("#t-links").addEventListener("click", copyLinks);
    $("#t-cves").addEventListener("click", copyCves);
    $("#t-csv").addEventListener("click", exportCsv);
    $("#t-md").addEventListener("click", exportMd);
    $("#a-csv").addEventListener("click", exportCsv);
    $("#a-cves").addEventListener("click", copyCves);

    $("#feed").addEventListener("click", async (e) => {
      const cp = e.target.closest(".js-copy");
      if (cp) { const ok = await S33R_UI.copyText(cp.dataset.link || "", "Link copied"); if (ok) { cp.classList.add("copied"); cp.textContent = "Copied"; setTimeout(() => { cp.classList.remove("copied"); cp.textContent = "Copy link"; }, 1200); } }
    });

    $$rail();

    window.addEventListener("scroll", () => {
      const host = $("#feed");
      const bottom = host.getBoundingClientRect().bottom;
      if (bottom - window.innerHeight < 400 && state.visible < state.filtered.length) { state.visible += state.batch; renderList(); updateStatus(); }
    }, { passive: true });

    document.addEventListener("keydown", (e) => {
      const tag = document.activeElement?.tagName;
      if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(tag)) { e.preventDefault(); input.focus(); input.select(); }
    });

    $("#rail-theme").addEventListener("click", () => S33R_UI.toggleTheme());
  }
  function $$rail() {}

  /* ---------- init ---------- */
  async function init() {
    bind();
    try {
      const data = await (await fetch(DATA_URL)).json();
      state.all = (data.items || []).map((it) => { if (!it.type && it.type_label) it.type = it.type_label.toLowerCase().replace(/\s+/g, "_"); return it; });
      state.generatedAt = data.generated_at || null;

      const feedCount = (data.source_catalog && data.source_catalog.active_feeds) || (data.feed_attempts && data.feed_attempts.length) || null;
      if (feedCount) document.querySelectorAll(".js-feed-count").forEach((el) => (el.textContent = feedCount.toLocaleString()));

      const p = new URLSearchParams(location.search);
      if (p.get("q")) { state.search = p.get("q"); state.windowHours = 0; $("#search-input").value = state.search; document.querySelectorAll("#twin button").forEach((b) => b.classList.toggle("on", b.dataset.h === "0")); }

      renderCategories(); renderWarRoom(); renderIntel();
      applyFilters(true);
    } catch (err) {
      console.error("feed load failed", err);
      $("#feed").innerHTML = `<div class="state error"><h3>Feed unavailable</h3><p>Could not load the intelligence feed. Please try again later.</p></div>`;
      $("#wr-title").textContent = "Feed unavailable";
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
