/* ============================================================
   S33R — shared activity rail (WARDEN redesign)
   Injects the left icon rail used across every page so the
   navigation chrome stays identical and in one place.
   Set the active item with <body data-page="morning"> etc.
   Depends on ui.js (window.S33R_UI) for theme toggle.
   ============================================================ */
(function () {
  const ICONS = {
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    seer: '<path d="M7 32 C18 18 46 18 57 32 C46 46 18 46 7 32 Z" fill="none" stroke="currentColor" stroke-width="3.6" stroke-linejoin="round"/><circle cx="32" cy="32" r="9.5" fill="none" stroke="currentColor" stroke-width="3.6"/><path d="M32 32 L32 22.5 A9.5 9.5 0 0 1 40.7 27.6 Z" fill="currentColor"/><circle cx="32" cy="32" r="3.4" fill="currentColor"/>',
    feed: '<path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/>',
    am: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M5 5l1.5 1.5M17.5 17.5 19 19M2 12h2M20 12h2M5 19l1.5-1.5M17.5 6.5 19 5"/>',
    trend: '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>',
    hist: '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 16 14"/>',
    brief: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
    arch: '<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/>',
    ovr: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>',
    src: '<path d="M5 12.5a11 11 0 0 1 14 0"/><path d="M1.5 9a16 16 0 0 1 21 0"/><circle cx="12" cy="20" r="1"/>',
    github: '<path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.24-.82 2.18-.74.33-2.58.94-3.68-1.18 0 0-.68-1.23-2-1.32 0 0-1.28-.02-.09.8 0 0 .86.4 1.46 1.92 0 0 .77 2.57 4.27 1.7V22"/>',
  };

  // [key, label, standalone-href, jekyll-permalink (no leading slash), icon]
  const NAV = [
    ["feed", "FEED", "S33R Feed.html", "", "feed"],
    ["morning", "AM", "S33R Morning.html", "morning/", "am"],
    ["trends", "TREND", "S33R Trends.html", "trend/", "trend"],
    ["history", "HIST", "S33R History.html", "history/", "hist"],
    ["briefs", "BRIEF", "S33R Briefs.html", "briefs/", "brief"],
    ["archive", "ARCH", "S33R Archive.html", "archive/", "arch"],
    ["overview", "OVR", "S33R Overview.html", "archive-overview/", "ovr"],
    ["sources", "SRC", "S33R Sources.html", "sources/", "src"],
  ];

  // When running inside the Jekyll site, pages define window.S33R.base
  // (e.g. "/S33R/") so links honour the site baseurl. Otherwise we fall
  // back to the standalone .html filenames.
  const BASE = (window.S33R && window.S33R.base) || null;
  const hrefFor = (htmlHref, perm) => BASE != null ? BASE + perm : htmlHref;

  function svg(name) {
    return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;
  }

  function build() {
    const active = document.body.dataset.page || "";
    const nav = document.createElement("nav");
    nav.className = "rail";
    nav.setAttribute("aria-label", "Sections");
    nav.innerHTML =
      `<a class="rail-logo" href="${hrefFor("S33R Feed.html", "")}" title="S33R — the SEER"><svg width="25" height="25" viewBox="0 0 64 64" fill="none" stroke-linecap="round">${ICONS.seer}</svg></a>` +
      NAV.map(([key, label, htmlHref, perm, icon]) =>
        `<a class="rail-link${key === active ? " on" : ""}" href="${hrefFor(htmlHref, perm)}"${key === active ? ' aria-current="page"' : ""}>${svg(icon)}${label}</a>`
      ).join("") +
      `<div class="rail-spacer"></div>` +
      `<a class="rail-github" href="https://github.com/clivoa/S33R" target="_blank" rel="noopener noreferrer" title="Open S33R on GitHub" aria-label="Open S33R on GitHub">${svg("github")}</a>` +
      `<button class="rail-theme" id="rail-theme" title="Toggle theme (Shift+T)">◐</button>`;
    return nav;
  }

  function mount() {
    const host = document.getElementById("app") || document.querySelector(".app");
    if (!host || host.querySelector(".rail")) return;
    const nav = build();
    host.insertBefore(nav, host.firstChild);
    const tbtn = nav.querySelector("#rail-theme");
    if (tbtn) tbtn.addEventListener("click", () => window.S33R_UI && window.S33R_UI.toggleTheme());
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
