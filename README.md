<img width="1374" height="569" alt="image" src="https://github.com/user-attachments/assets/25ebd1ad-f1a8-4dbb-9ff2-2e1bcc6d9649" />

# S33R Security News Feed

A **GitHub Pages–friendly security news platform** that aggregates, normalizes, archives, and visualizes cybersecurity news from hundreds of public RSS feeds.

This project delivers:

- A fast, filterable **24h News Feed**
- A complete **Historical Archive** (monthly + yearly)
- An **Annual Overview Dashboard** with `<canvas>` charts
- Automated backend powered by **GitHub Actions + Python**
- Fully static front-end optimized for GitHub Pages

Everything runs without servers, APIs, or databases — just HTML, CSS, JS, and prebuilt JSON.

---

## 🚀 Features

### 🔥 Live-style News Feed (`index.html`)
- Displays only the most recent **24 hours** of security news  
- Category filters (Crypto, DFIR, Malware, Threat Intel, CVEs, etc.)  
- Full-text search (title, summary, source)  
- Infinite scroll (progressive card loading)  
- Dracula-inspired dark theme  
- Blazing fast thanks to a **prebuilt JSON cache**

---

### 📦 Historical Archive (`archive.html`)
Browse all past content with:

- **Monthly archives** from `/data/archive/monthly/YYYY/YYYY-MM.json`
- Search within the archive (title, summary, source)
- Group-by-source toggle
- Pagination
- Automatic statistics for any period:
  - total items  
  - number of sources  
  - date range  
  - top sources  

---

### 📊 Annual Overview Dashboard (`archive-overview.html`)
A fully static dashboard built with **vanilla JS + `<canvas>`**, no libraries:

- Monthly activity chart (bar chart)
- Top sources (horizontal bar chart)
- Summary metadata:
  - total items in the year  
  - number of sources  
  - first and last publication date  
- Loads from `/data/archive/yearly/YYYY.json`

Perfect for analyzing feed performance, seasonality, and content trends.

---

## ⚙️ Automated Backend Architecture

Two Python pipelines run via GitHub Actions.

---

### **1. build_news_json.py — 24h Feed Generator**
Creates the file used by the homepage:

```
data/news_recent.json
```

Process:
1. Reads feeds from `sec_feeds.xml` (OPML).
2. Fetches and normalizes all RSS entries.
3. Deduplicates by link.
4. Keeps only entries from the last **24 hours**.
5. Saves compact JSON for fast front-end lookup.

Triggered by:

```
.github/workflows/update_news_json.yml
```

---

### **2. build_news_archive.py — Archive Builder**
Maintains long-term historical storage:

```
data/archive/
  yearly/YYYY.json
  monthly/YYYY/YYYY-MM.json
```

Logic:
- Loads the latest `news_recent.json`
- Sorts, deduplicates, merges incrementally
- Commits new/updated JSON files back to the repository

Triggered by:

```
.github/workflows/update_news_archive.yml
```

---

## 📁 Project Structure

```
S33R/
│
├── index.html                  # Main 24h news feed
├── archive.html                # Monthly archive UI
├── archive-overview.html       # Annual visualization dashboard
│
├── styles.css                  # Dracula-inspired theme
│
├── data/
│   ├── news_recent.json        # Auto-generated (last 24h)
│   └── archive/
│       ├── yearly/2025.json
│       └── monthly/2025/2025-11.json
│
├── scripts/
│   ├── build_news_json.py      # Generates recent JSON cache
│   └── build_news_archive.py   # Builds monthly/yearly history
│
└── .github/
    └── workflows/
        ├── update_news_json.yml
        └── update_news_archive.yml
```

---

## 🔧 Customization

### Change the time window (default: 24 hours)
Edit in `scripts/build_news_json.py`:

```python
DAYS_BACK = 1
```

### Add or remove RSS feeds  
Edit:

```
sec_feeds.xml
```

(OPML format supports categories, labels, nesting)

### Adjust categories  
Modify in `index.html`:

- category buttons  
- `TYPE_LABELS` mapping  

### Tweak styling  
Edit:

```
styles.css
```

The UI uses CSS variables (`--bg-elevated`, `--accent`, etc.) for easy theme mods.

---

## 🖥️ Local Preview

Serve the repository locally:

```bash
cd S33R
python -m http.server 8000
```

Open:

```
http://localhost:8000
```

---

## 🧠 Why this architecture?

- No CORS problems (feeds fetched server-side via Actions)
- Frontend loads instantly thanks to prebuilt JSON
- Historical data is always preserved and updated incrementally
- GitHub Pages works perfectly with static JSON + JS
- No external dependencies or backend servers

---

## 📌 Optional Enhancements (future roadmap)

- Source reliability scoring  
- Per-category analytics  
- Tag cloud / topic extraction  
- User preferences stored in localStorage  
- Light/dark theme toggle  

---

## 💬 Feedback & Contributions

Issues and PRs are welcome.  
Feel free to fork, adapt, or reuse this architecture for your own OSINT / Threat Intel dashboards.

---

**S33R — Security News. Sorted. Simplified. Static.**
