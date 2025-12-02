#!/usr/bin/env python3
"""
Gera data/trends.json com métricas de tendências:

- Top keywords por janela (24h, 7d, 30d, 90d)
- Volume diário de notícias (últimos 90d)
- Breakdown por categoria
- Contagem por vendor
- Tendências de termos de ataque (ransomware, supply chain, 0-day, etc.)
- Heatmap MITRE ATT&CK (T-codes) por frequência

Fonte de dados:
- data/news_recent.json
- data/archive/monthly/<ano>/*.json
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Any, Iterable, Optional

# -------------------------------
# Caminhos baseados na estrutura do S33R
# -------------------------------
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"

RECENT_PATH = DATA_DIR / "news_recent.json"
ARCHIVE_DIR = DATA_DIR / "archive"
MONTHLY_DIR = ARCHIVE_DIR / "monthly"

OUTPUT_PATH = DATA_DIR / "trends.json"  # => trend.html lê em "data/trends.json"

TIME_WINDOWS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}

ATTACK_TERMS = {
    "ransomware": "Ransomware",
    "supply chain": "Supply chain",
    "0-day": "0-day",
    "zero-day": "Zero-day",
    "supply-chain": "Supply-chain",
    "phishing": "Phishing",
    "data extortion": "Data extortion",
    "double extortion": "Double extortion",
}

VENDORS = [
    "CrowdStrike", "Microsoft", "Cisco", "Palo Alto", "Palo Alto Networks",
    "Fortinet", "Cloudflare", "Google", "Mandiant", "FireEye",
    "Check Point", "Trend Micro", "SentinelOne", "Okta",
    "Zscaler", "IBM", "Rapid7", "Sophos", "Kaspersky",
    "Oracle", "Amazon", "AWS",
]

STOPWORDS = {
    "the", "and", "for", "with", "from", "this", "that", "have",
    "has", "into", "about", "como", "para", "com", "uma", "uma",
    "dos", "das", "nos", "nas", "de", "da", "do", "aqui", "mais",
    "less", "but", "you", "your", "their", "them", "they", "was",
    "were", "will", "would", "could", "should", "sobre", "entre",
    "após", "apos", "after", "before", "during",
}


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        return datetime.fromisoformat(v).astimezone(timezone.utc)
    except Exception:
        return None


def load_json_items(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}")
        return []

    # news_recent.json tem formato {"items": [...]}
    if isinstance(raw, dict) and "items" in raw:
        items = raw["items"]
        return items if isinstance(items, list) else []

    # arquivos mensais são listas
    if isinstance(raw, list):
        return raw

    return []


def iter_news_items() -> Iterable[Dict[str, Any]]:
    """Itera sobre news_recent + arquivos mensais (dedupe por link)."""
    seen_links = set()

    # recent
    for item in load_json_items(RECENT_PATH):
        link = item.get("link") or item.get("url")
        if not link or link in seen_links:
            continue
        seen_links.add(link)
        yield item

    # monthly/<ano>/*.json
    if MONTHLY_DIR.exists():
        for year_dir in sorted(MONTHLY_DIR.iterdir()):
            if not year_dir.is_dir():
                continue
            for path in sorted(year_dir.glob("*.json")):
                for item in load_json_items(path):
                    link = item.get("link") or item.get("url")
                    if not link or link in seen_links:
                        continue
                    seen_links.add(link)
                    yield item


def extract_keywords(item: Dict[str, Any]) -> List[str]:
    # Se já houver keywords/tags no item, usa direto
    for key in ("keywords", "tags"):
        if key in item and item[key]:
            val = item[key]
            if isinstance(val, str):
                return [val.strip().lower()] if val.strip() else []
            if isinstance(val, list):
                return [str(v).strip().lower() for v in val if str(v).strip()]
    # Caso contrário, extrai do texto
    text_parts = [
        item.get("title") or "",
        item.get("summary") or "",
        item.get("description") or "",
    ]
    text = " ".join(text_parts).lower()
    words = re.findall(r"[a-z0-9\-]{4,}", text)
    return [
        w for w in words
        if w not in STOPWORDS and not w.isdigit()
    ]


EXCLUDED_CATEGORIES = {"Curated"}

def extract_categories(item: Dict[str, Any]) -> List[str]:
    """
    Use the same grouping field used by S33R smart groups.
    Priority:
    - smart_groups (main field used in news_recent.json)
    - categories / category (fallbacks, if present)
    """
    cats = (
        item.get("smart_groups")
        or item.get("categories")
        or item.get("category")
        or []
    )

    if isinstance(cats, str):
        cats = [cats]

    cleaned = []
    for c in cats:
        c = str(c).strip()
        if not c:
            continue
        if c in EXCLUDED_CATEGORIES:
            continue
        cleaned.append(c)

    return cleaned



def extract_mitre_techniques(item: Dict[str, Any]) -> List[str]:
    mitre = item.get("mitre_techniques") or item.get("mitre") or []
    if isinstance(mitre, str):
        mitre = [mitre]

    techniques: List[str] = []

    for m in mitre:
        m_str = str(m).strip().upper()
        if re.match(r"^T\d{4}(\.\d{3})?$", m_str):
            techniques.append(m_str)

    # Também tenta achar Txxxx no texto
    blob = " ".join([
        item.get("title") or "",
        item.get("summary") or "",
        item.get("description") or "",
        " ".join(item.get("tags") or []),
    ])
    for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", blob):
        m_str = match.strip().upper()
        if m_str:
            techniques.append(m_str)

    # remove duplicados preservando ordem
    seen = set()
    norm: List[str] = []
    for t in techniques:
        if t not in seen:
            seen.add(t)
            norm.append(t)
    return norm


def detect_vendors(item: Dict[str, Any]) -> List[str]:
    text = " ".join([
        item.get("title") or "",
        item.get("summary") or "",
        item.get("description") or "",
        item.get("source") or "",
    ]).lower()
    found: List[str] = []
    for v in VENDORS:
        if v.lower() in text:
            found.append(v)
    return found


def count_attack_terms(text: str) -> Counter:
    text_l = text.lower()
    counts: Counter = Counter()
    for raw, label in ATTACK_TERMS.items():
        if raw in text_l:
            counts[label] += text_l.count(raw)
    return counts


def main() -> None:
    now = datetime.now(timezone.utc)

    # Counters por janela
    keyword_counters: Dict[str, Counter] = {k: Counter() for k in TIME_WINDOWS}
    category_counters: Dict[str, Counter] = {k: Counter() for k in TIME_WINDOWS}
    vendor_counters: Dict[str, Counter] = {k: Counter() for k in TIME_WINDOWS}
    attack_counters: Dict[str, Counter] = {k: Counter() for k in TIME_WINDOWS}

    # MITRE (90d) + volume diário (90d)
    mitre_counter: Counter = Counter()
    daily_counts: Counter = Counter()

    max_age = TIME_WINDOWS["90d"]

    for item in iter_news_items():
        published = parse_datetime(item.get("published") or item.get("date"))
        if not published:
            continue

        age = now - published
        if age < timedelta(0) or age > max_age:
            continue

        day_key = published.strftime("%Y-%m-%d")
        daily_counts[day_key] += 1

        keywords = extract_keywords(item)
        categories = extract_categories(item)
        mitre = extract_mitre_techniques(item)
        vendors_found = detect_vendors(item)

        text_blob = " ".join([
            item.get("title") or "",
            item.get("summary") or "",
            item.get("description") or "",
        ])
        attack_terms_counts = count_attack_terms(text_blob)

        # Atualiza counters por janela
        for win_key, delta in TIME_WINDOWS.items():
            if age <= delta:
                keyword_counters[win_key].update(keywords)
                category_counters[win_key].update(categories)
                vendor_counters[win_key].update(vendors_found)
                attack_counters[win_key].update(attack_terms_counts)

        mitre_counter.update(mitre)

    # Volume diário (ordenado por data)
    daily_volume = [
        {"date": d, "count": int(daily_counts[d])}
        for d in sorted(daily_counts.keys())
    ]

    # Top keywords / vendors por janela
    top_keywords = {
        win: [[k, int(c)] for k, c in counter.most_common(30)]
        for win, counter in keyword_counters.items()
    }
    vendors = {
        win: [[k, int(c)] for k, c in counter.most_common(20)]
        for win, counter in vendor_counters.items()
    }
    categories = {
        win: {k: int(c) for k, c in counter.most_common()}
        for win, counter in category_counters.items()
    }

    trending_terms: Dict[str, Any] = {}
    for _raw, label in ATTACK_TERMS.items():
        term_data = {}
        for win in TIME_WINDOWS:
            term_data[win] = int(attack_counters[win][label])
        trending_terms[label] = {
            "label": label,
            "counts": term_data,
        }

    mitre_counts = [
        {"technique": t, "count": int(c)}
        for t, c in mitre_counter.most_common()
    ]

    output = {
        "generated_at": now.isoformat(),
        "windows": list(TIME_WINDOWS.keys()),
        "daily_volume": daily_volume,
        "top_keywords": top_keywords,
        "vendors": vendors,
        "categories": categories,
        "mitre_counts": mitre_counts,
        "trending_terms": trending_terms,
    }

    OUTPUT_PATH.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Trends written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
