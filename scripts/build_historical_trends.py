#!/usr/bin/env python3
"""
Build data/historical_trends.json from monthly archive files.

Reads all data/archive/monthly/**/*.json and computes:
- Monthly item counts, CVE counts, source counts, curated counts
- Topic evolution (ransomware, phishing, zero-day, etc.) per month
- Top CVEs, vendors, smart groups per month
- CVE lifecycle: first seen, last seen, monthly counts across all months
"""

import json
import re
import glob
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent.parent
MONTHLY_DIR = BASE_DIR / "data" / "archive" / "monthly"
OUTPUT_PATH = BASE_DIR / "data" / "historical_trends.json"

TRENDING_TERMS = {
    "ransomware": "Ransomware",
    "supply chain": "Supply chain",
    "zero-day": "Zero-day",
    "0-day": "0-day",
    "phishing": "Phishing",
    "data breach": "Data breach",
    "initial access": "Initial access",
    "credential stuffing": "Credential stuffing",
    "double extortion": "Double extortion",
}

VENDOR_KEYWORDS = {
    "Microsoft": ["microsoft", "windows", "exchange", "azure"],
    "Cisco": ["cisco", "ios xe"],
    "Palo Alto": ["palo alto", "pan-os"],
    "Fortinet": ["fortinet", "fortigate"],
    "Google": ["google", "chrome", "android"],
    "Apple": ["apple", "macos", "ios"],
    "VMware": ["vmware", "esxi"],
    "Citrix": ["citrix"],
    "Atlassian": ["atlassian", "jira", "confluence"],
}

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def load_items(path: Path) -> List[Dict[str, Any]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Could not read {path}: {exc}")
        return []
    if isinstance(raw, list):
        return raw
    for key in ("items", "entries", "news", "data"):
        if key in raw and isinstance(raw[key], list):
            return raw[key]
    return []


def format_month_label(month: str) -> str:
    try:
        dt = datetime.strptime(month, "%Y-%m")
        return dt.strftime("%b %Y")
    except ValueError:
        return month


def main() -> None:
    monthly_files = sorted(
        Path(f) for f in glob.glob(str(MONTHLY_DIR / "**" / "*.json"), recursive=True)
    )

    monthly_stats: Dict[str, Any] = {}
    cve_lifecycle: Dict[str, Any] = defaultdict(
        lambda: {"monthly_counts": {}, "first_seen": None, "last_seen": None, "total": 0}
    )

    for path in monthly_files:
        month = path.stem
        if not re.match(r"^\d{4}-\d{2}$", month):
            continue

        items = load_items(path)
        if not items:
            print(f"[INFO] {month}: 0 items, skipping")
            continue

        texts = [
            ((i.get("title") or "") + " " + (i.get("summary") or "")).lower()
            for i in items
        ]

        cve_counter: Counter = Counter()
        for text in texts:
            for cve in CVE_REGEX.findall(text):
                cve_counter[cve.upper()] += 1

        vendor_counter: Counter = Counter()
        for text in texts:
            for vendor, patterns in VENDOR_KEYWORDS.items():
                if any(p in text for p in patterns):
                    vendor_counter[vendor] += 1

        sg_counter: Counter = Counter()
        for item in items:
            for sg in item.get("smart_groups") or []:
                if sg.lower() != "curated":
                    sg_counter[sg] += 1

        term_counts: Dict[str, Any] = {}
        for term, label in TRENDING_TERMS.items():
            count = sum(1 for t in texts if term in t)
            term_counts[term] = {"label": label, "count": count}

        curated = sum(1 for i in items if i.get("curated"))
        sources = {i.get("source") for i in items if i.get("source")}

        monthly_stats[month] = {
            "label": format_month_label(month),
            "total_items": len(items),
            "curated_items": curated,
            "unique_cves": len(cve_counter),
            "unique_sources": len(sources),
            "top_cves": [[k, v] for k, v in cve_counter.most_common(20)],
            "top_vendors": [[k, v] for k, v in vendor_counter.most_common(10)],
            "top_smart_groups": [[k, v] for k, v in sg_counter.most_common(15)],
            "trending_terms": term_counts,
        }

        for cve, count in cve_counter.items():
            lc = cve_lifecycle[cve]
            lc["monthly_counts"][month] = count
            lc["total"] += count
            if lc["first_seen"] is None or month < lc["first_seen"]:
                lc["first_seen"] = month
            if lc["last_seen"] is None or month > lc["last_seen"]:
                lc["last_seen"] = month

        print(f"[INFO] {month}: {len(items)} items | {len(cve_counter)} CVEs | {len(sources)} sources")

    top_cves_all_time = sorted(
        [
            {
                "cve": cve,
                "total": data["total"],
                "months_active": len(data["monthly_counts"]),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
            }
            for cve, data in cve_lifecycle.items()
        ],
        key=lambda x: x["total"],
        reverse=True,
    )[:100]

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "months": sorted(monthly_stats.keys()),
        "monthly_stats": monthly_stats,
        "cve_lifecycle": {
            cve: {
                "monthly_counts": data["monthly_counts"],
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "total": data["total"],
                "months_active": len(data["monthly_counts"]),
            }
            for cve, data in cve_lifecycle.items()
        },
        "top_cves_all_time": top_cves_all_time,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Written to {OUTPUT_PATH} ({len(monthly_stats)} months, {len(cve_lifecycle)} unique CVEs)")


if __name__ == "__main__":
    main()
