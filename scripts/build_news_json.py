#!/usr/bin/env python3
\"\"\"
Build a consolidated JSON file with recent security news.

- Reads an OPML file containing RSS feeds (sec_feeds.xml)
- Walks the OPML tree respecting the actual group structure
- Assigns categories based on OPML group titles (Crypto, DFIR, Threat Intel, etc.)
- Fetches all feeds using feedparser
- Keeps only last N days (default: 30)
- Deduplicates by link
- Cleans HTML from summaries
- Enriches items with keyword-based "smart_groups"
- Writes data/news_recent.json

This script is meant to be run from the repo root (S33R).
\"\"\"

import os
import json
import html
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Iterable, List, Optional, Tuple

import feedparser

try:
    from bs4 import BeautifulSoup  # Optional, nicer HTML cleanup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

# -------------------------------
# Configuration
# -------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
OPML_PATH = BASE_DIR / "sec_feeds.xml"
OUTPUT_PATH = BASE_DIR / "data" / "news_recent.json"

DAYS_BACK = int(os.environ.get("DAYS_BACK", "30"))

# Map OPML group titles to internal type slugs
CATEGORY_SLUGS = {
    "Crypto & Blockchain Security": "crypto",
    "Cybercrime, Darknet & Leaks": "cybercrime",
    "DFIR & Forensics": "dfir",
    "General Security": "general",
    "Government & CERT": "government",
    "Leaks & Breaches": "leaks",
    "Malware": "malware",
    "Threat Intel": "threat_intel",
    "Malware Analysis": "malware_analysis",
    "OSINT & Communities": "osint",
    "Podcasts": "podcasts",
    "Vendors": "vendors",
    "Vulnerabilities & CVEs": "vulns",
    "Exploits": "exploits",
    "Vulnerability Advisories": "vuln_advisories",
}

# -------------------------------
# Keyword-based smart grouping
# -------------------------------
SMART_GROUP_RULES = [
    ("Ransomware", [
        "ransomware", "ransom note", "double extortion",
        "locker", "crypto-locker", "ransom demand"
    ]),
    ("Vulnerabilities / CVEs", [
        "cve-", "vulnerability", "vulnerabilities",
        "remote code execution", "rce",
        "privilege escalation", "buffer overflow",
        "out-of-bounds write", "sql injection"
    ]),
    ("Exploit / PoC", [
        "exploit", "poc released", "proof-of-concept",
        "exploit code", "weaponized", "exploit available"
    ]),
    ("Windows / Microsoft", [
        "windows", "exchange server", "office 365",
        "msrc", "sharepoint", "outlook"
    ]),
    ("Linux / Unix", [
        "linux", "ubuntu", "debian", "centos",
        "red hat", "rhel", "suse"
    ]),
    ("Cloud / SaaS", [
        "aws", "azure", "gcp", "google cloud",
        "cloudflare", "okta", "auth0", "saas",
        "s3 bucket"
    ]),
    ("Threat Actors / APT", [
        " apt ", " apt-", "apt group",
        "lazarus", "sandworm", "fin7", "apt29",
        "apt28", "charming kitten", "oilrig",
        "turla", "cozy bear", "fancy bear"
    ]),
    ("Malware / Payloads", [
        "malware", "trojan", "backdoor",
        "infostealer", "info-stealer", "stealer",
        " rat ", "remote access trojan", "botnet",
        "loader", "dropper"
    ]),
    ("Data Breaches / Leaks", [
        "data breach", "data leak", "leaked data",
        "database leaked", "records exposed",
        "credentials leaked", "credential dump"
    ]),
    ("Phishing / Social Engineering", [
        "phishing", "spear-phishing", "spear phishing",
        "social engineering", "credential harvesting",
        "smishing", "vishing"
    ]),
]


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text or "unknown"


def normalize_category(group_title: str):
    label = (group_title or "General").strip()
    slug = CATEGORY_SLUGS.get(label)
    if not slug:
        slug = slugify(label)
    return slug, label


def clean_html_summary(raw: str) -> str:
    if not raw:
        return ""
    raw = html.unescape(raw)

    if BeautifulSoup is not None:
        soup = BeautifulSoup(raw, "html.parser")
        text = soup.get_text(separator=" ", strip=True)
    else:
        text = re.sub(r"<[^>]+>", " ", raw)
        text = re.sub(r"\s+", " ", text).strip()

    return text


def parse_published(entry) -> Optional[datetime]:
    dt_struct = getattr(entry, "published_parsed", None) or getattr(
        entry, "updated_parsed", None
    )
    if not dt_struct:
        return None
    return datetime(*dt_struct[:6], tzinfo=timezone.utc)


def compute_smart_groups(title: str, summary: str) -> list[str]:
    text = f"{title or ''} {summary or ''}".lower()
    groups: list[str] = []

    for label, keywords in SMART_GROUP_RULES:
        for kw in keywords:
            if kw.lower() in text:
                groups.append(label)
                break

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for g in groups:
        if g not in seen:
            seen.add(g)
            deduped.append(g)
    return deduped


def iter_opml_feeds(opml_path: Path) -> Iterable[Tuple[str, str, str]]:
    tree = ET.parse(opml_path)
    root = tree.getroot()
    body = root.find("body")
    if body is None:
        return []

    for group in body.findall("outline"):
        group_title = group.attrib.get("title") or group.attrib.get("text") or "General"
        for feed in group.findall("outline"):
            xml_url = feed.attrib.get("xmlUrl")
            if not xml_url:
                continue
            feed_title = feed.attrib.get("title") or feed.attrib.get("text") or xml_url
            yield group_title, feed_title, xml_url


def main():
    if not OPML_PATH.exists():
        raise SystemExit(f"OPML file not found: {OPML_PATH}")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=DAYS_BACK)

    items_by_link: dict[str, dict] = {}

    print(f"[INFO] Using OPML: {OPML_PATH}")
    print(f"[INFO] Collecting items from the last {DAYS_BACK} days (>= {cutoff.isoformat()})")

    for group_title, feed_title, xml_url in iter_opml_feeds(OPML_PATH):
        type_slug, type_label = normalize_category(group_title)
        print(f"[INFO] Fetching feed: {feed_title} ({xml_url}) [{type_label}]")

        parsed = feedparser.parse(xml_url)

        for entry in parsed.entries:
            link = getattr(entry, "link", None)
            title = getattr(entry, "title", "").strip()
            summary_raw = getattr(entry, "summary", "") or getattr(entry, "description", "")

            if not link or not title:
                continue

            pub_dt = parse_published(entry)
            if not pub_dt:
                pub_iso = None
                pub_ts = None
            else:
                if pub_dt < cutoff:
                    continue
                pub_iso = pub_dt.isoformat()
                pub_ts = int(pub_dt.timestamp())

            summary = clean_html_summary(summary_raw)
            smart_groups = compute_smart_groups(title, summary)

            item = {
                "title": title,
                "summary": summary,
                "link": link,
                "source": feed_title,
                "type": type_slug,
                "type_label": type_label,
                "published": pub_iso,
                "published_ts": pub_ts,
                "smart_groups": smart_groups,
            }

            existing = items_by_link.get(link)
            if existing is None:
                items_by_link[link] = item
            else:
                if (item["published_ts"] or 0) > (existing.get("published_ts") or 0):
                    items_by_link[link] = item

    items_list = list(items_by_link.values())
    items_list.sort(
        key=lambda x: x["published_ts"] if x["published_ts"] is not None else 0,
        reverse=True,
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    out_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days_back": DAYS_BACK,
        "total_items": len(items_list),
        "items": items_list,
    }
    OUTPUT_PATH.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
    print(f"[INFO] Wrote {len(items_list)} items to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
