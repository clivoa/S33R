#!/usr/bin/env python3
"""
Build a consolidated JSON file with recent security news.

- Reads an OPML file containing RSS feeds (sec_feeds.xml)
- Walks the OPML tree respecting the actual group structure
- Assigns categories based on OPML group titles (Crypto, DFIR, Threat Intel, etc.)
- Fetches all feeds using feedparser
- Keeps only last N days (default: 30)
- Deduplicates by link
- Cleans HTML from summaries
- Enriches items with keyword-based "smart_groups"
- Filters out promotional/deal content (Black Friday, etc.) using conservative rules
- Writes data/news_recent.json
- Writes a report of filtered promotional items to:
    - data/archive/promo_filtered_YYYYMMDD_HHMMSS.json
    - data/archive/promo_filtered_latest.json
"""

import os
import json
import html
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Iterable, List, Optional, Tuple

from email.utils import parsedate_to_datetime

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
ARCHIVE_DIR = BASE_DIR / "data" / "archive"

DAYS_BACK = int(os.environ.get("DAYS_BACK", "30"))

# Map OPML group titles to internal type slugs
CATEGORY_SLUGS = {
    "Crypto & Blockchain Security": "crypto",
    "Cybercrime, Darknet & Leaks": "cybercrime",
    "DFIR & Forensics": "dfir",
    "General Security & Blogs": "general",
    "General Security": "general",
    "Government, CERT & Advisories": "government",
    "Government, CERT": "government",
    "Leaks & Breaches": "leaks",
    "Malware": "malware",
    "Threat Intel": "threat_intel",
    "Malware Analysis": "malware_analysis",
    "OSINT, Communities & Subreddits": "osint",
    "OSINT & Communities": "osint",
    "Podcasts & YouTube": "podcasts",
    "Podcasts": "podcasts",
    "Vendors & Product Blogs": "vendors",
    "Vendors": "vendors",
    "Vulnerabilities & CVEs": "vulns",
    "Exploits": "exploits",
    "Vulnerability Advisories": "vuln_advisories",
}

# -------------------------------
# Curated: keywords para notícias "selecionadas"
# -------------------------------
CURATED_KEYWORDS: List[str] = [
    # Exploits e vulns críticas
    "zero-day", "zeroday", "0day",
    "critical vulnerability", "exploit",
    "exploit", "cve-", "backdoor", "rce", 
    "remote code execution", "privilege escalation",
    "trojan", "wormable", "trojanized",

    # Supply chain / impacto grande
    "supply chain attack", "software supply chain",
    "supply-chain attack",

    # Vazamentos e mega incidentes
    "major breach", "data leak", "data leaks", "massive leak",

    # Ransom gangs (mais quentes)
    "ransom gang", "ransomware", "double extortion", "ransom note",

    # Vendor
]


# -------------------------------
# Keyword-based smart grouping
# -------------------------------
SMART_GROUP_RULES: List[Tuple[str, List[str]]] = [

    # === Curated (high-signal items) ===
    ("Curated", CURATED_KEYWORDS),
    
    # === Ransomware ===
    ("Ransomware", [
        # General terms
        "ransomware", "ransom note", "double extortion",
        "locker", "crypto-locker", "ransom demand", "ransom gang",
        "extortion", "data exfiltration extortion",

        # MITRE groups known for ransomware operations
        "wizard spider",         # Ryuk
        "royal",                 # Royal Ransomware (ex-Wizard Spider splinter)
        "fin12",                 # Known ransomware affiliate
        "muddled libra",         # Ransomware extortion/social engineering
        "scattered spider",      # Also involved in ransomware breaches
        "black basta",           # Known ransomware gang
        "hellokitty",            # HelloKitty/FiveHands

        # Well-known ransomware gangs
        "lockbit", "lockbit 3.0", "lockbit 2.0",
        "alphv", "blackcat", "alphv/blackcat",
        "clop", "cl0p", "clop ransomware",
        "conti", "conti leaks",
        "emotet",
        "ryuk",
        "maze", "maze cartel",
        "egregor",
        "revil", "sodinokibi",
        "darkside", "dark side",
        "blackmatter",
        "doppelpaymer",
        "vice society",
        "babuk",
        "netwalker",
        "hive ransomware", "hive",
        "royal ransomware",
        "play ransomware", "playcrypt",
        "phobos ransomware",
        "vice society",
        "bianlian",
        "redkite",
        "snatch ransomware",

        # Ransomware affiliates & IABs
        "fin7",
        "fin13",
        "lazarus",
        "apt41",

        # Operational language
        "leak site", "ransom negotiation", "ransom portal",
        "ransomware-as-a-service", "raas",
        "affiliate program", "affiliate ransomware",
    ]),

    # === Vulnerabilities / CVEs ===
    ("Vulnerabilities / CVEs", [
        "cve-", "vulnerability", "vulnerabilities",
        "remote code execution", "rce",
        "privilege escalation", "buffer overflow",
        "out-of-bounds write", "sql injection",
        "authentication bypass", "zero-day", "0day",
    ]),

    # === Exploit / PoC ===
    ("Exploit / PoC", [
        "exploit", "poc released", "proof-of-concept",
        "exploit code", "weaponized", "exploit available",
        "exploit toolkit", "exploit released",
    ]),

    # === Microsoft Ecosystem ===
    ("Windows / Microsoft", [
        "windows", "exchange server", "office 365",
        "azure ad", "active directory",
        "powershell", "ms defender", "intune",
    ]),

    # === Linux Ecosystem ===
    ("Linux / Unix", [
        "linux", "ubuntu", "debian", "centos",
        "red hat", "rhel", "suse", "unix",
        "systemd", "kernel module",
    ]),

    # === Cloud / SaaS ===
    ("Cloud / SaaS", [
        "aws", "azure", "gcp", "google cloud",
        "cloudflare", "okta", "auth0", "saas",
        "s3 bucket", "cloud misconfiguration",
        "iam role", "cloudtrail", "kubernetes", "k8s",
    ]),

    # === Threat Actors / APT ===
    ("Threat Actors / APT", [
        " apt ", " apt-", "apt group",
        "lazarus", "sandworm", "fin7", "apt29",
        "apt28", "charming kitten", "oilrig",
        "turla", "cozy bear", "fancy bear",
        "wizard spider", "black basta", "lockbit",
        "muddled libra",
    ]),

    # === Malware / Payloads ===
    ("Malware / Payloads", [
        "malware", "trojan", "backdoor",
        "rootkit", "botnet", "loader",
        "infostealer", "info-stealer", "keylogger",
        "rat (remote access trojan)", "remote access trojan",
        "wiper", "locker", "locker malware",
    ]),

    # === Web App / API Security ===
    ("Web / API Security", [
        "xss", "cross-site scripting",
        "csrf", "cross-site request forgery",
        "sql injection", "sqli",
        "lfi", "rfi", "directory traversal",
        "api security", "graphql", "web application firewall",
    ]),

    # === Identity / Access ===
    ("Identity / Access", [
        "mfa", "2fa", "passwordless",
        "sso", "single sign-on",
        "oauth", "saml", "openid connect",
        "identity provider", "idp",
    ]),

    # === Network / OT / ICS ===
    ("Network / OT / ICS", [
        "ics", "scada", "plc",
        "industrial control systems",
        "critical infrastructure",
        "ot security", "operational technology",
    ]),

    # === Data Breaches / Leaks ===
    ("Data Breaches / Leaks", [
        "data breach", "data leak", "leaked data",
        "database leaked", "records exposed",
        "credentials leaked", "credential dump",
        "publicly exposed", "open database",
    ]),

    # === Phishing / Social Engineering ===
    ("Phishing / Social Engineering", [
        "phishing", "spear-phishing", "spear phishing",
        "social engineering", "credential harvesting",
        "smishing", "vishing",
        "business email compromise", "bec attack",
    ]),

    # === Crypto / Web3 ===
    ("Crypto / Web3", [
        "crypto exchange", "cryptocurrency",
        "defi", "dex", "web3",
        "smart contract", "solidity",
        "rug pull", "bridge exploit",
    ]),

    # === Supply-chain / Software ===
    ("Supply Chain / Software", [
        "software supply chain",
        "ci/cd pipeline",
        "dependency confusion",
        "typosquatting package",
        "malicious npm package", "malicious pypi package",
        "malicious nuget package",
    ]),
]

# -------------------------------
# Promotional / commercial content filtering (ultra-conservador)
# -------------------------------

# Padrões fortes: praticamente só aparecem em conteúdo de ofertas/vendas
STRONG_PROMO_PATTERNS: List[str] = [
    "black friday",
    "cyber monday",
    "prime day",
    "doorbuster",
    "flash sale",
    "mega sale",
    "hot sale",
    "limited-time offer",
    "limited time offer",
    "time-limited offer",
    "price drop",
    "price drops",
    "on sale",
    "lowest price",
    "lowest-ever price",
    "cheapest price",
    "save up to",
    "save $",
    "save €",
    "% off",
    "discount code",
    "discounts on",
    "coupon code",
    "voucher code",
    "deal of the day",
    "deal alert",
    " tv deals",
    " laptop deals",
    " monitor deals",
    " ipad deals",
    " iphone deals",
    " macbook deals",
    " gaming pc deals",
    " gaming laptop deals",
    "live-tracking the best",
    "live tracking the best",
    "i'm live-tracking",
    "im live-tracking",
    "GISEC GLOBAL 2026"
]

def is_promotional_entry(title: str, summary_raw: str) -> bool:
    """
    Versão ultra-conservadora:
    - SOMENTE filtra se bater em STRONG_PROMO_PATTERNS
      no título+summary.
    - Não usa tags, categorias, weak patterns ou heurísticas
      por feed.
    """
    text = f"{title or ''} {summary_raw or ''}".lower()
    return any(pat in text for pat in STRONG_PROMO_PATTERNS)

# -------------------------------
# Helpers
# -------------------------------
def slugify(label: str) -> str:
    text = label.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    return text or "unknown"


def normalize_category(group_title: str) -> Tuple[str, str]:
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
    """Return a timezone-aware datetime for a feed entry.

    - Tries feedparser's *_parsed fields first
    - Falls back to common date fields using parsedate_to_datetime
    - If no timezone is present, assumes UTC
    """
    dt_struct = getattr(entry, "published_parsed", None) or getattr(
        entry, "updated_parsed", None
    )

    if dt_struct is not None:
        try:
            dt = datetime(*dt_struct[:6])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    candidate_fields = [
        "published",
        "updated",
        "pubDate",
        "dc:date",
        "dc_date",
        "date",
    ]

    for field in candidate_fields:
        value = getattr(entry, field, None)
        if not value and isinstance(entry, dict):
            value = entry.get(field)
        if not value:
            continue

        try:
            dt = parsedate_to_datetime(str(value))
        except (TypeError, ValueError):
            continue

        if dt is None:
            continue

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt

    return None


def compute_smart_groups(title: str, summary: str) -> List[str]:
    text = f"{title or ''} {summary or ''}".lower()
    groups: List[str] = []

    for label, keywords in SMART_GROUP_RULES:
        for kw in keywords:
            if kw.lower() in text:
                groups.append(label)
                break

    seen = set()
    deduped: List[str] = []
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

# -------------------------------
# Main
# -------------------------------
def main() -> None:
    if not OPML_PATH.exists():
        raise SystemExit(f"OPML file not found: {OPML_PATH}")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=DAYS_BACK)

    items_by_link: dict[str, dict] = {}

    # Estatísticas de promo por feed
    promo_stats: dict[str, dict] = {}

    # Incremental mode: reaproveita itens existentes
    if OUTPUT_PATH.exists():
        try:
            existing_data = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
            existing_items = existing_data.get("items", [])
            kept_existing = 0

            for item in existing_items:
                link = item.get("link")
                if not link:
                    continue

                pub_ts = item.get("published_ts")
                if pub_ts is not None:
                    try:
                        existing_dt = datetime.fromtimestamp(pub_ts, tz=timezone.utc)
                        if existing_dt < cutoff:
                            continue
                    except Exception:
                        pass

                # Garante que itens antigos também tenham o campo "curated"
                if "curated" not in item:
                    title = (item.get("title") or "")
                    summary = (item.get("summary") or "")
                    text = f"{title} {summary}".lower()
                    item["curated"] = any(
                        kw.lower() in text for kw in CURATED_KEYWORDS
                    )

                items_by_link[link] = item
                kept_existing += 1

            if kept_existing:
                print(f"[INFO] Pre-loaded {kept_existing} existing items from {OUTPUT_PATH}")
        except Exception as e:
            print(f"[WARN] Could not load existing JSON from {OUTPUT_PATH}: {e!r}")

    print(f"[INFO] Using OPML: {OPML_PATH}")
    print(f"[INFO] Collecting items from the last {DAYS_BACK} days (>= {cutoff.isoformat()})")

    for group_title, feed_title, xml_url in iter_opml_feeds(OPML_PATH):
        type_slug, type_label = normalize_category(group_title)
        print(f"[INFO] Fetching feed: {feed_title} ({xml_url}) [{type_label}]")

        feed_key = xml_url or feed_title
        if feed_key not in promo_stats:
            promo_stats[feed_key] = {
                "feed_title": feed_title,
                "xml_url": xml_url,
                "type_label": type_label,
                "promo_count": 0,
                "examples": [],
            }

        feed_stat = promo_stats[feed_key]

        try:
            parsed = feedparser.parse(xml_url)
        except Exception as e:
            print(f"[WARN] Failed to fetch feed {feed_title} ({xml_url}): {e!r}")
            continue

        if getattr(parsed, "bozo", False) and getattr(parsed, "bozo_exception", None):
            print(
                f"[WARN] Bozo parsing feed {feed_title} ({xml_url}): "
                f"{parsed.bozo_exception!r}"
            )

        for entry in parsed.entries:
            link = getattr(entry, "link", None)
            title = getattr(entry, "title", "").strip()
            summary_raw = getattr(entry, "summary", "") or getattr(entry, "description", "")

            if not link or not title:
                continue

            # Filtro PROMO super conservador
            if is_promotional_entry(title, summary_raw):
                feed_stat["promo_count"] += 1
                if len(feed_stat["examples"]) < 10:
                    feed_stat["examples"].append(title)
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

            # Item é "Curated" se o smart_group já tiver Curated
            is_curated = "Curated" in smart_groups

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
                "curated": is_curated,
            }

            existing = items_by_link.get(link)
            if existing is None:
                items_by_link[link] = item
            else:
                if (item["published_ts"] or 0) > (existing.get("published_ts") or 0):
                    items_by_link[link] = item

    # Converte para lista e ordena por data
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

    # -------------------------------
    # Relatório de itens promocionais filtrados
    # -------------------------------
    total_promo = sum(s["promo_count"] for s in promo_stats.values())
    print(f"[INFO] Total promotional items filtered: {total_promo}")

    for feed_key, s in promo_stats.items():
        if s["promo_count"] > 0:
            print(
                f"[INFO]   {s['feed_title']} ({s['xml_url']}): "
                f"{s['promo_count']} promotional items filtered"
            )

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    report_path = ARCHIVE_DIR / f"promo_filtered_{now.strftime('%Y%m%d_%H%M%S')}.json"
    report_latest = ARCHIVE_DIR / "promo_filtered_latest.json"

    report = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "days_back": DAYS_BACK,
    "total_promo_filtered": total_promo,
    "feeds": [],
    }   

    for s in promo_stats.values():
        # Só inclui feeds que realmente tiveram itens filtrados
        if s["promo_count"] > 0:
            report["feeds"].append(
                {
                    "feed_title": s["feed_title"],
                    "xml_url": s["xml_url"],
                    "type_label": s["type_label"],
                    "promo_count": s["promo_count"],
                    "examples": s["examples"],
                }
            )


    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_latest.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"[INFO] Wrote promo filter report to {report_path}")
    print(f"[INFO] Updated latest promo report alias at {report_latest}")


if __name__ == "__main__":
    main()
