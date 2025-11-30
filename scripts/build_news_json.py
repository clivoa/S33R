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
- Writes data/news_recent.json

This script is meant to be run from the repo root (S33R).
"""

import os
import json
import html
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Iterable, List, Optional, Tuple

from email.utils import parsedate_to_datetime  # <-- NOVO

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
# Keyword-based smart grouping
# -------------------------------
SMART_GROUP_RULES: List[Tuple[str, List[str]]] = [

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

    # Well-known ransomware gangs (not always MITRE groups but widely referenced)
    "lockbit", "lockbit 3.0", "lockbit 2.0",
    "alphv", "blackcat", "alphv/blackcat",
    "clop", "cl0p", "clop ransomware",
    "conti", "conti leaks",
    "emotet", # precursor/access vector for ransomware ops
    "ryuk",
    "maze", "maze cartel",
    "egregor",
    "revictim",
    "play ransomware",
    "akira",
    "blackbyte",
    "ragnar locker",
    "darkside",
    "babuk",
    "hive",
    "royal ransomware",
    "nokoyawa",
    "cuba ransomware",
    "mount locker",
    "phobos ransomware",
    "vice society",
    "bianlian",
    "redkite",
    "snatch ransomware",

    # Ransomware affiliates & IABs linked to MITRE groups
    "fin7",           # sometimes tied in supply-chain / IAB
    "fin13",
    "lazarus",        # has used faux-ransomware in ops
    "apt41",          # double-extortion impersonation cases

    # Common indicators / operational language
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
        "msrc", "sharepoint", "outlook",
        "active directory", "adfs", "ntlm",
        "ms defender", "intune",
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
        "infostealer", "info-stealer", "stealer",
        " rat ", "remote access trojan", "botnet",
        "loader", "dropper", "rootkit", "worm",
        "keylogger", "banking trojan",
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
        "smishing", "vishing", "impersonation",
        "brand impersonation",
    ]),

    # === Vendor Security Intelligence (Novo!) ===
    ("Vendor Security Intelligence", [
        # EDR/AV vendors
        "crowdstrike", "falcon", "sentinelone", "sentinel one",
        "palo alto", "cortex xdr", "unit 42",
        "microsoft defender", "mdr microsoft", "ms defender",
        "symantec", "broadcom security",
        "trend micro",

        # Networking & FW vendors
        "cisco", "asa firewall", "talos",
        "fortinet", "fortigate", "fortios",
        "checkpoint", "juniper",

        # IR & Threat intel vendors
        "mandiant", "fireeye", "google cloud sec",
        "kaspersky", "securelist", "bitdefender",
        "eset", "secureworks", "sophos",

        # Cloud & CDN vendors
        "cloudflare", "akamai", "fastly",

        # Identity vendors
        "okta", "auth0", "duo security",

        # Email & anti-phish vendors
        "proofpoint", "mimecast",

        # Other relevant vendors
        "vmware", "broadcom", "1password", "lastpass",
    ]),

    # === Supply Chain Security / Dependency Attacks ===
    ("Supply Chain & Dependency Attacks", [
        "supply chain attack", "dependency hijack",
        "package compromise", "typosquatting",
        "npm package", "pypi", "malicious package",
        "software supply chain", "backdoored library",
    ]),

    # === Crypto / Blockchain Security ===
    ("Crypto / Blockchain Security", [
        "crypto scam", "blockchain hack", "defi exploit",
        "smart contract vulnerability", "rug pull",
        "crypto theft", "exchange hacked",
        "web3", "metamask", "ledger",
    ]),

    # === Darknet / Cybercrime Ops ===
    ("Cybercrime / Darknet", [
        "darknet", "dark web", "crime forum",
        "underground marketplace", "stealer logs",
        "initial access broker", "iab", "ransom gang leak site",
    ]),

    # === DFIR / Incident Response ===
    ("DFIR / Incident Response", [
        "dfir", "forensic", "incident response",
        "memory analysis", "disk image", "timeline analysis",
        "ioc", "tactics techniques", "mitre att&ck",
    ]),
]


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
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
    Tries feedparser's *_parsed fields first, then falls back to date strings.
    If no timezone is present, assumes UTC.
    """
    # 1) Tenta primeiro os campos estruturados do feedparser
    dt_struct = getattr(entry, "published_parsed", None) or getattr(
        entry, "updated_parsed", None
    )
    if dt_struct:
        return datetime(*dt_struct[:6], tzinfo=timezone.utc)

    # 2) Fallback para campos de data em string
    candidate_fields = [
        "published",
        "updated",
        "pubDate",
        "dc:date",
        "dc_date",
        "date",
    ]

    for field in candidate_fields:
        # feedparser entries se comportam como dict + atributos
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

        # Se não tiver timezone, assume UTC (como você pediu)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            # Normaliza para UTC por consistência
            dt = dt.astimezone(timezone.utc)

        return dt

    # Nada deu certo -> caller decide se ignora o item
    return None


def compute_smart_groups(title: str, summary: str) -> list[str]:
    text = f"{title or ''} {summary or ''}".lower()
    groups: list[str] = []

    for label, keywords in SMART_GROUP_RULES:
        for kw in keywords:
            if kw.lower() in text:
                groups.append(label)
                break

    # Dedup preservando ordem
    seen = set()
    deduped: list[str] = []
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


def main() -> None:
    if not OPML_PATH.exists():
        raise SystemExit(f"OPML file not found: {OPML_PATH}")

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=DAYS_BACK)

    items_by_link: dict[str, dict] = {}

    # -------------------------------
    # Incremental mode:
    #   - Carrega o JSON existente (se houver)
    #   - Reaproveita itens ainda dentro da janela DAYS_BACK
    #   - Evita duplicatas por link
    # -------------------------------
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
                # Se tiver timestamp, aplica o mesmo cutoff de DAYS_BACK
                if pub_ts is not None:
                    try:
                        existing_dt = datetime.fromtimestamp(pub_ts, tz=timezone.utc)
                        if existing_dt < cutoff:
                            # Muito antigo, deixa expirar naturalmente
                            continue
                    except Exception:
                        # Se der algum problema bizarro no timestamp, não derruba o script
                        pass

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

        # --- robust fetch: don't let one broken feed kill the whole job
        try:
            parsed = feedparser.parse(xml_url)
        except Exception as e:  # network / TLS errors, RemoteDisconnected, etc.
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

            pub_dt = parse_published(entry)
            if not pub_dt:
                pub_iso = None
                pub_ts = None
            else:
                # Respeita a janela de DAYS_BACK
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
                # Novo link
                items_by_link[link] = item
            else:
                # Mesmo link: fica com a versão mais recente
                if (item["published_ts"] or 0) > (existing.get("published_ts") or 0):
                    items_by_link[link] = item

    # Converte para lista e ordena por published_ts desc
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
