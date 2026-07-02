#!/usr/bin/env python3
"""
Build a consolidated JSON file with recent security news.

- Reads an OPML file containing RSS feeds (sec_feeds.xml)
- Walks the OPML tree respecting the actual group structure
- Assigns categories based on OPML group titles
- Fetches all feeds using feedparser
- Keeps only last N days (default: 30)
- Deduplicates by link
- Cleans HTML from summaries
- Enriches items with smart groups and per-group confidence
- Computes source quality scores (freshness, useful volume, duplication, noise)
- Computes priority_score per item for ranking use-cases
- Computes operational signal tiers for high-signal filtering
- Writes data/news_recent.json
- Writes a report of filtered promotional items to data/archive/
"""

import html
import json
import math
import os
import re
import socket
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import feedparser

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None


# -------------------------------
# Configuration
# -------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
OPML_PATH = BASE_DIR / "sec_feeds.xml"
OUTPUT_PATH = BASE_DIR / "data" / "news_recent.json"
ARCHIVE_DIR = BASE_DIR / "data" / "archive"
SOURCE_CATALOG_PATH = BASE_DIR / "data" / "source_catalog.json"
SMART_GROUP_DICT_PATH = Path(
    os.environ.get("SMART_GROUP_DICT_PATH", str(BASE_DIR / "scripts" / "smart_group_dictionary.json"))
)

DAYS_BACK = int(os.environ.get("DAYS_BACK", "30"))
HIGH_CONFIDENCE_THRESHOLD = float(os.environ.get("SMART_GROUP_HIGH_CONF_THRESHOLD", "0.75"))
FEED_TIMEOUT_SECONDS = int(os.environ.get("FEED_TIMEOUT_SECONDS", "20"))
NEWS_RECENT_MAX_BYTES = int(os.environ.get("NEWS_RECENT_MAX_BYTES", "95000000"))
NEWS_RECENT_MIN_ITEMS = int(os.environ.get("NEWS_RECENT_MIN_ITEMS", "1000"))


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


SMART_GROUP_RULES: List[Tuple[str, List[str]]] = [
    (
        "Ransomware",
        [
            "ransomware",
            "ransom note",
            "double extortion",
            "ransom demand",
            "ransom gang",
            "raas",
            "affiliate ransomware",
            "lockbit",
            "alphv",
            "blackcat",
            "clop",
            "conti",
            "ryuk",
            "revil",
            "darkside",
            "hive",
            "play ransomware",
            "bianlian",
            "scattered spider",
            "wizard spider",
        ],
    ),
    (
        "Vulnerabilities / CVEs",
        [
            "cve-",
            "vulnerability",
            "vulnerabilities",
            "remote code execution",
            "rce",
            "privilege escalation",
            "buffer overflow",
            "authentication bypass",
            "zero-day",
            "0day",
        ],
    ),
    (
        "Exploit / PoC",
        [
            "exploit",
            "proof-of-concept",
            "poc released",
            "exploit code",
            "weaponized",
            "exploit toolkit",
        ],
    ),
    (
        "Windows / Microsoft",
        [
            "windows",
            "exchange server",
            "office 365",
            "azure ad",
            "active directory",
            "powershell",
            "ms defender",
            "intune",
            "entra id",
        ],
    ),
    (
        "Linux / Unix",
        [
            "linux",
            "ubuntu",
            "debian",
            "centos",
            "red hat",
            "rhel",
            "suse",
            "unix",
            "kernel",
            "systemd",
        ],
    ),
    (
        "Cloud / SaaS",
        [
            "aws",
            "azure",
            "gcp",
            "google cloud",
            "cloudflare",
            "okta",
            "auth0",
            "saas",
            "kubernetes",
            "k8s",
            "s3 bucket",
            "cloud misconfiguration",
        ],
    ),
    (
        "Threat Actors / APT",
        [
            "apt ",
            "apt-",
            "apt group",
            "lazarus",
            "sandworm",
            "apt29",
            "apt28",
            "turla",
            "cozy bear",
            "fancy bear",
            "threat actor",
            "state-sponsored",
        ],
    ),
    (
        "Malware / Payloads",
        [
            "malware",
            "trojan",
            "backdoor",
            "rootkit",
            "botnet",
            "loader",
            "infostealer",
            "keylogger",
            "remote access trojan",
            "wiper",
            "dropper",
            "stealer",
        ],
    ),
    (
        "Web / API Security",
        [
            "xss",
            "cross-site scripting",
            "csrf",
            "sql injection",
            "sqli",
            "lfi",
            "rfi",
            "directory traversal",
            "api security",
            "graphql",
            "ssrf",
        ],
    ),
    (
        "Identity / Access",
        [
            "mfa",
            "2fa",
            "passwordless",
            "sso",
            "single sign-on",
            "oauth",
            "saml",
            "openid connect",
            "identity provider",
            "idp",
        ],
    ),
    (
        "Network / OT / ICS",
        [
            "ics",
            "scada",
            "plc",
            "industrial control systems",
            "critical infrastructure",
            "ot security",
            "operational technology",
        ],
    ),
    (
        "Data Breaches / Leaks",
        [
            "data breach",
            "data leak",
            "leaked data",
            "database leaked",
            "records exposed",
            "credentials leaked",
            "credential dump",
            "open database",
        ],
    ),
    (
        "Phishing / Social Engineering",
        [
            "phishing",
            "spear-phishing",
            "spear phishing",
            "social engineering",
            "credential harvesting",
            "smishing",
            "vishing",
            "business email compromise",
            "bec attack",
        ],
    ),
    (
        "Crypto / Web3",
        [
            "crypto exchange",
            "cryptocurrency",
            "defi",
            "dex",
            "web3",
            "smart contract",
            "solidity",
            "rug pull",
            "bridge exploit",
        ],
    ),
    (
        "Supply Chain / Software",
        [
            "software supply chain",
            "ci/cd pipeline",
            "dependency confusion",
            "typosquatting package",
            "malicious npm package",
            "malicious pypi package",
            "malicious nuget package",
            "supply-chain",
        ],
    ),
]


SMART_GROUP_REGEX_RULES: List[Tuple[str, str, float]] = [
    ("Vulnerabilities / CVEs", r"\\bCVE-\\d{4}-\\d{4,7}\\b", 0.9),
    ("Threat Actors / APT", r"\\b(?:APT ?\\d+|TA\\d+|UNC\\d+|Storm-\\d+)\\b", 0.82),
    ("Ransomware", r"\\b(?:lockbit|alphv|blackcat|clop|conti|revil|play|bianlian)\\b", 0.84),
    ("Phishing / Social Engineering", r"\\b(?:bec|business email compromise|spear[- ]?phishing|credential harvesting)\\b", 0.82),
    ("Supply Chain / Software", r"\\b(?:dependency confusion|typosquatting|sbom|malicious package)\\b", 0.8),
    ("Identity / Access", r"\\b(?:mfa fatigue|session hijack(?:ing)?|saml|oauth|openid connect)\\b", 0.8),
]


OPERATIONAL_SIGNAL_VERSION = "operational-signal-v1"
OPERATIONAL_HIGH_TIERS = {"critical", "high"}
GENERIC_HIGH_CONF_GROUPS = {"Vulnerabilities / CVEs", "General Security"}
CURATION_POLICY_VERSION = "curated-auto-v2"
CURATED_MIN_SIGNAL_SCORE = float(os.environ.get("CURATED_MIN_SIGNAL_SCORE", "65"))
CURATED_MAX_AGE_HOURS = float(os.environ.get("CURATED_MAX_AGE_HOURS", str(24 * 7)))
CURATED_BULK_SOURCE_MIN_SIGNAL_SCORE = float(os.environ.get("CURATED_BULK_SOURCE_MIN_SIGNAL_SCORE", "85"))
ACTIONABLE_GROUPS = {
    "Exploit / PoC",
    "Ransomware",
    "Threat Actors / APT",
    "Malware / Payloads",
    "Data Breaches / Leaks",
    "Supply Chain / Software",
    "Identity / Access",
    "Cloud / SaaS",
    "Network / OT / ICS",
    "Web / API Security",
}

ACTIVE_EXPLOIT_RE = re.compile(
    r"\b(active(?:ly)? exploited|active exploitation|exploited in the wild|known exploited|cisa kev|kev catalog|under attack|weaponized)\b",
    re.IGNORECASE,
)
ZERO_DAY_RE = re.compile(r"\b(zero[- ]day|0[- ]day|0day|zeroday)\b", re.IGNORECASE)
CRITICAL_IMPACT_RE = re.compile(
    r"\b(critical vulnerability|critical flaw|critical bug|remote code execution|rce|pre-auth|preauth|unauthenticated|authentication bypass|privilege escalation|wormable|cvss\s*(?:9|10)|patch now|emergency patch)\b",
    re.IGNORECASE,
)
EXPLOIT_POC_RE = re.compile(
    r"\b(poc|proof[- ]of[- ]concept|exploit code|exploit released|public exploit|exploit available|weaponized exploit)\b",
    re.IGNORECASE,
)
RANSOMWARE_RE = re.compile(r"\b(ransomware|ransom gang|double extortion|ransom note|raas)\b", re.IGNORECASE)
BREACH_RE = re.compile(
    r"\b(data breach|data leak|leaked data|stolen data|records exposed|credential dump|customer data|compromised data)\b",
    re.IGNORECASE,
)
SUPPLY_CHAIN_RE = re.compile(
    r"\b(supply[- ]chain|malicious package|typosquat(?:ting)?|dependency confusion|trojanized package|compromised package|npm package|pypi package)\b",
    re.IGNORECASE,
)
MALWARE_RE = re.compile(
    r"\b(malware|backdoor|infostealer|stealer|loader|wiper|trojan|botnet|rootkit|remote access trojan)\b",
    re.IGNORECASE,
)
THREAT_ACTOR_RE = re.compile(
    r"\b(apt ?\d+|apt-\d+|ta\d+|unc\d+|storm-\d+|threat actor|state-sponsored|nation-state|campaign)\b",
    re.IGNORECASE,
)

BULK_VULN_SOURCE_RE = re.compile(
    r"\b(vuldb|vulners|msrc security update guide|cve \| threatint|ubuntu security notices|linuxsecurity advisories|debian security|security advisories?)\b",
    re.IGNORECASE,
)

CURATION_NOISE_RE = re.compile(
    r"\b(black hat|conference|summit|webinar|workshop|training|course|certification|podcast|episode|newsletter|roundup|recap|interview|award|call for papers|cfp|register|save your seat)\b",
    re.IGNORECASE,
)


TYPE_FALLBACK_GROUPS: Dict[str, Tuple[str, float]] = {
    "crypto": ("Crypto / Web3", 0.42),
    "cybercrime": ("Data Breaches / Leaks", 0.42),
    "dfir": ("Detection Engineering", 0.4),
    "general": ("General Security", 0.35),
    "government": ("Government / CERT", 0.48),
    "leaks": ("Data Breaches / Leaks", 0.44),
    "malware": ("Malware / Payloads", 0.46),
    "threat_intel": ("Threat Actors / APT", 0.44),
    "malware_analysis": ("Malware / Payloads", 0.43),
    "osint": ("OSINT / Community", 0.34),
    "podcasts": ("Community / Briefing", 0.32),
    "vendors": ("Vendors / Product Security", 0.44),
    "vulns": ("Vulnerabilities / CVEs", 0.5),
    "exploits": ("Exploit / PoC", 0.5),
    "vuln_advisories": ("Vulnerability Advisory", 0.5),
}


STRONG_PROMO_PATTERNS: List[str] = [
    # Event listings / contests from news sources (e.g. DarkReading)
    "[virtual event]",
    "name that toon",
    "register & save",
    "register now",
    # General promo
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
    "save EUR",
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
]


COMPILED_SMART_GROUP_REGEX_RULES: List[Tuple[str, re.Pattern[str], float]] = [
    (label, re.compile(pattern, re.IGNORECASE), conf)
    for label, pattern, conf in SMART_GROUP_REGEX_RULES
]


# -------------------------------
# Helpers
# -------------------------------
def clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def round_conf(value: float) -> float:
    return round(clamp01(value), 3)


def combine_confidence(existing: float, new_value: float) -> float:
    existing = clamp01(existing)
    new_value = clamp01(new_value)
    return clamp01(1.0 - (1.0 - existing) * (1.0 - new_value))


def keyword_confidence(keyword: str) -> float:
    kw = (keyword or "").strip().lower()
    if not kw:
        return 0.55

    if "cve-" in kw or "zero-day" in kw or "0day" in kw:
        return 0.88
    if "apt" in kw or "storm-" in kw or "unc" in kw:
        return 0.84

    words = [w for w in kw.split() if w]
    if len(words) >= 4:
        return 0.78
    if len(words) == 3:
        return 0.72
    if len(words) == 2:
        return 0.66
    return 0.6


def is_promotional_entry(title: str, summary_raw: str) -> bool:
    text = f"{title or ''} {summary_raw or ''}".lower()
    return any(pat in text for pat in STRONG_PROMO_PATTERNS)


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


def parse_published(entry: Any) -> Optional[datetime]:
    dt_struct = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)

    if dt_struct is not None:
        try:
            dt = datetime(*dt_struct[:6])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass

    candidate_fields = ["published", "updated", "pubDate", "dc:date", "dc_date", "date"]

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


def normalize_title_fingerprint(title: str) -> str:
    if not title:
        return ""
    t = title.lower()
    t = re.sub(r"https?://\\S+", " ", t)
    t = re.sub(r"\\bCVE-\\d{4}-\\d{4,7}\\b", "cve", t, flags=re.IGNORECASE)
    t = re.sub(r"[^a-z0-9 ]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


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


def load_source_catalog(path: Path) -> Dict[str, Any]:
    empty: Dict[str, Any] = {"path": str(path), "metadata": None, "by_url": {}}
    if not path.exists():
        return empty

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Could not load source catalog {path}: {exc!r}")
        return empty

    feeds = raw.get("feeds", [])
    if not isinstance(feeds, list):
        print(f"[WARN] Invalid source catalog format (feeds must be a list): {path}")
        return empty

    by_url: Dict[str, Dict[str, Any]] = {}
    for feed in feeds:
        if not isinstance(feed, dict):
            continue
        url = str(feed.get("xml_url") or feed.get("url") or "").strip()
        if not url:
            continue
        by_url[url] = feed

    metadata = {
        "path": str(path),
        "generated_at": raw.get("generated_at"),
        "total_feeds": raw.get("total_feeds"),
        "active_feeds": raw.get("active_feeds"),
        "active_opml_feeds": raw.get("active_opml_feeds"),
        "upstream": raw.get("upstream"),
        "source": raw.get("source"),
    }
    print(f"[INFO] Loaded source catalog {path} ({len(by_url)} feeds)")
    return {"path": str(path), "metadata": metadata, "by_url": by_url}


def load_external_smart_group_rules(path: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "path": str(path),
        "version": None,
        "keywords": [],  # list[tuple[group, keyword, confidence]]
        "regex": [],  # list[tuple[group, compiled_regex, confidence]]
    }

    if not path.exists():
        print(f"[WARN] External smart group dictionary not found: {path}")
        return out

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Could not load external smart group dictionary {path}: {exc!r}")
        return out

    if not isinstance(raw, dict):
        print(f"[WARN] Invalid external smart group dictionary format (expected object): {path}")
        return out

    out["version"] = raw.get("version")
    groups = raw.get("groups")
    if not isinstance(groups, dict):
        return out

    for group_name, block in groups.items():
        if not isinstance(group_name, str) or not group_name.strip():
            continue
        group_label = group_name.strip()
        if group_label.lower() == "curated":
            print("[WARN] Ignoring reserved external smart group 'Curated'; curation is computed from signal policy")
            continue
        if not isinstance(block, dict):
            continue

        for kw_entry in block.get("keywords", []):
            term = None
            conf = None
            if isinstance(kw_entry, str):
                term = kw_entry
                conf = keyword_confidence(term)
            elif isinstance(kw_entry, dict):
                term = str(kw_entry.get("term", "")).strip()
                if not term:
                    continue
                try:
                    conf = float(kw_entry.get("confidence", keyword_confidence(term)))
                except (TypeError, ValueError):
                    conf = keyword_confidence(term)

            if not term:
                continue

            out["keywords"].append((group_label, term.lower(), clamp01(conf)))

        for regex_entry in block.get("regex", []):
            pattern = None
            conf = None
            if isinstance(regex_entry, str):
                pattern = regex_entry
                conf = 0.72
            elif isinstance(regex_entry, dict):
                pattern = str(regex_entry.get("pattern", "")).strip()
                if not pattern:
                    continue
                try:
                    conf = float(regex_entry.get("confidence", 0.72))
                except (TypeError, ValueError):
                    conf = 0.72

            if not pattern:
                continue

            try:
                compiled = re.compile(pattern, re.IGNORECASE)
            except re.error as exc:
                print(f"[WARN] Invalid external regex '{pattern}' for group '{group_label}': {exc}")
                continue

            out["regex"].append((group_label, compiled, clamp01(conf)))

    print(
        "[INFO] Loaded external smart group dictionary "
        f"{path} (version={out['version']!r}, keywords={len(out['keywords'])}, regex={len(out['regex'])})"
    )
    return out


def classify_smart_groups(
    title: str,
    summary: str,
    type_slug: Optional[str],
    external_rules: Dict[str, Any],
) -> Dict[str, Any]:
    text = f"{title or ''} {summary or ''}".lower()
    scores: Dict[str, float] = {}

    for label, keywords in SMART_GROUP_RULES:
        for kw in keywords:
            if kw.lower() in text:
                scores[label] = combine_confidence(scores.get(label, 0.0), keyword_confidence(kw))

    for label, regex_obj, conf in COMPILED_SMART_GROUP_REGEX_RULES:
        if regex_obj.search(text):
            scores[label] = combine_confidence(scores.get(label, 0.0), conf)

    for label, kw, conf in external_rules.get("keywords", []):
        if kw in text:
            scores[label] = combine_confidence(scores.get(label, 0.0), conf)

    for label, regex_obj, conf in external_rules.get("regex", []):
        if regex_obj.search(text):
            scores[label] = combine_confidence(scores.get(label, 0.0), conf)

    fallback = TYPE_FALLBACK_GROUPS.get(type_slug or "")
    if fallback:
        fallback_label, fallback_conf = fallback
        if fallback_label not in scores:
            scores[fallback_label] = combine_confidence(scores.get(fallback_label, 0.0), fallback_conf)

    sorted_groups = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    groups = [group for group, _ in sorted_groups]
    conf_map = {group: round_conf(score) for group, score in sorted_groups}
    high_conf = [group for group, score in sorted_groups if score >= HIGH_CONFIDENCE_THRESHOLD]
    max_conf = max(scores.values()) if scores else 0.0

    return {
        "smart_groups": groups,
        "smart_group_confidence": conf_map,
        "smart_groups_high_confidence": high_conf,
        "smart_group_max_confidence": round_conf(max_conf),
    }


def build_source_quality(items: List[Dict[str, Any]], now: datetime) -> Tuple[Dict[str, float], List[Dict[str, Any]]]:
    title_counts: Dict[str, int] = defaultdict(int)
    title_sources: Dict[str, Set[str]] = defaultdict(set)

    for item in items:
        title_fp = normalize_title_fingerprint(str(item.get("title") or ""))
        if not title_fp:
            continue
        src = str(item.get("source") or "Unknown")
        title_counts[title_fp] += 1
        title_sources[title_fp].add(src)

    now_ts = now.timestamp()
    stats: Dict[str, Dict[str, float]] = defaultdict(
        lambda: {
            "total": 0.0,
            "fresh_48h": 0.0,
            "fresh_7d": 0.0,
            "duplicates": 0.0,
            "noise": 0.0,
            "unclassified": 0.0,
            "high_conf": 0.0,
            "curated": 0.0,
        }
    )

    for item in items:
        src = str(item.get("source") or "Unknown")
        st = stats[src]
        st["total"] += 1.0

        ts = item.get("published_ts")
        if isinstance(ts, (int, float)):
            age_hours = max(0.0, (now_ts - float(ts)) / 3600.0)
            if age_hours <= 48.0:
                st["fresh_48h"] += 1.0
            if age_hours <= 24.0 * 7:
                st["fresh_7d"] += 1.0

        title_fp = normalize_title_fingerprint(str(item.get("title") or ""))
        if title_fp and title_counts.get(title_fp, 0) > 1 and len(title_sources.get(title_fp, set())) > 1:
            st["duplicates"] += 1.0

        summary = str(item.get("summary") or "").strip()
        if len(summary) < 80:
            st["noise"] += 1.0

        smart_groups = item.get("smart_groups") or []
        if not smart_groups:
            st["unclassified"] += 1.0

        if item.get("smart_groups_high_confidence"):
            st["high_conf"] += 1.0

        if bool(item.get("curated")):
            st["curated"] += 1.0

    score_map: Dict[str, float] = {}
    report: List[Dict[str, Any]] = []

    for source, st in stats.items():
        total = max(1.0, st["total"])

        fresh_48_ratio = st["fresh_48h"] / total
        fresh_7_ratio = st["fresh_7d"] / total
        dup_ratio = st["duplicates"] / total
        noise_ratio = st["noise"] / total
        high_conf_ratio = st["high_conf"] / total

        useful_volume = max(0.0, total - st["duplicates"] - (0.6 * st["noise"]) - (0.4 * st["unclassified"]))

        freshness_score = 100.0 * (0.65 * fresh_48_ratio + 0.35 * fresh_7_ratio)
        volume_score = min(100.0, 22.0 * math.log2(useful_volume + 1.0))
        dedup_score = max(0.0, 100.0 * (1.0 - dup_ratio))
        noise_score = max(0.0, 100.0 * (1.0 - noise_ratio))
        classification_score = 100.0 * high_conf_ratio

        quality_score = (
            0.32 * freshness_score
            + 0.24 * volume_score
            + 0.20 * dedup_score
            + 0.14 * noise_score
            + 0.10 * classification_score
        )
        quality_score = round(max(0.0, min(100.0, quality_score)), 2)

        score_map[source] = quality_score
        report.append(
            {
                "source": source,
                "score": quality_score,
                "components": {
                    "freshness": round(freshness_score, 2),
                    "useful_volume": round(volume_score, 2),
                    "dedup": round(dedup_score, 2),
                    "noise": round(noise_score, 2),
                    "classification": round(classification_score, 2),
                },
                "metrics": {
                    "total_items": int(st["total"]),
                    "fresh_items_48h": int(st["fresh_48h"]),
                    "fresh_items_7d": int(st["fresh_7d"]),
                    "duplicates": int(st["duplicates"]),
                    "noise_items": int(st["noise"]),
                    "unclassified_items": int(st["unclassified"]),
                    "high_conf_items": int(st["high_conf"]),
                    "curated_items": int(st["curated"]),
                    "useful_volume_estimate": int(useful_volume),
                },
            }
        )

    report.sort(key=lambda x: (x["score"], x["metrics"]["total_items"]), reverse=True)
    for idx, row in enumerate(report, start=1):
        row["rank"] = idx

    return score_map, report


def compute_priority_score(item: Dict[str, Any], source_quality_score: float, now: datetime) -> float:
    recency = 0.0
    ts = item.get("published_ts")
    if isinstance(ts, (int, float)):
        age_hours = max(0.0, (now.timestamp() - float(ts)) / 3600.0)
        recency = max(0.0, 1.0 - min(1.0, age_hours / (24.0 * 7.0)))

    quality_norm = max(0.0, min(1.0, source_quality_score / 100.0))
    classification_conf = max(0.0, min(1.0, float(item.get("smart_group_max_confidence") or 0.0)))
    curated_boost = 1.0 if item.get("curated") else 0.0

    priority = 100.0 * (
        0.45 * recency
        + 0.30 * quality_norm
        + 0.15 * classification_conf
        + 0.10 * curated_boost
    )
    return round(max(0.0, min(100.0, priority)), 2)


def _signal_add(reasons: List[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def compute_operational_signal(item: Dict[str, Any], source_quality_score: float, now: datetime) -> Dict[str, Any]:
    title = str(item.get("title") or "")
    summary = str(item.get("summary") or "")
    text = f"{title} {summary[:600]}"
    high_conf_groups = set(item.get("smart_groups_high_confidence") or [])
    source = str(item.get("source") or "")
    cve_count = len(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE))
    is_bulk_vuln_source = bool(BULK_VULN_SOURCE_RE.search(source))

    score = 0.0
    reasons: List[str] = []

    if ACTIVE_EXPLOIT_RE.search(text):
        score += 40.0
        _signal_add(reasons, "active exploitation / KEV signal")
    if ZERO_DAY_RE.search(text):
        score += 34.0
        _signal_add(reasons, "zero-day signal")
    if CRITICAL_IMPACT_RE.search(text):
        score += 24.0
        _signal_add(reasons, "critical impact language")
    if EXPLOIT_POC_RE.search(text):
        score += 18.0
        _signal_add(reasons, "exploit or PoC signal")
    if RANSOMWARE_RE.search(text):
        score += 28.0
        _signal_add(reasons, "ransomware signal")
    if BREACH_RE.search(text):
        score += 22.0
        _signal_add(reasons, "breach or leak signal")
    if SUPPLY_CHAIN_RE.search(text):
        score += 24.0
        _signal_add(reasons, "supply-chain signal")
    if MALWARE_RE.search(text):
        score += 14.0
        _signal_add(reasons, "malware signal")
    if THREAT_ACTOR_RE.search(text):
        score += 14.0
        _signal_add(reasons, "threat actor / campaign signal")

    if cve_count:
        score += min(14.0, 5.0 + (cve_count * 2.0))
        _signal_add(reasons, f"{cve_count} CVE reference{'s' if cve_count != 1 else ''}")

    actionable_high_conf = sorted((high_conf_groups & ACTIONABLE_GROUPS) - GENERIC_HIGH_CONF_GROUPS)
    if actionable_high_conf:
        score += min(10.0, 4.0 + len(actionable_high_conf) * 2.0)
        _signal_add(reasons, "high-confidence actionable category")

    ts = item.get("published_ts")
    if isinstance(ts, (int, float)):
        age_hours = max(0.0, (now.timestamp() - float(ts)) / 3600.0)
        if age_hours <= 24.0:
            score += 8.0
            _signal_add(reasons, "fresh in the last 24h")
        elif age_hours <= 72.0:
            score += 4.0

    score += min(6.0, max(0.0, source_quality_score) * 0.06)

    has_action_context = any(
        (
            ACTIVE_EXPLOIT_RE.search(text),
            ZERO_DAY_RE.search(text),
            CRITICAL_IMPACT_RE.search(text),
            EXPLOIT_POC_RE.search(text),
            RANSOMWARE_RE.search(text),
            BREACH_RE.search(text),
            SUPPLY_CHAIN_RE.search(text),
            MALWARE_RE.search(text),
            THREAT_ACTOR_RE.search(text),
        )
    )
    title_action_context = any(
        (
            ACTIVE_EXPLOIT_RE.search(title),
            ZERO_DAY_RE.search(title),
            CRITICAL_IMPACT_RE.search(title),
            EXPLOIT_POC_RE.search(title),
            RANSOMWARE_RE.search(title),
            BREACH_RE.search(title),
            SUPPLY_CHAIN_RE.search(title),
            MALWARE_RE.search(title),
            THREAT_ACTOR_RE.search(title),
        )
    )
    direct_signal = title_action_context or cve_count > 0
    bulk_strong_context = any(
        (
            ACTIVE_EXPLOIT_RE.search(text),
            ZERO_DAY_RE.search(text),
            EXPLOIT_POC_RE.search(text),
            RANSOMWARE_RE.search(text),
            BREACH_RE.search(text),
            SUPPLY_CHAIN_RE.search(text),
            MALWARE_RE.search(text),
            THREAT_ACTOR_RE.search(text),
        )
    )

    if is_bulk_vuln_source and not has_action_context:
        score = min(score, 38.0)
        _signal_add(reasons, "bulk vulnerability feed without exploitation context")
    elif is_bulk_vuln_source and not bulk_strong_context:
        score = min(score, 49.0)
    elif not has_action_context and cve_count:
        score = min(score, 44.0)

    score = round(max(0.0, min(100.0, score)), 2)
    if score >= 78.0 and has_action_context and direct_signal:
        tier = "critical"
    elif score >= 50.0 and has_action_context and direct_signal:
        tier = "high"
    elif score >= 28.0 or cve_count or high_conf_groups:
        tier = "watch"
    else:
        tier = "low"

    return {
        "signal_score": score,
        "signal_tier": tier,
        "signal_reasons": reasons[:6],
        "signal_model": OPERATIONAL_SIGNAL_VERSION,
    }


def compute_curated_status(item: Dict[str, Any], source_quality_score: float, now: datetime) -> Dict[str, Any]:
    title = str(item.get("title") or "")
    summary = str(item.get("summary") or "")
    source = str(item.get("source") or "")
    text = f"{title} {summary[:600]}"
    tier = str(item.get("signal_tier") or "").lower()

    try:
        signal_score = float(item.get("signal_score") or 0.0)
    except (TypeError, ValueError):
        signal_score = 0.0

    if tier not in OPERATIONAL_HIGH_TIERS or signal_score < CURATED_MIN_SIGNAL_SCORE:
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    ts = item.get("published_ts")
    if not isinstance(ts, (int, float)):
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    age_hours = max(0.0, (now.timestamp() - float(ts)) / 3600.0)
    if age_hours > CURATED_MAX_AGE_HOURS:
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    if CURATION_NOISE_RE.search(f"{source} {title}"):
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    if BULK_VULN_SOURCE_RE.search(source) and signal_score < CURATED_BULK_SOURCE_MIN_SIGNAL_SCORE:
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    title_has_action_context = any(
        (
            ACTIVE_EXPLOIT_RE.search(title),
            ZERO_DAY_RE.search(title),
            CRITICAL_IMPACT_RE.search(title),
            EXPLOIT_POC_RE.search(title),
            RANSOMWARE_RE.search(title),
            BREACH_RE.search(title),
            SUPPLY_CHAIN_RE.search(title),
            MALWARE_RE.search(title),
            THREAT_ACTOR_RE.search(title),
        )
    )
    title_has_cve = bool(re.search(r"\bCVE-\d{4}-\d{4,7}\b", title, flags=re.IGNORECASE))
    if not title_has_action_context and not (title_has_cve and signal_score >= 75.0):
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    reasons: List[str] = []
    if ACTIVE_EXPLOIT_RE.search(text):
        _signal_add(reasons, "active exploitation / KEV")
    if ZERO_DAY_RE.search(text):
        _signal_add(reasons, "zero-day")
    if EXPLOIT_POC_RE.search(text):
        _signal_add(reasons, "exploit or PoC")
    if RANSOMWARE_RE.search(text):
        _signal_add(reasons, "ransomware")
    if BREACH_RE.search(text):
        _signal_add(reasons, "breach or leak")
    if SUPPLY_CHAIN_RE.search(text):
        _signal_add(reasons, "supply-chain")
    if CRITICAL_IMPACT_RE.search(title):
        _signal_add(reasons, "critical impact")
    if MALWARE_RE.search(title) and signal_score >= 75.0:
        _signal_add(reasons, "malware")
    if THREAT_ACTOR_RE.search(title) and signal_score >= 75.0:
        _signal_add(reasons, "threat actor / campaign")

    if not reasons:
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    if source_quality_score < 20.0 and signal_score < 85.0:
        return {"curated": False, "curation_reasons": [], "curation_policy": CURATION_POLICY_VERSION}

    return {
        "curated": True,
        "curation_reasons": reasons[:4],
        "curation_policy": CURATION_POLICY_VERSION,
    }


def dump_news_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def build_news_output(
    items: List[Dict[str, Any]],
    now: datetime,
    external_rules: Dict[str, Any],
    source_catalog: Dict[str, Any],
    feed_attempts: Dict[str, Dict[str, Any]],
    total_collected_items: int,
    output_truncated_by_bytes: bool,
) -> Dict[str, Any]:
    _, source_quality_report = build_source_quality(items, now)

    total_items = len(items)
    with_groups = sum(1 for i in items if i.get("smart_groups"))
    with_high_conf = sum(1 for i in items if i.get("smart_groups_high_confidence"))
    curated_count = sum(1 for i in items if bool(i.get("curated")))
    signal_tier_counts: Dict[str, int] = defaultdict(int)
    for item in items:
        signal_tier_counts[str(item.get("signal_tier") or "low")] += 1

    classification_stats = {
        "external_dictionary_path": str(SMART_GROUP_DICT_PATH),
        "external_dictionary_version": external_rules.get("version"),
        "high_confidence_threshold": HIGH_CONFIDENCE_THRESHOLD,
        "items_with_smart_groups": with_groups,
        "items_with_high_confidence_smart_groups": with_high_conf,
        "coverage_ratio": round((with_groups / total_items), 4) if total_items else 0.0,
        "high_confidence_ratio": round((with_high_conf / total_items), 4) if total_items else 0.0,
    }
    curation_stats = {
        "policy": CURATION_POLICY_VERSION,
        "curated_items": curated_count,
        "curated_ratio": round((curated_count / total_items), 4) if total_items else 0.0,
        "min_signal_score": CURATED_MIN_SIGNAL_SCORE,
        "max_age_hours": CURATED_MAX_AGE_HOURS,
        "bulk_source_min_signal_score": CURATED_BULK_SOURCE_MIN_SIGNAL_SCORE,
    }
    signal_stats = {
        "model": OPERATIONAL_SIGNAL_VERSION,
        "high_tiers": sorted(OPERATIONAL_HIGH_TIERS),
        "tier_counts": dict(sorted(signal_tier_counts.items())),
        "high_signal_items": sum(signal_tier_counts[tier] for tier in OPERATIONAL_HIGH_TIERS),
        "high_signal_ratio": round(
            (sum(signal_tier_counts[tier] for tier in OPERATIONAL_HIGH_TIERS) / total_items),
            4,
        ) if total_items else 0.0,
    }
    output_limits = {
        "serialization": "compact",
        "max_bytes": NEWS_RECENT_MAX_BYTES if NEWS_RECENT_MAX_BYTES > 0 else None,
        "min_items": NEWS_RECENT_MIN_ITEMS,
        "total_collected_items": total_collected_items,
        "items_written": total_items,
        "items_omitted": max(0, total_collected_items - total_items),
        "truncated_by_bytes": output_truncated_by_bytes,
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days_back": DAYS_BACK,
        "total_items": total_items,
        "total_collected_items": total_collected_items,
        "output_limits": output_limits,
        "classification_stats": classification_stats,
        "curation_stats": curation_stats,
        "signal_stats": signal_stats,
        "source_quality_model": {
            "freshness_weight": 0.32,
            "useful_volume_weight": 0.24,
            "dedup_weight": 0.20,
            "noise_weight": 0.14,
            "classification_weight": 0.10,
        },
        "source_catalog": source_catalog.get("metadata"),
        "source_quality": source_quality_report,
        "feed_attempts": list(feed_attempts.values()),
        "items": items,
    }


def fit_news_output_to_size(
    items: List[Dict[str, Any]],
    now: datetime,
    external_rules: Dict[str, Any],
    source_catalog: Dict[str, Any],
    feed_attempts: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Any], str]:
    total_collected_items = len(items)
    selected_items = items
    payload = build_news_output(
        selected_items,
        now,
        external_rules,
        source_catalog,
        feed_attempts,
        total_collected_items,
        output_truncated_by_bytes=False,
    )
    text = dump_news_json(payload)

    if NEWS_RECENT_MAX_BYTES <= 0:
        return payload, text

    min_items = min(max(0, NEWS_RECENT_MIN_ITEMS), total_collected_items)
    truncated = False

    while len(text.encode("utf-8")) > NEWS_RECENT_MAX_BYTES and len(selected_items) > min_items:
        current_bytes = len(text.encode("utf-8"))
        ratio = NEWS_RECENT_MAX_BYTES / max(1, current_bytes)
        target_count = max(min_items, int(len(selected_items) * ratio * 0.97))
        if target_count >= len(selected_items):
            target_count = len(selected_items) - 1

        selected_items = selected_items[:target_count]
        truncated = True
        payload = build_news_output(
            selected_items,
            now,
            external_rules,
            source_catalog,
            feed_attempts,
            total_collected_items,
            output_truncated_by_bytes=True,
        )
        text = dump_news_json(payload)

    final_bytes = len(text.encode("utf-8"))
    if final_bytes > NEWS_RECENT_MAX_BYTES:
        raise SystemExit(
            f"news_recent.json would be {final_bytes} bytes after keeping "
            f"{len(selected_items)} items, still above NEWS_RECENT_MAX_BYTES={NEWS_RECENT_MAX_BYTES}"
        )

    if truncated:
        print(
            "[WARN] Trimmed news_recent.json from "
            f"{total_collected_items} to {len(selected_items)} items to stay under "
            f"{NEWS_RECENT_MAX_BYTES} bytes"
        )

    return payload, text


# -------------------------------
# Main
# -------------------------------
def main() -> None:
    if not OPML_PATH.exists():
        raise SystemExit(f"OPML file not found: {OPML_PATH}")

    socket.setdefaulttimeout(FEED_TIMEOUT_SECONDS)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=DAYS_BACK)
    external_rules = load_external_smart_group_rules(SMART_GROUP_DICT_PATH)
    source_catalog = load_source_catalog(SOURCE_CATALOG_PATH)
    source_catalog_by_url: Dict[str, Dict[str, Any]] = source_catalog.get("by_url", {})

    items_by_link: Dict[str, Dict[str, Any]] = {}
    promo_stats: Dict[str, Dict[str, Any]] = {}
    feed_attempts: Dict[str, Dict[str, Any]] = {}  # key = xml_url

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
                        existing_dt = datetime.fromtimestamp(float(pub_ts), tz=timezone.utc)
                        if existing_dt < cutoff or existing_dt > now:
                            continue
                    except Exception:
                        pass

                title = str(item.get("title") or "")
                summary = str(item.get("summary") or "")
                type_slug = str(item.get("type") or "")
                classification = classify_smart_groups(title, summary, type_slug, external_rules)

                item["smart_groups"] = classification["smart_groups"]
                item["smart_group_confidence"] = classification["smart_group_confidence"]
                item["smart_groups_high_confidence"] = classification["smart_groups_high_confidence"]
                item["smart_group_max_confidence"] = classification["smart_group_max_confidence"]
                item["curated"] = False
                item["curation_reasons"] = []
                item["curation_policy"] = CURATION_POLICY_VERSION

                items_by_link[link] = item
                kept_existing += 1

            if kept_existing:
                print(f"[INFO] Pre-loaded {kept_existing} existing items from {OUTPUT_PATH}")
        except Exception as exc:
            print(f"[WARN] Could not load existing JSON from {OUTPUT_PATH}: {exc!r}")

    print(f"[INFO] Using OPML: {OPML_PATH}")
    print(f"[INFO] Collecting items from the last {DAYS_BACK} days (>= {cutoff.isoformat()})")

    for group_title, feed_title, xml_url in iter_opml_feeds(OPML_PATH):
        type_slug, type_label = normalize_category(group_title)
        print(f"[INFO] Fetching feed: {feed_title} ({xml_url}) [{type_label}]")

        feed_key = xml_url or feed_title
        catalog_feed = source_catalog_by_url.get(xml_url, {})
        if feed_key not in promo_stats:
            promo_stats[feed_key] = {
                "feed_title": feed_title,
                "xml_url": xml_url,
                "type_label": type_label,
                "promo_count": 0,
                "examples": [],
            }

        feed_stat = promo_stats[feed_key]

        # Initialise attempt record for this feed
        attempt: Dict[str, Any] = {
            "feed_title": feed_title,
            "xml_url": xml_url,
            "category": type_label,
            "type_slug": type_slug,
            "status": "error",
            "error": None,
            "bozo": False,
            "entries_in_feed": 0,
            "entries_kept": 0,
            "entries_too_old": 0,
            "entries_promo": 0,
            "entries_no_date": 0,
            "catalog_status": catalog_feed.get("source_status"),
            "ingest_enabled": catalog_feed.get("ingest_enabled", True),
            "external_http_status": catalog_feed.get("http_status"),
            "external_error": catalog_feed.get("error"),
            "external_consecutive_failures": catalog_feed.get("consecutive_failures"),
            "external_down_since": catalog_feed.get("down_since"),
            "external_last_seen_active": catalog_feed.get("last_seen_active"),
        }
        feed_attempts[feed_key] = attempt

        try:
            parsed = feedparser.parse(xml_url)
        except Exception as exc:
            err_str = repr(exc)
            print(f"[WARN] Failed to fetch feed {feed_title} ({xml_url}): {err_str}")
            attempt["status"] = "error"
            attempt["error"] = err_str
            continue

        bozo = getattr(parsed, "bozo", False)
        bozo_exc = getattr(parsed, "bozo_exception", None)
        if bozo and bozo_exc:
            bozo_str = repr(bozo_exc)
            print(f"[WARN] Bozo parsing feed {feed_title} ({xml_url}): {bozo_str}")
            attempt["bozo"] = True
            attempt["error"] = bozo_str

        attempt["entries_in_feed"] = len(parsed.entries)

        for entry in parsed.entries:
            link = getattr(entry, "link", None)
            title = getattr(entry, "title", "").strip()
            summary_raw = getattr(entry, "summary", "") or getattr(entry, "description", "")

            if not link or not title:
                continue

            if is_promotional_entry(title, summary_raw):
                feed_stat["promo_count"] += 1
                attempt["entries_promo"] += 1
                if len(feed_stat["examples"]) < 10:
                    feed_stat["examples"].append(title)
                continue

            pub_dt = parse_published(entry)
            if not pub_dt:
                pub_iso = None
                pub_ts = None
                attempt["entries_no_date"] += 1
            else:
                if pub_dt < cutoff or pub_dt > now:
                    attempt["entries_too_old"] += 1
                    continue
                pub_iso = pub_dt.isoformat()
                pub_ts = int(pub_dt.timestamp())

            summary = clean_html_summary(summary_raw)
            classification = classify_smart_groups(title, summary, type_slug, external_rules)

            item = {
                "title": title,
                "summary": summary,
                "link": link,
                "source": feed_title,
                "type": type_slug,
                "type_label": type_label,
                "published": pub_iso,
                "published_ts": pub_ts,
                "smart_groups": classification["smart_groups"],
                "smart_group_confidence": classification["smart_group_confidence"],
                "smart_groups_high_confidence": classification["smart_groups_high_confidence"],
                "smart_group_max_confidence": classification["smart_group_max_confidence"],
                "curated": False,
                "curation_reasons": [],
                "curation_policy": CURATION_POLICY_VERSION,
            }

            existing = items_by_link.get(link)
            if existing is None:
                items_by_link[link] = item
            else:
                if (item["published_ts"] or 0) > (existing.get("published_ts") or 0):
                    items_by_link[link] = item

            attempt["entries_kept"] += 1

        # Resolve final status for this attempt
        if attempt["status"] == "error" and attempt["entries_in_feed"] == 0 and not attempt["error"]:
            attempt["status"] = "empty"
        elif attempt["entries_kept"] > 0:
            attempt["status"] = "ok"
        elif attempt["bozo"] and attempt["entries_in_feed"] == 0:
            attempt["status"] = "bozo"
        elif attempt["entries_in_feed"] > 0 and attempt["entries_kept"] == 0:
            # Had entries but all were filtered (too old, promo, no date)
            attempt["status"] = "empty"
        elif attempt["status"] == "error":
            pass  # already set
        else:
            attempt["status"] = "empty"

    for url, feed in source_catalog_by_url.items():
        if url in feed_attempts:
            continue

        category = str(feed.get("category") or "General").strip()
        type_slug, type_label = normalize_category(category)
        catalog_status = str(feed.get("source_status") or "unknown")
        feed_attempts[url] = {
            "feed_title": feed.get("title") or url,
            "xml_url": url,
            "category": type_label,
            "type_slug": type_slug,
            "status": catalog_status,
            "error": feed.get("error"),
            "bozo": feed.get("bozo"),
            "entries_in_feed": int(feed.get("entries") or 0),
            "entries_kept": 0,
            "entries_too_old": 0,
            "entries_promo": 0,
            "entries_no_date": 0,
            "catalog_status": catalog_status,
            "ingest_enabled": bool(feed.get("ingest_enabled")),
            "external_http_status": feed.get("http_status"),
            "external_error": feed.get("error"),
            "external_consecutive_failures": feed.get("consecutive_failures"),
            "external_down_since": feed.get("down_since"),
            "external_last_seen_active": feed.get("last_seen_active"),
        }

    items_list = list(items_by_link.values())

    source_quality_map, _ = build_source_quality(items_list, now)

    for item in items_list:
        source_name = str(item.get("source") or "Unknown")
        source_score = source_quality_map.get(source_name, 50.0)
        item["source_quality_score"] = source_score
        item.update(compute_operational_signal(item, source_score, now))
        item.update(compute_curated_status(item, source_score, now))
        item["priority_score"] = compute_priority_score(item, source_score, now)

    items_list.sort(
        key=lambda x: (
            float(x.get("signal_score") or 0.0),
            float(x.get("priority_score") or 0.0),
            float(x.get("published_ts") or 0.0),
        ),
        reverse=True,
    )

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    out_data, output_text = fit_news_output_to_size(
        items_list,
        now,
        external_rules,
        source_catalog,
        feed_attempts,
    )
    output_bytes = len(output_text.encode("utf-8"))
    OUTPUT_PATH.write_text(output_text, encoding="utf-8")
    print(f"[INFO] Wrote {out_data['total_items']} items to {OUTPUT_PATH} ({output_bytes} bytes)")
    omitted = out_data.get("output_limits", {}).get("items_omitted", 0)
    if omitted:
        print(f"[INFO] Omitted {omitted} lower-ranked items from news_recent.json output")

    total_promo = sum(s["promo_count"] for s in promo_stats.values())
    print(f"[INFO] Total promotional items filtered: {total_promo}")

    for feed_stat in promo_stats.values():
        if feed_stat["promo_count"] > 0:
            print(
                f"[INFO]   {feed_stat['feed_title']} ({feed_stat['xml_url']}): "
                f"{feed_stat['promo_count']} promotional items filtered"
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

    for feed_stat in promo_stats.values():
        if feed_stat["promo_count"] > 0:
            report["feeds"].append(
                {
                    "feed_title": feed_stat["feed_title"],
                    "xml_url": feed_stat["xml_url"],
                    "type_label": feed_stat["type_label"],
                    "promo_count": feed_stat["promo_count"],
                    "examples": feed_stat["examples"],
                }
            )

    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_latest.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"[INFO] Wrote promo filter report to {report_path}")
    print(f"[INFO] Updated latest promo report alias at {report_latest}")


if __name__ == "__main__":
    main()
