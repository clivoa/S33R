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
SMART_GROUP_DICT_PATH = Path(
    os.environ.get("SMART_GROUP_DICT_PATH", str(BASE_DIR / "scripts" / "smart_group_dictionary.json"))
)

DAYS_BACK = int(os.environ.get("DAYS_BACK", "30"))
HIGH_CONFIDENCE_THRESHOLD = float(os.environ.get("SMART_GROUP_HIGH_CONF_THRESHOLD", "0.75"))
FEED_TIMEOUT_SECONDS = int(os.environ.get("FEED_TIMEOUT_SECONDS", "20"))


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


CURATED_KEYWORDS: List[str] = [
    "zero-day",
    "zeroday",
    "0day",
    "critical vulnerability",
    "exploit",
    "cve-",
    "backdoor",
    "rce",
    "remote code execution",
    "privilege escalation",
    "trojan",
    "wormable",
    "trojanized",
    "supply chain attack",
    "software supply chain",
    "supply-chain attack",
    "major breach",
    "data leak",
    "data leaks",
    "massive leak",
    "ransom gang",
    "ransomware",
    "double extortion",
    "ransom note",
]


SMART_GROUP_RULES: List[Tuple[str, List[str]]] = [
    ("Curated", CURATED_KEYWORDS),
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

            out["keywords"].append((group_name.strip(), term.lower(), clamp01(conf)))

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
                print(f"[WARN] Invalid external regex '{pattern}' for group '{group_name}': {exc}")
                continue

            out["regex"].append((group_name.strip(), compiled, clamp01(conf)))

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

    items_by_link: Dict[str, Dict[str, Any]] = {}
    promo_stats: Dict[str, Dict[str, Any]] = {}

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
                item["curated"] = (
                    classification["smart_group_confidence"].get("Curated", 0.0) >= 0.55
                    or bool(item.get("curated"))
                )

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
        except Exception as exc:
            print(f"[WARN] Failed to fetch feed {feed_title} ({xml_url}): {exc!r}")
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
                if pub_dt < cutoff or pub_dt > now:
                    continue
                pub_iso = pub_dt.isoformat()
                pub_ts = int(pub_dt.timestamp())

            summary = clean_html_summary(summary_raw)
            classification = classify_smart_groups(title, summary, type_slug, external_rules)
            curated_conf = classification["smart_group_confidence"].get("Curated", 0.0)

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
                "curated": curated_conf >= 0.55,
            }

            existing = items_by_link.get(link)
            if existing is None:
                items_by_link[link] = item
            else:
                if (item["published_ts"] or 0) > (existing.get("published_ts") or 0):
                    items_by_link[link] = item

    items_list = list(items_by_link.values())

    source_quality_map, source_quality_report = build_source_quality(items_list, now)

    for item in items_list:
        source_name = str(item.get("source") or "Unknown")
        source_score = source_quality_map.get(source_name, 50.0)
        item["source_quality_score"] = source_score
        item["priority_score"] = compute_priority_score(item, source_score, now)

    items_list.sort(
        key=lambda x: (
            float(x.get("priority_score") or 0.0),
            float(x.get("published_ts") or 0.0),
        ),
        reverse=True,
    )

    total_items = len(items_list)
    with_groups = sum(1 for i in items_list if i.get("smart_groups"))
    with_high_conf = sum(1 for i in items_list if i.get("smart_groups_high_confidence"))

    classification_stats = {
        "external_dictionary_path": str(SMART_GROUP_DICT_PATH),
        "external_dictionary_version": external_rules.get("version"),
        "high_confidence_threshold": HIGH_CONFIDENCE_THRESHOLD,
        "items_with_smart_groups": with_groups,
        "items_with_high_confidence_smart_groups": with_high_conf,
        "coverage_ratio": round((with_groups / total_items), 4) if total_items else 0.0,
        "high_confidence_ratio": round((with_high_conf / total_items), 4) if total_items else 0.0,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    out_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "days_back": DAYS_BACK,
        "total_items": total_items,
        "classification_stats": classification_stats,
        "source_quality_model": {
            "freshness_weight": 0.32,
            "useful_volume_weight": 0.24,
            "dedup_weight": 0.20,
            "noise_weight": 0.14,
            "classification_weight": 0.10,
        },
        "source_quality": source_quality_report,
        "items": items_list,
    }
    OUTPUT_PATH.write_text(json.dumps(out_data, indent=2), encoding="utf-8")
    print(f"[INFO] Wrote {total_items} items to {OUTPUT_PATH}")

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
