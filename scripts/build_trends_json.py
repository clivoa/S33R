#!/usr/bin/env python3
"""
Generates data/trends.json with trend metrics for trend.html:

- Daily news volume
- Category breakdown (smart_groups / tags)
- Top keywords by window (24h, 7d, 30d, 90d)
- Vendor counts by window
- Attack-term trends (ransomware, supply chain, 0-day, etc.)
- Top CVEs by window (for the CVE ranking)
- Threat actor mention timeline (by day),
  including top_actors per day for tooltips.

Data source:
- data/news_recent.json
"""

import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

BASE_DIR = Path(__file__).resolve().parent.parent
NEWS_RECENT_PATH = BASE_DIR / "data" / "news_recent.json"
OUTPUT_PATH = BASE_DIR / "data" / "trends.json"

# Windows used by the frontend
WINDOWS = {
    "24h": 1,
    "7d": 7,
    "30d": 30,
    "90d": 90,
}

STOPWORDS = {
    # Generic language stopwords
    "the", "and", "for", "with", "from", "this", "that", "have", "has",
    "into", "over", "under", "about", "your", "you", "are", "was", "were",
    "will", "their", "they", "them", "its", "our", "out", "but", "not",
    "can", "could", "would", "should", "may", "might", "than", "then",
    "after", "before", "more", "less", "also", "just", "into", "via",
    # Very generic security/news terms
    "security", "cyber", "attack", "attacks", "threat", "threats",
    "vulnerability", "vulnerabilities", "report", "reports",
    "blog", "post", "news", "data",
    # Common low-signal feed words
    "first", "all", "access", "based", "using", "used", "user", "users",
    "update", "updated", "updates", "detail", "details",
    # URL / protocol fragments
    "http", "https", "www", "com",
}

KEYWORD_VENDOR_STOPWORDS = {
    "upguard",
    # "kaspersky", "crowdstrike", etc. if they start polluting keywords
}


# Simple vendors (adjust as needed)
VENDOR_KEYWORDS = {
    "Microsoft": ["microsoft", "windows", "exchange", "azure"],
    "Cisco": ["cisco", "ios xe"],
    "Palo Alto": ["palo alto", "pan-os"],
    "Fortinet": ["fortinet", "fortigate"],
    "Cloudflare": ["cloudflare"],
    "Google": ["google", "chrome", "android", "gmail"],
    "Apple": ["apple", "macos", "ios", "ipados"],
    "VMware": ["vmware", "esxi"],
    "Citrix": ["citrix"],
    "Progress": ["progress", "moveit"],
    "Atlassian": ["atlassian", "jira", "confluence"],
}

# "Attack trends" terms shown in the Emerging attack trends chart
TRENDING_TERMS = {
    "ransomware": "Ransomware",
    "double extortion": "Double extortion",
    "supply chain": "Supply chain",
    "0-day": "0-day",
    "zero-day": "Zero-day",
    "data breach": "Data breach",
    "initial access": "Initial access",
    "phishing": "Phishing",
    "credential stuffing": "Credential stuffing",
}

# Malware families / clusters used for Actor x Malware correlation
MALWARE_KEYWORDS = {
    "Ransomware": ["ransomware", "raas", "double extortion", "locker"],
    "Infostealer": ["infostealer", "stealer", "credential stealer", "password stealer"],
    "Loader": ["loader", "dropper", "downloader"],
    "Backdoor": ["backdoor", "implant", "remote access trojan", "rat"],
    "Wiper": ["wiper", "data wiper", "disk wiper"],
    "Botnet": ["botnet", "c2 bot", "command-and-control bot"],
    "Banking Trojan": ["banking trojan", "banker malware"],
    "Cryptominer": ["cryptominer", "crypto miner", "mining malware"],
}

# =========================================================
#  Threat actors
# =========================================================
# TODO: Replace this list with the full threat_actors.txt list.
THREAT_ACTOR_NAMES = [
    "APT-C-23",
    "APT-C-36",
    "APT1",
    "APT12",
    "APT16",
    "APT17",
    "APT18",
    "APT19",
    "APT28",
    "APT29",
    "APT3",
    "APT30",
    "APT32",
    "APT33",
    "APT37",
    "APT38",
    "APT39",
    "APT41",
    "APT42",
    "APT5",
    "Agrius",
    "Ajax Security Team",
    "Akira",
    "Andariel",
    "Aoqin Dragon",
    "AppleJeus",
    "Aquatic Panda",
    "Axiom",
    "BITTER",
    "BRONZE BUTLER",
    "BackdoorDiplomacy",
    "BlackByte",
    "BlackOasis",
    "BlackTech",
    "Blue Mockingbird",
    "CURIUM",
    "Carbanak",
    "Chimera",
    "Cinnamon Tempest",
    "Cleaver",
    "Cobalt Group",
    "Confucius",
    "Contagious Interview",
    "CopyKittens",
    "Daggerfly",
    "Dark Caracal",
    "DarkHydrus",
    "DarkVishnya",
    "Darkhotel",
    "Deep Panda",
    "DragonOK",
    "Dragonfly",
    "EXOTIC LILY",
    "Earth Lusca",
    "Elderwood",
    "Ember Bear",
    "Equation",
    "Evilnum",
    "FIN10",
    "FIN13",
    "FIN4",
    "FIN5",
    "FIN6",
    "FIN7",
    "FIN8",
    "Ferocious Kitten",
    "Fox Kitten",
    "GALLIUM",
    "GCMAN",
    "GOLD SOUTHFIELD",
    "Gallmaker",
    "Gamaredon Group",
    "Gorgon Group",
    "Group5",
    "HAFNIUM",
    "HEXANE",
    "Higaisa",
    "INC Ransom",
    "Inception",
    "IndigoZebra",
    "Indrik Spider",
    "Ke3chang",
    "Kimsuky",
    "LAPSUS$",
    "Lazarus Group",
    "LazyScripter",
    "Leafminer",
    "Leviathan",
    "Lotus Blossom",
    "LuminousMoth",
    "Machete",
    "Magic Hound",
    "Malteiro",
    "Medusa Group",
    "Metador",
    "Moafee",
    "Mofang",
    "Molerats",
    "Moonstone Sleet",
    "Moses Staff",
    "MoustachedBouncer",
    "MuddyWater",
    "Mustang Panda",
    "Mustard Tempest",
    "NEODYMIUM",
    "Naikon",
    "Nomadic Octopus",
    "OilRig",
    "Orangeworm",
    "PLATINUM",
    "POLONIUM",
    "PROMETHIUM",
    "Patchwork",
    "PittyTiger",
    # "Play" intentionally omitted here — matched via CONTEXT_REQUIRED_ACTORS below
    "Poseidon Group",
    "Putter Panda",
    "RTM",
    "Rancor",
    "RedCurl",
    "RedEcho",
    "Rocke",
    "Saint Bear",
    "Salt Typhoon",
    "Sandworm Team",
    "Scarlet Mimic",
    "Scattered Spider",
    "Sea Turtle",
    "SideCopy",
    "Sidewinder",
    "Silence",
    "Silent Librarian",
    "SilverTerrier",
    "Sowbug",
    "Star Blizzard",
    "Stealth Falcon",
    "Storm-0501",
    "Storm-1811",
    "Strider",
    "Suckfly",
    "TA2541",
    "TA459",
    "TA505",
    "TA551",
    "TA577",
    "TA578",
    "TEMP.Veles",
    "TeamTNT",
    "The White Company",
    "Threat Group-1314",
    "Threat Group-3390",
    "Thrip",
    "ToddyCat",
    "Tonto Team",
    "Transparent Tribe",
    "Tropic Trooper",
    "Turla",
    "UNC3886",
    "Velvet Ant",
    "Volatile Cedar",
    "Volt Typhoon",
    "WIRTE",
    "Water Galura",
    "Whitefly",
    "Windigo",
    "Windshift",
    "Winnti Group",
    "Winter Vivern",
    "Wizard Spider",
    "ZIRCONIUM",
    "admin@338",
    "menuPass",
    "Amethyst Rain",
    "Antique Typhoon",
    "Aqua Blizzard",
    "Berry Sandstorm",
    "Blue Tsunami",
    "Brass Typhoon",
    "Brocade Typhoon",
    "Burgundy Sandstorm",
    "Cadet Blizzard",
    "Canary Typhoon",
    "Canvas Cyclone",
    "Caramel Tsunami",
    "Carmine Tsunami",
    "Charcoal Typhoon",
    "Checkered Typhoon",
    "Cinnamon Tempest",
    "Circle Typhoon",
    "Citrine Sleet",
    "Copper Typhoon",
    "Cotton Sandstorm",
    "CovertNetwork-1658",
    "Crescent Typhoon",
    "Crimson Sandstorm",
    "Cuboid Sandstorm",
    "Daffodil Gust",
    "Denim Tsunami",
    "Diamond Sleet",
    "Emerald Sleet",
    "Fallow Squall",
    "Flax Typhoon",
    "Forest Blizzard",
    "Ghost Blizzard",
    "Gingham Typhoon",
    "Granite Typhoon",
    "Gray Sandstorm",
    "Hazel Sandstorm",
    "Heart Typhoon",
    "Hexagon Typhoon",
    "Houndstooth Typhoon",
    "Jade Sleet",
    "Jasper Sleet",
    "Lace Tempest",
    "Lemon Sandstorm",
    "Leopard Typhoon",
    "Lilac Typhoon",
    "Linen Typhoon",
    "Luna Tempest",
    "Magenta Dust",
    "Manatee Tempest",
    "Mango Sandstorm",
    "Marbled Dust",
    "Marigold Sandstorm",
    "Midnight Blizzard",
    "Mint Sandstorm",
    "Moonstone Sleet",
    "Mulberry Typhoon",
    "Mustard Tempest",
    "Neva Flood",
    "Night Tsunami",
    "Nylon Typhoon",
    "Octo Tempest",
    "Oka Flood",
    "Onyx Sleet",
    "Opal Sleet",
    "Patched Lightning",
    "Peach Sandstorm",
    "Pearl Sleet",
    "Pepper Typhoon",
    "Periwinkle Tempest",
    "Phlox Tempest",
    "Pink Sandstorm",
    "Pinstripe Lightning",
    "Pistachio Tempest",
    "Plaid Rain",
    "Pumpkin Sandstorm",
    "Purple Typhoon",
    "Raspberry Typhoon",
    "Red Sandstorm",
    "Ruby Sleet",
    "Ruza Flood",
    "Salmon Typhoon",
    "Salt Typhoon",
    "Sangria Tempest",
    "Sapphire Sleet",
    "Satin Typhoon",
    "Seashell Blizzard",
    "Secret Blizzard",
    "Sefid Flood",
    "Shadow Typhoon",
    "Silk Typhoon",
    "Smoke Sandstorm",
    "Spandex Tempest",
    "Star Blizzard",
    "Storm-0216",
    "Storm-0230",
    "Storm-0247",
    "Storm-0249",
    "Storm-0252",
    "Storm-0288",
    "Storm-0302",
    "Storm-0408",
    "Storm-0485",
    "Storm-0501",
    "Storm-0538",
    "Storm-0539",
    "Storm-0569",
    "Storm-0671",
    "Storm-0940",
    "Storm-0978",
    "Storm-1101",
    "Storm-1113",
    "Storm-1152",
    "Storm-1175",
    "Storm-1194",
    "Storm-1249",
    "Storm-1516",
    "Storm-1567",
    "Storm-1607",
    "Storm-1674",
    "Storm-1811",
    "Storm-1849",
    "Storm-1865",
    "Storm-1982",
    "Storm-2035",
    "Storm-2077",
    "Storm-2246",
    "Storm-2372",
    "Storm-2460",
    "Storm-2477",
    "Storm-2603",
    "Storm-2657",
    "Strawberry Tempest",
    "Sunglow Blizzard",
    "Swirl Typhoon",
    "Taffeta Typhoon",
    "Taizi Flood",
    "Tumbleweed Typhoon",
    "Twill Typhoon",
    "Vanilla Tempest",
    "Velvet Tempest",
    "Violet Typhoon",
    "Void Blizzard",
    "Volga Flood",
    "Volt Typhoon",
    "Wheat Tempest",
    "Wisteria Tsunami",
    "Yulong Flood",
    "Zigzag Hail",
    "HAZARD SPIDER",
    "FROZEN SPIDER",
    "HERMIT SPIDER",
    "BITWISE SPIDER",
    "IMPOSTER SPIDER",
    "MUTANT SPIDER",
    "SCION SPIDER",
    "SLY SPIDER",
    "APOTHECARY SPIDER",
    "DEMON SPIDER",
    "VETO SPIDER",
    "VICE SPIDER",
    "SOLAR SPIDER",
    "TRAVELING SPIDER",
    "PLUMP SPIDER",
    "NITRO SPIDER",
    "CURLY SPIDER",
    "CHATTY SPIDER",
    "RENAISSANCE SPIDER",
    "PUNK SPIDER",
    "RECESS SPIDER",
    "BRAIN SPIDER",
    "SCATTERED SPIDER",
    "AVIATOR SPIDER",
    "PROPHET SPIDER",
    "GRACEFUL SPIDER",
    "SCULLY SPIDER",
    "BRASH SPIDER",
    "LIGHTNING SPIDER",
    "HOOK SPIDER",
    "HOLIDAY SPIDER",
    "SAMBA SPIDER",
    "LUNAR SPIDER",
    "LUXURY SPIDER",
    "NIMBLE SPIDER",
    "COOKIE SPIDER",
    "ROBOT SPIDER",
    "ODYSSEY SPIDER",
    "ROYAL SPIDER",
    "BLIND SPIDER",
    "WIZARD SPIDER",
    "BOUNTY JACKAL",
    "CRUEL JACKAL",
    "HORDE PANDA",
    "SUNRISE PANDA",
    "PHANTOM PANDA",
    "CASCADE PANDA",
    "LOTUS PANDA",
    "GENESIS PANDA",
    "WARP PANDA",
    "VERTIGO PANDA",
    "MUSTANG PANDA",
    "HORDE PANDA",
    "OPERATOR PANDA",
    "ENVOY PANDA",
    "GOSSAMER BEAR",
    "FANCY BEAR",
    "PRIMITIVE BEAR",
    "COZY BEAR",
    "VOODOO BEAR",
    "VENOMOUS BEAR",
    "FABLE TIGER",
    "OUTRIDER TIGER",
    "HAZY TIGER",
    "RAZOR TIGER",
    "FRANTIC TIGER",
    "FAMOUS CHOLLIMA",
    "LABYRINTH CHOLLIMA",
    "STARDUST CHOLLIMA",
    "HAYWIRE KITTEN",
    "SPECTRAL KITTEN",
    "GALACTIC OCELOT",
]

def build_threat_actor_patterns() -> List[str]:
    """
    Builds the regex list for threat actor detection:
    - generic patterns (APTxx, TAxxx, UNCxxx, Storm-xxxx, FINxx, Threat Group-xxxx)
    - one large pattern with all known names (THREAT_ACTOR_NAMES)
    """
    generic_patterns = [
        r"\bAPT ?\d+\b",
        r"\bAPT-C-\d+\b",
        r"\bTA\d+\b",
        r"\bUNC\d+\b",
        r"\bStorm-\d+\b",
        r"\bFIN\d+\b",
        r"\bThreat Group-\d+\b",
    ]

    unique_names = sorted(set(THREAT_ACTOR_NAMES))
    alt = "|".join(re.escape(name) for name in unique_names)
    name_pattern = rf"\b(?:{alt})\b"

    return generic_patterns + [name_pattern]


THREAT_ACTOR_PATTERNS = build_threat_actor_patterns()

# Canonical map: lowercase -> official name (include context-required actors too)
CANONICAL_TA_MAP = {name.lower(): name for name in THREAT_ACTOR_NAMES}
CANONICAL_TA_MAP.update({k.lower(): k for k in ["Play"]})

# Actors whose names are common English words — only matched when a disambiguating
# keyword appears in the same text (within ~300 chars is handled by full-text scan).
CONTEXT_REQUIRED_ACTORS: Dict[str, re.Pattern] = {
    "Play": re.compile(
        r"\bPlay\s+(?:ransomware|group|gang|threat\s+actor|APT|actors?)\b"
        r"|\bPlay\b.{0,80}(?:ransomware|encrypted|extortion|exfiltrat)",
        re.IGNORECASE | re.DOTALL,
    ),
}

# Single regex to extract threat actor names (without generic patterns)
THREAT_ACTOR_NAME_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(name) for name in THREAT_ACTOR_NAMES) + r")\b",
    re.IGNORECASE,
)

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
ACTIVE_EXPLOIT_REGEX = re.compile(
    r"\b(active exploitation|exploited in the wild|weaponized|poc released|zero-day|0-day|rce)\b",
    re.IGNORECASE,
)

WATCH_SURFACES_BY_VENDOR = {
    "Microsoft": ["Entra ID sign-in logs", "Defender for Endpoint alerts", "Exchange audit logs"],
    "Cisco": ["VPN/ASA auth logs", "NetFlow anomalies", "Cisco appliance syslogs"],
    "Palo Alto": ["PAN-OS threat logs", "GlobalProtect auth logs", "WildFire detections"],
    "Fortinet": ["FortiGate traffic logs", "SSL-VPN auth logs", "FortiAnalyzer alerts"],
    "Google": ["Google Workspace audit", "Chrome EDR telemetry", "GCP audit logs"],
    "Apple": ["MDM compliance events", "macOS EDR telemetry", "Apple mobile fleet alerts"],
    "Cloudflare": ["WAF blocked events", "Access auth logs", "edge firewall telemetry"],
}

CAMPAIGN_MIN_ITEMS = 2
PRIORITY_TOP_K = 20
CLUSTER_TOP_K = 12


# =========================================================
#  Utilities
# =========================================================

def parse_iso(date_str: str) -> datetime:
    """
    Parses an ISO-ish date string and returns a timezone-aware UTC datetime.
    """
    if not date_str:
        raise ValueError("empty date")
    s = date_str
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def load_news() -> List[Dict[str, Any]]:
    """
    Loads news_recent.json while accepting different formats:

    - Root list:
      [ {entry}, {entry}, ... ]

    - Object with a key containing a list:
      { "entries": [ ... ] } ou "items"/"news"/"results"/"data"
    """
    print(f"[INFO] Loading {NEWS_RECENT_PATH}...")
    raw = NEWS_RECENT_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)

    # Ideal case: root list
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("entries", "items", "news", "results", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]

        # Fallback: any value that is a list of dicts
        for v in data.values():
            if isinstance(v, list) and (not v or isinstance(v[0], dict)):
                return v

        raise RuntimeError(
            "news_recent.json is an object, but no entry list was found "
            "under 'entries', 'items', 'news', 'results', or 'data'."
        )

    raise RuntimeError(
        f"news_recent.json has an unexpected root type: {type(data).__name__}"
    )


def normalize_text(entry: Dict[str, Any]) -> str:
    parts = [
        entry.get("title", "") or "",
        entry.get("summary", "") or "",
        entry.get("source", "") or "",
    ]
    return " ".join(parts).lower()


def tokenize(text: str) -> Iterable[str]:
    """
    Splits text into simple tokens, removing:
    - stopwords
    - very short tokens
    - pure numbers / years (2024, 2025)
    - URL fragments (http, https, www, com)
    - some vendors already shown in another chart
    """
    for token in re.findall(r"[a-zA-Z0-9\-]+", text.lower()):
        # Slightly larger minimum size to capture richer terms
        if len(token) < 4:
            continue

        if token in STOPWORDS:
            continue

        # Ignore numbers and years
        if token.isdigit():
            continue
        if re.fullmatch(r"20\d{2}", token):
            continue

        # URL fragments (already covered in STOPWORDS, kept as a guard)
        if token in ("http", "https", "www", "com"):
            continue

        # Vendors we only want to show in the Vendors chart
        if token in KEYWORD_VENDOR_STOPWORDS:
            continue

        yield token



def get_categories(entry: Dict[str, Any]) -> List[str]:
    """
    Attempts to read categories / smart_groups from an entry.
    """
    cats: List[str] = []

    sg = entry.get("smart_groups") or entry.get("categories") or entry.get("tags")
    if isinstance(sg, list):
        cats.extend([str(c) for c in sg])
    elif isinstance(sg, str):
        cats.append(sg)

    cat = entry.get("category")
    if isinstance(cat, str):
        cats.append(cat)

    cleaned: List[str] = []
    for c in cats:
        c = c.strip()
        if c:
            cleaned.append(c)
    return cleaned


def within_window(entry_dt: datetime, now: datetime, days: int) -> bool:
    return entry_dt >= (now - timedelta(days=days))


def within_previous_window(entry_dt: datetime, now: datetime, days: int) -> bool:
    current_start = now - timedelta(days=days)
    previous_start = now - timedelta(days=2 * days)
    return previous_start <= entry_dt < current_start


def counter_to_sorted_list(cnt: Counter, limit: int = 0) -> List[List[Any]]:
    rows = [[k, int(v)] for k, v in cnt.most_common()]
    if limit > 0:
        return rows[:limit]
    return rows


def pair_counter_to_rows(
    cnt: Counter,
    left_key: str,
    right_key: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    rows = []
    for (left, right), n in cnt.most_common(limit):
        rows.append({left_key: left, right_key: right, "count": int(n)})
    return rows


def build_delta_rows(current: Counter, previous: Counter, limit: int = 25) -> List[Dict[str, Any]]:
    keys = set(current.keys()) | set(previous.keys())
    rows: List[Dict[str, Any]] = []

    for name in keys:
        cur = int(current.get(name, 0))
        prev = int(previous.get(name, 0))
        if cur == 0 and prev == 0:
            continue

        delta = cur - prev
        if prev > 0:
            pct_change = round((delta / prev) * 100.0, 2)
        elif cur > 0:
            pct_change = None
        else:
            pct_change = 0.0

        direction = "flat"
        status = "flat"
        if prev == 0 and cur > 0:
            direction = "up"
            status = "new"
        elif cur == 0 and prev > 0:
            direction = "down"
            status = "dropped"
        elif delta > 0:
            direction = "up"
            status = "accelerating" if prev > 0 and cur >= int(prev * 1.5) else "persistent"
        elif delta < 0:
            direction = "down"
            status = "cooling"
        elif cur > 0:
            status = "persistent"

        rows.append(
            {
                "name": name,
                "current": cur,
                "previous": prev,
                "delta": delta,
                "pct_change": pct_change,
                "direction": direction,
                "status": status,
            }
        )

    rows.sort(key=lambda r: (abs(r["delta"]), r["current"], r["name"]), reverse=True)
    return rows[:limit]


def shannon_entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values() if c > 0)


def _sort_set(values: Iterable[str], limit: int = 4) -> List[str]:
    clean = sorted({str(v).strip() for v in values if str(v).strip()})
    if limit > 0:
        return clean[:limit]
    return clean


def classify_priority_tier(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def compute_operational_priority(
    entry: Dict[str, Any],
    dt: datetime,
    now: datetime,
    text: str,
    cve_hits: List[str],
    actor_hits: List[str],
    vendor_hits: List[str],
    malware_hits: List[str],
    categories: List[str],
) -> Dict[str, Any]:
    age_hours = max(0.0, (now - dt).total_seconds() / 3600.0)
    recency_score = max(0.0, 28.0 - min(28.0, age_hours / 3.0))
    cve_score = min(24.0, len(cve_hits) * 8.0)
    actor_score = min(16.0, len(actor_hits) * 6.0)
    malware_score = min(12.0, len(malware_hits) * 4.0)
    category_score = min(8.0, len(categories) * 1.5)

    active_exploit_score = 0.0
    if ACTIVE_EXPLOIT_REGEX.search(text):
        active_exploit_score = 16.0

    confidence_score = 0.0
    raw_conf = entry.get("smart_group_max_confidence")
    if isinstance(raw_conf, (int, float)):
        confidence_score = min(10.0, max(0.0, float(raw_conf)) * 10.0)

    source_quality_score = 0.0
    raw_source_score = entry.get("source_quality_score")
    if isinstance(raw_source_score, (int, float)):
        source_quality_score = min(8.0, max(0.0, float(raw_source_score)) * 0.08)

    curated_bonus = 8.0 if bool(entry.get("curated")) else 0.0

    explicit_priority = 0.0
    raw_priority = entry.get("priority_score")
    if isinstance(raw_priority, (int, float)):
        explicit_priority = min(8.0, max(0.0, float(raw_priority)) * 0.08)

    total = (
        recency_score
        + cve_score
        + actor_score
        + malware_score
        + category_score
        + active_exploit_score
        + confidence_score
        + source_quality_score
        + curated_bonus
        + explicit_priority
    )
    total = max(0.0, min(100.0, total))

    drivers = []
    if cve_hits:
        drivers.append(f"CVE signals ({len(cve_hits)})")
    if actor_hits:
        drivers.append(f"Actor mentions ({len(actor_hits)})")
    if malware_hits:
        drivers.append(f"Malware indicators ({len(malware_hits)})")
    if active_exploit_score > 0:
        drivers.append("Active exploitation language")
    if bool(entry.get("curated")):
        drivers.append("Curated/high-signal source")

    if not drivers:
        drivers.append("Recency + baseline context")

    return {
        "score": round(total, 2),
        "tier": classify_priority_tier(total),
        "drivers": drivers[:4],
    }


def build_campaign_actions(cluster: Dict[str, Any]) -> List[str]:
    actions: List[str] = []
    cves = cluster.get("top_cves") or []
    vendors = cluster.get("top_vendors") or []
    malware = cluster.get("top_malware") or []
    actors = cluster.get("top_actors") or []

    if cves:
        top = ", ".join([c[0] for c in cves[:2]])
        actions.append(f"Validate exposure and patch status for {top}; prioritize internet-facing assets first.")

    if malware:
        family = ", ".join([m[0] for m in malware[:2]])
        actions.append(f"Run EDR hunts for {family} behaviors and suspicious parent-child process chains.")

    for vendor, _ in vendors[:2]:
        surfaces = WATCH_SURFACES_BY_VENDOR.get(vendor, [])
        if surfaces:
            actions.append(f"Increase monitoring on {vendor}: {', '.join(surfaces[:2])}.")
            break

    if actors:
        actions.append("Map observed activity to ATT&CK techniques and tune detections for related TTPs.")

    if not actions:
        actions.append("Review top linked reports and extract actionable detections for current SOC hunts.")

    return actions[:3]


def make_campaign_key(
    cves: List[str],
    actors: List[str],
    vendors: List[str],
    malware: List[str],
    categories: List[str],
) -> str:
    cve_key = ",".join(_sort_set(cves, limit=2))
    actor_key = ",".join(_sort_set(actors, limit=2))
    vendor_key = ",".join(_sort_set(vendors, limit=2))
    malware_key = ",".join(_sort_set(malware, limit=2))
    # If we already have a strong structural signal (CVE/actor), avoid malware to prevent campaign fragmentation.
    if cve_key or actor_key:
        malware_key = ""

    parts = [cve_key, actor_key, vendor_key, malware_key]
    signal_dims = sum(1 for p in parts[:4] if p)
    if signal_dims < 2:
        return ""
    return "|".join(p or "-" for p in parts)


def _bump_counter(counter: Dict[str, int], key: str, step: int = 1) -> None:
    if not key:
        return
    counter[key] = int(counter.get(key, 0)) + step


def update_campaign_bucket(
    bucket: Dict[str, Dict[str, Any]],
    key: str,
    entry: Dict[str, Any],
    dt: datetime,
    priority: Dict[str, Any],
    cves: List[str],
    actors: List[str],
    vendors: List[str],
    malware: List[str],
    categories: List[str],
) -> None:
    if not key:
        return

    row = bucket.get(key)
    if row is None:
        row = {
            "cluster_id": key,
            "items_count": 0,
            "first_seen": dt.isoformat(),
            "last_seen": dt.isoformat(),
            "top_links": [],
            "top_titles": [],
            "cves": {},
            "actors": {},
            "vendors": {},
            "malware": {},
            "categories": {},
            "priority_sum": 0.0,
            "priority_max": 0.0,
            "curated_hits": 0,
        }
        bucket[key] = row

    row["items_count"] += 1
    row["priority_sum"] += float(priority["score"])
    row["priority_max"] = max(float(row["priority_max"]), float(priority["score"]))
    if bool(entry.get("curated")):
        row["curated_hits"] += 1

    iso = dt.isoformat()
    if iso < row["first_seen"]:
        row["first_seen"] = iso
    if iso > row["last_seen"]:
        row["last_seen"] = iso

    link = str(entry.get("link") or "").strip()
    title = str(entry.get("title") or "").strip()
    if link and link not in row["top_links"] and len(row["top_links"]) < 6:
        row["top_links"].append(link)
    if title and title not in row["top_titles"] and len(row["top_titles"]) < 6:
        row["top_titles"].append(title)

    for cve in cves:
        _bump_counter(row["cves"], cve)
    for actor in actors:
        _bump_counter(row["actors"], actor)
    for vendor in vendors:
        _bump_counter(row["vendors"], vendor)
    for mal in malware:
        _bump_counter(row["malware"], mal)
    for cat in categories:
        _bump_counter(row["categories"], cat)


def top_counter_map(counter: Dict[str, int], k: int = 5) -> List[List[Any]]:
    return [[k1, int(v1)] for k1, v1 in sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:k]]


# =========================================================
#  Main
# =========================================================

def main() -> None:
    news = load_news()
    now = datetime.now(timezone.utc)

    # Aggregated counters
    daily_counter = Counter()  # date_str -> total news items
    per_window_categories: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_keywords: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_vendors: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_trends: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_cves: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_actors: Dict[str, Counter] = {w: Counter() for w in WINDOWS}

    # Previous window for delta analytics
    prev_window_vendors: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    prev_window_cves: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    prev_window_actors: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    prev_window_keywords: Dict[str, Counter] = {w: Counter() for w in WINDOWS}

    # Co-occurrence
    co_cve_vendor: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    co_actor_malware: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    co_category_category: Dict[str, Counter] = {w: Counter() for w in WINDOWS}

    # Operational outputs
    priority_now_rows: Dict[str, List[Dict[str, Any]]] = {w: [] for w in WINDOWS}
    campaign_current: Dict[str, Dict[str, Dict[str, Any]]] = {w: {} for w in WINDOWS}
    campaign_previous: Dict[str, Dict[str, Dict[str, Any]]] = {w: {} for w in WINDOWS}

    # Threat actors
    threat_actor_daily_counter = Counter()          # date_str -> news count with actor
    threat_actor_daily_names: Dict[str, Counter] = defaultdict(Counter)  # date_str -> Counter(actor_name)

    # Per-source quality metrics
    source_stats: Dict[str, Any] = {}

    threat_actor_compiled = [
        re.compile(pat, re.IGNORECASE) for pat in THREAT_ACTOR_PATTERNS
    ]

    processed = 0
    skipped_no_date = 0

    for entry in news:
        date_str = entry.get("published") or entry.get("date")
        if not date_str:
            skipped_no_date += 1
            continue

        try:
            dt = parse_iso(date_str)
        except Exception:
            skipped_no_date += 1
            continue

        date_only = dt.date().isoformat()
        text = normalize_text(entry)

        # Daily volume
        daily_counter[date_only] += 1

        # 1) Generic threat actor detection (APTxx, TAxxx, Storm-xxxx, etc.)
        has_actor = any(p.search(text) for p in threat_actor_compiled)
        if has_actor:
            threat_actor_daily_counter[date_only] += 1

        # 2) Concrete name extraction for top_actors
        name_matches = set(m.group(0) for m in THREAT_ACTOR_NAME_REGEX.finditer(text))
        # Also check context-required actors separately
        for actor_name, ctx_pattern in CONTEXT_REQUIRED_ACTORS.items():
            if ctx_pattern.search(text):
                name_matches.add(actor_name)
        actor_hits = set()
        for raw_name in name_matches:
            canonical = CANONICAL_TA_MAP.get(raw_name.lower(), raw_name)
            threat_actor_daily_names[date_only][canonical] += 1
            actor_hits.add(canonical)

        # Categories
        cats = get_categories(entry)

        # Keywords
        tokens = list(tokenize(text))

        # Vendors
        vendor_hits = set()
        for vendor, patterns in VENDOR_KEYWORDS.items():
            for pat in patterns:
                if pat.lower() in text:
                    vendor_hits.add(vendor)
                    break

        # Trending terms
        trend_hits = set()
        for key, label in TRENDING_TERMS.items():
            if key.lower() in text:
                trend_hits.add(key)

        # CVEs
        cve_hits = set(m.upper() for m in CVE_REGEX.findall(text))

        # Malware labels for Actor x Malware correlation
        malware_hits = set()
        for label, patterns in MALWARE_KEYWORDS.items():
            for pat in patterns:
                if pat.lower() in text:
                    malware_hits.add(label)
                    break

        actor_list = sorted(actor_hits)
        vendor_list = sorted(vendor_hits)
        cve_list = sorted(cve_hits)
        malware_list = sorted(malware_hits)
        category_list = sorted(set(cats))

        # Per-source quality accumulation (window-independent)
        _src = str(entry.get("source") or "Unknown").strip() or "Unknown"
        if _src not in source_stats:
            source_stats[_src] = {
                "total": 0,
                "curated": 0,
                "priority_scores": [],
                "cve_total": 0,
                "sg_counts": Counter(),
            }
        _ss = source_stats[_src]
        _ss["total"] += 1
        if bool(entry.get("curated")):
            _ss["curated"] += 1
        _raw_ps = entry.get("priority_score")
        if isinstance(_raw_ps, (int, float)):
            _ss["priority_scores"].append(float(_raw_ps))
        _ss["cve_total"] += len(cve_hits)
        for _c in cats:
            _ss["sg_counts"][_c] += 1

        # Apply in each window
        for win, days in WINDOWS.items():
            if not within_window(dt, now, days):
                if within_previous_window(dt, now, days):
                    for v in vendor_hits:
                        prev_window_vendors[win][v] += 1
                    for cve in cve_hits:
                        prev_window_cves[win][cve] += 1
                    for actor in actor_hits:
                        prev_window_actors[win][actor] += 1
                    for t in tokens:
                        prev_window_keywords[win][t] += 1

                    prev_priority = compute_operational_priority(
                        entry=entry,
                        dt=dt,
                        now=now,
                        text=text,
                        cve_hits=cve_list,
                        actor_hits=actor_list,
                        vendor_hits=vendor_list,
                        malware_hits=malware_list,
                        categories=category_list,
                    )
                    prev_key = make_campaign_key(
                        cve_list,
                        actor_list,
                        vendor_list,
                        malware_list,
                        category_list,
                    )
                    update_campaign_bucket(
                        bucket=campaign_previous[win],
                        key=prev_key,
                        entry=entry,
                        dt=dt,
                        priority=prev_priority,
                        cves=cve_list,
                        actors=actor_list,
                        vendors=vendor_list,
                        malware=malware_list,
                        categories=category_list,
                    )
                continue

            for c in cats:
                per_window_categories[win][c] += 1

            for t in tokens:
                per_window_keywords[win][t] += 1

            for v in vendor_hits:
                per_window_vendors[win][v] += 1

            for key in trend_hits:
                per_window_trends[win][key] += 1

            for cve in cve_hits:
                per_window_cves[win][cve] += 1

            for actor in actor_hits:
                per_window_actors[win][actor] += 1

            # Co-occurrence: CVE x Vendor
            for cve in cve_hits:
                for vendor in vendor_hits:
                    co_cve_vendor[win][(cve, vendor)] += 1

            # Co-occurrence: Actor x Malware
            for actor in actor_hits:
                for malware in malware_hits:
                    co_actor_malware[win][(actor, malware)] += 1

            # Co-occurrence: Category x Category (unique pairs per item)
            unique_cats = sorted(set(cats))
            for i in range(len(unique_cats)):
                for j in range(i + 1, len(unique_cats)):
                    co_category_category[win][(unique_cats[i], unique_cats[j])] += 1

            priority = compute_operational_priority(
                entry=entry,
                dt=dt,
                now=now,
                text=text,
                cve_hits=cve_list,
                actor_hits=actor_list,
                vendor_hits=vendor_list,
                malware_hits=malware_list,
                categories=category_list,
            )
            priority_now_rows[win].append(
                {
                    "title": entry.get("title"),
                    "link": entry.get("link"),
                    "source": entry.get("source"),
                    "published": dt.isoformat(),
                    "score": priority["score"],
                    "tier": priority["tier"],
                    "drivers": priority["drivers"],
                    "cves": cve_list[:4],
                    "vendors": vendor_list[:4],
                    "actors": actor_list[:4],
                    "malware": malware_list[:4],
                    "categories": category_list[:5],
                    "curated": bool(entry.get("curated")),
                }
            )

            camp_key = make_campaign_key(
                cve_list,
                actor_list,
                vendor_list,
                malware_list,
                category_list,
            )
            update_campaign_bucket(
                bucket=campaign_current[win],
                key=camp_key,
                entry=entry,
                dt=dt,
                priority=priority,
                cves=cve_list,
                actors=actor_list,
                vendors=vendor_list,
                malware=malware_list,
                categories=category_list,
            )

        processed += 1

    print(f"[INFO] Processed entries: {processed}, skipped (no date): {skipped_no_date}")

    # Build source quality ranking
    source_quality_rows: List[Dict[str, Any]] = []
    _max_entropy = 0.0
    for _src, _ss in source_stats.items():
        _total = _ss["total"]
        if _total < 5:
            continue
        _curated_rate = round(_ss["curated"] / _total, 4)
        _ps_list = _ss["priority_scores"]
        _avg_ps = round(sum(_ps_list) / len(_ps_list), 2) if _ps_list else 0.0
        _std_ps = round(
            math.sqrt(sum((x - _avg_ps) ** 2 for x in _ps_list) / max(1, len(_ps_list))), 2
        ) if len(_ps_list) > 1 else 0.0
        _cve_density = round(_ss["cve_total"] / _total * 100, 2)
        _entropy = round(shannon_entropy(_ss["sg_counts"]), 4)
        _max_entropy = max(_max_entropy, _entropy)
        source_quality_rows.append({
            "source": _src,
            "total_items": _total,
            "curated_rate": _curated_rate,
            "avg_priority": _avg_ps,
            "std_priority": _std_ps,
            "cve_density": _cve_density,
            "topic_entropy": _entropy,
            "quality_score": 0.0,
        })

    for _row in source_quality_rows:
        _curated_c  = _row["curated_rate"] * 40.0
        _priority_c = (_row["avg_priority"] / 100.0) * 30.0
        _cve_c      = min(_row["cve_density"] / 30.0, 1.0) * 20.0
        _entropy_c  = (_row["topic_entropy"] / max(_max_entropy, 1e-9)) * 10.0
        _row["quality_score"] = round(_curated_c + _priority_c + _cve_c + _entropy_c, 2)

    source_quality_rows.sort(key=lambda r: r["quality_score"], reverse=True)

    # daily_volume ordenado
    daily_volume = [
        {"date": d, "count": int(daily_counter[d])}
        for d in sorted(daily_counter.keys())
    ]

    categories_out = {
        win: {k: int(v) for k, v in per_window_categories[win].most_common()}
        for win in WINDOWS
    }

    top_keywords_out = {
        win: counter_to_sorted_list(per_window_keywords[win])
        for win in WINDOWS
    }

    vendors_out = {
        win: counter_to_sorted_list(per_window_vendors[win])
        for win in WINDOWS
    }

    trending_terms_out: Dict[str, Dict[str, Any]] = {}
    for key, label in TRENDING_TERMS.items():
        counts_per_win = {}
        for win in WINDOWS:
            counts_per_win[win] = int(per_window_trends[win][key])
        trending_terms_out[key] = {
            "label": label,
            "counts": counts_per_win,
        }

    top_cves_out = {
        win: counter_to_sorted_list(per_window_cves[win])
        for win in WINDOWS
    }

    top_actors_out = {
        win: counter_to_sorted_list(per_window_actors[win])
        for win in WINDOWS
    }

    # Keyword velocity: keywords that grew most compared to the previous window
    keyword_velocity_out: Dict[str, List[Any]] = {}
    for win in WINDOWS:
        cur = per_window_keywords[win]
        prev = prev_window_keywords[win]
        velocity_rows: List[Any] = []
        for word, cur_count in cur.most_common(300):
            if cur_count < 3:
                continue
            prev_count = int(prev.get(word, 0))
            if prev_count == 0:
                growth = float(cur_count * 2)
            else:
                growth = round((cur_count - prev_count) / max(1, prev_count) * 100.0, 1)
            velocity_rows.append({
                "keyword": word,
                "current": int(cur_count),
                "previous": int(prev_count),
                "growth_pct": growth,
            })
        velocity_rows.sort(key=lambda x: x["growth_pct"], reverse=True)
        keyword_velocity_out[win] = velocity_rows[:20]

    # Threat actor timeline com top_actors para tooltip
    threat_actor_daily = []
    for d in sorted(threat_actor_daily_counter.keys()):
        total = int(threat_actor_daily_counter[d])
        names_counter = threat_actor_daily_names.get(d, Counter())
        top_names = [[name, int(cnt)] for name, cnt in names_counter.most_common(5)]
        threat_actor_daily.append({
            "date": d,
            "count": total,
            "top_actors": top_names,
        })

    cooccurrence_out = {
        "cve_vendor": {
            win: pair_counter_to_rows(co_cve_vendor[win], "cve", "vendor", limit=100)
            for win in WINDOWS
        },
        "actor_malware": {
            win: pair_counter_to_rows(co_actor_malware[win], "actor", "malware", limit=100)
            for win in WINDOWS
        },
        "category_category": {
            win: pair_counter_to_rows(co_category_category[win], "left_category", "right_category", limit=120)
            for win in WINDOWS
        },
    }

    delta_analytics = {
        "vendors": {
            win: build_delta_rows(per_window_vendors[win], prev_window_vendors[win], limit=25)
            for win in WINDOWS
        },
        "cves": {
            win: build_delta_rows(per_window_cves[win], prev_window_cves[win], limit=25)
            for win in WINDOWS
        },
        "threat_actors": {
            win: build_delta_rows(per_window_actors[win], prev_window_actors[win], limit=25)
            for win in WINDOWS
        },
    }

    priority_now_out: Dict[str, Dict[str, Any]] = {}
    for win in WINDOWS:
        rows = priority_now_rows[win]
        rows.sort(key=lambda r: (float(r["score"]), r.get("published") or ""), reverse=True)
        top_rows = rows[:PRIORITY_TOP_K]

        tier_counts = Counter([r.get("tier", "low") for r in rows])
        priority_now_out[win] = {
            "items": top_rows,
            "summary": {
                "total_items": len(rows),
                "critical": int(tier_counts.get("critical", 0)),
                "high": int(tier_counts.get("high", 0)),
                "medium": int(tier_counts.get("medium", 0)),
                "low": int(tier_counts.get("low", 0)),
            },
        }

    campaign_clusters_out: Dict[str, List[Dict[str, Any]]] = {}
    for win in WINDOWS:
        clusters = []
        prev_bucket = campaign_previous[win]
        for key, row in campaign_current[win].items():
            items_count = int(row["items_count"])
            if items_count < CAMPAIGN_MIN_ITEMS:
                continue

            avg_priority = float(row["priority_sum"]) / max(1, items_count)
            unique_cves = len(row["cves"])
            unique_actors = len(row["actors"])
            unique_malware = len(row["malware"])
            unique_vendors = len(row["vendors"])

            last_seen_dt = parse_iso(str(row["last_seen"]))
            age_hours = max(0.0, (now - last_seen_dt).total_seconds() / 3600.0)
            recency_bonus = max(0.0, 12.0 - min(12.0, age_hours / 4.0))

            campaign_score = (
                min(40.0, items_count * 6.0)
                + min(16.0, unique_cves * 6.0)
                + min(14.0, unique_actors * 7.0)
                + min(12.0, unique_malware * 6.0)
                + min(10.0, unique_vendors * 4.0)
                + recency_bonus
                + min(16.0, avg_priority * 0.2)
            )
            if unique_cves == 0 and unique_actors == 0:
                campaign_score -= 18.0
            if unique_cves == 0 and unique_actors == 0 and unique_vendors <= 1:
                campaign_score -= 8.0
            campaign_score = round(max(0.0, min(100.0, campaign_score)), 2)

            prev_count = int((prev_bucket.get(key) or {}).get("items_count", 0))
            delta = items_count - prev_count
            if prev_count == 0 and items_count > 0:
                trend_status = "new"
            elif delta > 0 and items_count >= int(max(1, prev_count * 1.5)):
                trend_status = "accelerating"
            elif delta > 0:
                trend_status = "persistent"
            elif delta < 0 and items_count > 0:
                trend_status = "cooling"
            elif delta < 0 and items_count == 0:
                trend_status = "dropped"
            else:
                trend_status = "persistent"

            cluster_view = {
                "cluster_id": key,
                "campaign_score": campaign_score,
                "tier": classify_priority_tier(campaign_score),
                "trend_status": trend_status,
                "items_count": items_count,
                "previous_items_count": prev_count,
                "delta_items": delta,
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "top_cves": top_counter_map(row["cves"], k=5),
                "top_actors": top_counter_map(row["actors"], k=5),
                "top_vendors": top_counter_map(row["vendors"], k=5),
                "top_malware": top_counter_map(row["malware"], k=5),
                "top_categories": top_counter_map(row["categories"], k=5),
                "top_titles": row["top_titles"][:4],
                "top_links": row["top_links"][:4],
                "avg_priority": round(avg_priority, 2),
                "curated_hits": int(row["curated_hits"]),
            }
            cluster_view["recommended_actions"] = build_campaign_actions(cluster_view)
            clusters.append(cluster_view)

        clusters.sort(
            key=lambda r: (
                float(r["campaign_score"]),
                int(r["items_count"]),
                float(r["avg_priority"]),
            ),
            reverse=True,
        )
        campaign_clusters_out[win] = clusters[:CLUSTER_TOP_K]

    output = {
        "generated_at": now.isoformat(),
        "windows": list(WINDOWS.keys()),
        "daily_volume": daily_volume,
        "categories": categories_out,
        "top_keywords": top_keywords_out,
        "keyword_velocity": keyword_velocity_out,
        "vendors": vendors_out,
        "trending_terms": trending_terms_out,
        "top_cves": top_cves_out,
        "top_actors": top_actors_out,
        "threat_actor_daily": threat_actor_daily,
        "cooccurrence": cooccurrence_out,
        "delta_analytics": delta_analytics,
        "priority_now": priority_now_out,
        "campaign_clusters": campaign_clusters_out,
        "source_quality": source_quality_rows,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Trends written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
