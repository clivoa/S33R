#!/usr/bin/env python3
"""
Gera data/trends.json com métricas de tendências para o trend.html:

- Volume diário de notícias
- Breakdown por categoria (smart_groups / tags)
- Top keywords por janela (24h, 7d, 30d, 90d)
- Contagem por vendor por janela
- Tendências de termos de ataque (ransomware, supply chain, 0-day, etc.)
- Top CVEs por janela (para o ranking de CVEs)
- Linha do tempo de menções a threat actors (por dia),
  incluindo os top_actors por dia para tooltip.

Fonte de dados:
- data/news_recent.json
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

BASE_DIR = Path(__file__).resolve().parent.parent
NEWS_RECENT_PATH = BASE_DIR / "data" / "news_recent.json"
OUTPUT_PATH = BASE_DIR / "data" / "trends.json"

# Janelas usadas pelo front
WINDOWS = {
    "24h": 1,
    "7d": 7,
    "30d": 30,
    "90d": 90,
}

STOPWORDS = {
    # stopwords genéricas de linguagem
    "the", "and", "for", "with", "from", "this", "that", "have", "has",
    "into", "over", "under", "about", "your", "you", "are", "was", "were",
    "will", "their", "they", "them", "its", "our", "out", "but", "not",
    "can", "could", "would", "should", "may", "might", "than", "then",
    "after", "before", "more", "less", "also", "just", "into", "via",
    # termos muito genéricos de segurança / notícia
    "security", "cyber", "attack", "attacks", "threat", "threats",
    "vulnerability", "vulnerabilities", "report", "reports",
    "blog", "post", "news", "data",
    # palavras vazias comuns do feed
    "first", "all", "access", "based", "using", "used", "user", "users",
    "update", "updated", "updates", "detail", "details",
    # pedaços de URL / protocolo
    "http", "https", "www", "com",
}

KEYWORD_VENDOR_STOPWORDS = {
    "upguard",
    # "kaspersky", "crowdstrike", etc. se começarem a poluir
}


# Vendors simples (ajuste conforme necessário)
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

# Termos de "attack trends" que aparecerão no gráfico Emerging attack trends
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

# =========================================================
#  Threat actors
# =========================================================
# ⚠️ SUBSTITUA ESSA LISTA PELA SUA LISTA COMPLETA (threat_actors.txt)
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
    "Play",
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
    Constrói a lista de regexes para detecção de threat actors:
    - padrões genéricos (APTxx, TAxxx, UNCxxx, Storm-xxxx, FINxx, Threat Group-xxxx)
    - um padrão grande com todos os nomes conhecidos (THREAT_ACTOR_NAMES)
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

# Mapa canônico: lowercase -> nome oficial
CANONICAL_TA_MAP = {name.lower(): name for name in THREAT_ACTOR_NAMES}

# Regex único para extrair nomes de threat actors (sem padrões genéricos)
THREAT_ACTOR_NAME_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(name) for name in THREAT_ACTOR_NAMES) + r")\b",
    re.IGNORECASE,
)

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# =========================================================
#  Utilitários
# =========================================================

def parse_iso(date_str: str) -> datetime:
    """
    Faz parse de uma string de data (ISO-ish) e retorna datetime com timezone UTC.
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
    Carrega news_recent.json aceitando diferentes formatos:

    - Lista na raiz:
      [ {entry}, {entry}, ... ]

    - Objeto com chave contendo lista:
      { "entries": [ ... ] } ou "items"/"news"/"results"/"data"
    """
    print(f"[INFO] Loading {NEWS_RECENT_PATH}...")
    raw = NEWS_RECENT_PATH.read_text(encoding="utf-8")
    data = json.loads(raw)

    # Caso ideal: lista na raiz
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("entries", "items", "news", "results", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]

        # fallback: qualquer valor que seja lista de dicts
        for v in data.values():
            if isinstance(v, list) and (not v or isinstance(v[0], dict)):
                return v

        raise RuntimeError(
            "news_recent.json é um objeto, mas não encontrei uma lista de entradas "
            "em 'entries', 'items', 'news', 'results' ou 'data'."
        )

    raise RuntimeError(
        f"news_recent.json tem tipo raiz inesperado: {type(data).__name__}"
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
    Divide o texto em tokens simples, removendo:
    - stopwords
    - tokens muito curtos
    - números puros / anos (2024, 2025)
    - pedaços de URL (http, https, www, com)
    - alguns vendors que já aparecem em outro gráfico
    """
    for token in re.findall(r"[a-zA-Z0-9\-]+", text.lower()):
        # tamanho mínimo um pouco maior pra pegar termos mais "ricos"
        if len(token) < 4:
            continue

        if token in STOPWORDS:
            continue

        # ignorar números e anos
        if token.isdigit():
            continue
        if re.fullmatch(r"20\d{2}", token):
            continue

        # pedaços de URL (já cobertos em STOPWORDS, mas por garantia)
        if token in ("http", "https", "www", "com"):
            continue

        # vendors que queremos ver só no gráfico de Vendors
        if token in KEYWORD_VENDOR_STOPWORDS:
            continue

        yield token



def get_categories(entry: Dict[str, Any]) -> List[str]:
    """
    Tenta obter categorias / smart_groups da entrada.
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


# =========================================================
#  Main
# =========================================================

def main() -> None:
    news = load_news()
    now = datetime.now(timezone.utc)

    # Contadores agregados
    daily_counter = Counter()  # date_str -> total de notícias
    per_window_categories: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_keywords: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_vendors: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_trends: Dict[str, Counter] = {w: Counter() for w in WINDOWS}
    per_window_cves: Dict[str, Counter] = {w: Counter() for w in WINDOWS}

    # Threat actors
    threat_actor_daily_counter = Counter()          # date_str -> qtd notícias com actor
    threat_actor_daily_names: Dict[str, Counter] = defaultdict(Counter)  # date_str -> Counter(actor_name)

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

        # Volume diário
        daily_counter[date_only] += 1

        # 1) Detecção genérica de threat actor (APTxx, TAxxx, Storm-xxxx, etc.)
        has_actor = any(p.search(text) for p in threat_actor_compiled)
        if has_actor:
            threat_actor_daily_counter[date_only] += 1

        # 2) Extração de nomes concretos para top_actors
        name_matches = set(m.group(0) for m in THREAT_ACTOR_NAME_REGEX.finditer(text))
        for raw_name in name_matches:
            canonical = CANONICAL_TA_MAP.get(raw_name.lower(), raw_name)
            threat_actor_daily_names[date_only][canonical] += 1

        # Categorias
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

        # Aplicar em cada janela
        for win, days in WINDOWS.items():
            if not within_window(dt, now, days):
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

        processed += 1

    print(f"[INFO] Processed entries: {processed}, skipped (no date): {skipped_no_date}")

    # daily_volume ordenado
    daily_volume = [
        {"date": d, "count": int(daily_counter[d])}
        for d in sorted(daily_counter.keys())
    ]

    def counter_to_sorted_list(cnt: Counter) -> List[List[Any]]:
        return [[k, int(v)] for k, v in cnt.most_common()]

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

    output = {
        "generated_at": now.isoformat(),
        "windows": list(WINDOWS.keys()),
        "daily_volume": daily_volume,
        "categories": categories_out,
        "top_keywords": top_keywords_out,
        "vendors": vendors_out,
        "trending_terms": trending_terms_out,
        "top_cves": top_cves_out,
        "threat_actor_daily": threat_actor_daily,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] Trends written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
