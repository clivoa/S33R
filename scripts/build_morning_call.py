#!/usr/bin/env python3
"""
scripts/build_morning_call.py

Generate a daily "morning call" style analysis for SOC teams based on
data/news_recent.json, using the OpenAI API.

- news_recent.json format (current):
  {
    "generated_at": "...",
    "days_back": 30,
    "total_items": 4057,
    "items": [
      {
        "title": "...",
        "summary": "...",
        "link": "...",
        "source": "...",
        "type": "...",
        "type_label": "...",
        "published": "2025-12-10T10:07:03+00:00",
        "published_ts": 1765361223,
        "smart_groups": [...],
        "curated": true
      },
      ...
    ]
  }

- Output:
  - data/archive/morning_call_YYYY-MM-DD.json
  - data/archive/morning_call_latest.json
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from openai import OpenAI
from openai import OpenAI, APIError

# -----------------------
# Configuráveis
# -----------------------

NEWS_RECENT_PATH = Path(os.getenv("NEWS_JSON_PATH", "data/news_recent.json"))

# Janela padrão (horas)
DEFAULT_WINDOW_HOURS = int(os.getenv("MORNING_CALL_WINDOW_HOURS", "24"))

# Máximo de itens enviados para o modelo
MAX_ITEMS_FOR_CONTEXT = int(os.getenv("MORNING_CALL_MAX_ITEMS", "120"))

# Modelo da OpenAI usado para o morning call
OPENAI_MODEL = os.getenv("MORNING_CALL_MODEL", "gpt-5.1")

# Onde salvamos os morning calls (segue padrão de promo_filtered_*)
OUTPUT_BASE_DIR = Path(os.getenv("MORNING_CALL_OUTPUT_DIR", "data/archive"))


# -----------------------
# Funções auxiliares
# -----------------------

def load_news_recent(path: Path) -> Dict[str, Any]:
    """Carrega o news_recent.json no formato atual (wrapper com items)."""
    print(f"[INFO] Loading {path}...")
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict) or "items" not in data:
        raise ValueError("news_recent.json must be an object with an 'items' array")

    if not isinstance(data["items"], list):
        raise ValueError("'items' in news_recent.json must be a list")

    print(f"[INFO] Loaded {len(data['items'])} items from news_recent.json")
    return data


def filter_last_hours(items: List[Dict[str, Any]], hours: int) -> List[Dict[str, Any]]:
    """Filtra itens das últimas N horas baseado em published_ts (epoch)."""
    now_ts = int(time.time())
    cutoff = now_ts - hours * 3600
    print(f"[INFO] Filtering items newer than epoch={cutoff} (last {hours}h)")

    filtered: List[Dict[str, Any]] = []
    for it in items:
        ts = it.get("published_ts")
        if isinstance(ts, (int, float)) and ts >= cutoff:
            it["_published_ts"] = int(ts)
            filtered.append(it)

    # Ordena por mais recente primeiro
    filtered.sort(key=lambda x: x.get("_published_ts", 0), reverse=True)
    print(f"[INFO] {len(filtered)} items are within the last {hours} hours")
    return filtered


def filter_curated_only(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Retorna apenas itens com curated == True."""
    curated_items = [it for it in items if bool(it.get("curated"))]
    print(f"[INFO] Curated items within window: {len(curated_items)}")
    return curated_items


def build_context_snippet(items: List[Dict[str, Any]]) -> str:
    """
    Constrói um contexto compacto com as notícias para mandar pro modelo.

    Usa:
    - published_ts -> ISO UTC
    - source
    - title
    - link
    - smart_groups
    """
    lines: List[str] = []

    for idx, it in enumerate(items, start=1):
        ts = it.get("_published_ts") or it.get("published_ts")
        if isinstance(ts, (int, float)):
            dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
            published_str = dt_utc.strftime("%Y-%m-%d %H:%M:%SZ")
        else:
            published_str = it.get("published") or "N/A"

        title = (it.get("title") or "").strip()
        source = it.get("source") or "Unknown source"
        link = it.get("link") or "N/A"
        smart_groups = it.get("smart_groups") or []
        if isinstance(smart_groups, list):
            sg_str = ", ".join(smart_groups[:5])
        else:
            sg_str = str(smart_groups)

        lines.append(
            f"[{idx}] {published_str} | {source} | {title}\n"
            f"    Link: {link}\n"
            f"    Tags: {sg_str}"
        )

    return "\n".join(lines)


def build_system_prompt() -> str:
    """
    Persona do consultor para o modelo.
    """
    return (
        "You are a seasoned cybersecurity consultant and threat intelligence lead "
        "supporting a 24/7 SOC for a critical financial institution.\n"
        "You have:\n"
        "- Deep experience in incident response, threat hunting and cyber defense.\n"
        "- Strong understanding of MITRE ATT&CK, ransomware operations, exploitation "
        "of vulnerabilities, cloud security and financial sector threats.\n"
        "- The ability to quickly triage external news and translate it into concrete "
        "operational guidance for SOC analysts (L1-L3).\n\n"
        "Your goal: Based on the last 24 hours of external security news, produce a concise, "
        "action-oriented *morning call* in English for the SOC team.\n"
        "Always prioritize:\n"
        "- Threats with potential direct operational impact (exploitable CVEs, active campaigns,\n"
        "  0-days, ransomware groups, supply-chain incidents, critical vendor advisories, "
        "  financial-sector targeting).\n"
        "- Clear recommendations on monitoring, detections, and immediate actions.\n"
        "- Brevity and clarity. The audience will read this during shift handover."
    )


def build_user_prompt(context_snippet: str, hours: int, total_items: int) -> str:
    """
    Instruções detalhadas para o modelo, incluindo o contexto das notícias.
    """
    return (
        f"The following list summarizes curated security-related news items collected during the last "
        f"{hours} hours.\n"
        f"There are {total_items} curated items in that time window. A subset of them is listed below.\n\n"
        "NEWS CONTEXT (each item includes timestamp, source, title, link and tags):\n"
        "------------------------------------------------------------\n"
        f"{context_snippet}\n"
        "------------------------------------------------------------\n\n"
        "TASK:\n"
        "Write a *morning call* style briefing in English for a Security Operations Center (SOC) "
        "supporting critical financial services. Assume your audience are SOC L1–L3 analysts, "
        "incident responders and threat hunters.\n\n"
        "STRUCTURE YOUR ANSWER AS MARKDOWN WITH THE FOLLOWING SECTIONS:\n"
        "1. `### Executive Summary` – 2–4 bullet points summarizing the most important developments.\n"
        "2. `### High-priority items (immediate attention)` – Bullet list of the 3–7 most critical issues. "
        "For each one, include:\n"
        "   - What happened\n"
        "   - Why it matters operationally\n"
        "   - Recommended immediate actions for the SOC (e.g. detections to check, log sources to review,\n"
        "     CVEs to prioritize, vendors/products possibly affected).\n"
        "3. `### Monitoring & detection recommendations` – Practical guidance mapping news items to:\n"
        "   - Suggested log sources (EDR, firewall, VPN, email, cloud, IdP, etc.)\n"
        "   - Hunting ideas (MITRE ATT&CK techniques where relevant)\n"
        "4. `### Medium-term follow-ups` – Items that are important but not urgent for today "
        "(e.g. future patching, policy updates, awareness topics).\n\n"
        "CONSTRAINTS & STYLE:\n"
        "- Use concise bullet points, not long paragraphs.\n"
        "- Use a sober, professional tone (no hype).\n"
        "- If the information is incomplete or unclear, explicitly state assumptions.\n"
        "- Do NOT invent specific IOCs (hashes, IPs, domains) unless they are clearly given in the news items.\n"
        "- You may refer to news items generically (e.g. 'a critical RCE in a mainstream VPN appliance') "
        "instead of repeating full titles.\n"
        "- Focus on *operational impact* and *what the SOC should do today*."
    )


def call_openai_morning_call(
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    """
    Faz a chamada à OpenAI usando Chat Completions e retorna o texto do morning call.
    Em caso de insufficient_quota, retorna uma mensagem amigável em vez de quebrar o script.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable not set")

    client = OpenAI(api_key=api_key)

    print(f"[INFO] Calling OpenAI Chat Completions with model={model}...")
    try:
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )
        text = completion.choices[0].message.content
        print("[INFO] OpenAI response received.")
        return text
    except APIError as e:
        # Se estourar quota, não derruba o pipeline, gera uma mensagem fallback
        err_code = getattr(e, "code", None)
        if err_code == "insufficient_quota":
            print("[ERROR] OpenAI insufficient_quota: cannot generate morning call today.")
            return (
                "### Morning call not available\n\n"
                "The automated SOC morning call could not be generated today due to "
                "`insufficient_quota` on the OpenAI API key.\n\n"
                "Please check the OpenAI billing / quota settings and re-run once the "
                "API is available again.\n"
            )
        # outros erros ainda sobem
        raise


def save_output_json(
    morning_call_text: str,
    curated_window: List[Dict[str, Any]],
    total_window_all: int,
    all_items_count: int,
    hours: int,
    model: str,
    source_meta: Dict[str, Any],
) -> Path:
    """
    Salva:
      - data/archive/morning_call_YYYY-MM-DD.json
      - data/archive/morning_call_latest.json

    Inclui:
      - total_items_in_window_all: total de notícias (curated ou não) na janela
      - total_items_in_window_curated: quantas curated na janela
    """
    now = datetime.now(timezone.utc)
    generated_at = now.isoformat()
    analysis_date = now.date().isoformat()

    OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)

    daily_path = OUTPUT_BASE_DIR / f"morning_call_{analysis_date}.json"
    latest_path = OUTPUT_BASE_DIR / "morning_call_latest.json"

    highlights = []
    for it in curated_window[:10]:
        ts = it.get("_published_ts") or it.get("published_ts")
        if isinstance(ts, (int, float)):
            dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
            published_str = dt_utc.isoformat()
        else:
            published_str = it.get("published") or None

        highlights.append(
            {
                "title": it.get("title"),
                "link": it.get("link") or it.get("url"),
                "source": it.get("source"),
                "published_ts": it.get("published_ts"),
                "published": published_str,
                "smart_groups": it.get("smart_groups") or [],
                "curated": bool(it.get("curated", False)),
            }
        )

    payload = {
        "generated_at": generated_at,
        "window_hours": hours,
        "source_file": str(NEWS_RECENT_PATH),
        "source_generated_at": source_meta.get("generated_at"),
        "source_days_back": source_meta.get("days_back"),
        "source_total_items": source_meta.get("total_items"),
        "model": model,
        "analysis_date": analysis_date,
        "audience": "SOC (L1-L3) with critical operations",
        "language": "en",
        "total_items_considered": all_items_count,
        "total_items_in_window_all": total_window_all,
        "total_items_in_window_curated": len(curated_window),
        "morning_call_markdown": morning_call_text,
        "highlights": highlights,
    }

    # Snapshot diário
    with daily_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    # Alias "latest"
    with latest_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"[INFO] Morning call JSON written to {daily_path} and {latest_path}")
    return daily_path


# -----------------------
# Main
# -----------------------

def main() -> None:
    # 1) Carrega JSON completo (wrapper + items)
    news_data = load_news_recent(NEWS_RECENT_PATH)
    items = news_data.get("items", [])
    all_items_count = len(items)

    window_hours = DEFAULT_WINDOW_HOURS

    # 2) Filtra últimas N horas (todas as notícias)
    items_window_all = filter_last_hours(items, window_hours)
    total_window_all = len(items_window_all)

    # 3) Dentre essas, filtra apenas as curated
    curated_window = filter_curated_only(items_window_all)

    # Se não houver curated na janela, opcionalmente cai de volta para todas,
    # para não gerar um morning call vazio.
    if not curated_window:
        print("[WARN] No curated items found in the time window. "
              "Falling back to all items in window.")
        curated_window = items_window_all

    # 4) Limita o número de itens enviados ao modelo
    subset = curated_window[:MAX_ITEMS_FOR_CONTEXT]
    print(
        f"[INFO] Using {len(subset)} curated items out of {len(curated_window)} "
        f"for OpenAI context (MAX_ITEMS_FOR_CONTEXT={MAX_ITEMS_FOR_CONTEXT})"
    )

    context_snippet = build_context_snippet(subset)
    system_prompt = build_system_prompt()
    user_prompt = build_user_prompt(context_snippet, window_hours, len(curated_window))

    # 5) Chama OpenAI
    morning_call_text = call_openai_morning_call(
        model=OPENAI_MODEL,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )

    # 6) Salva JSON de saída
    save_output_json(
        morning_call_text=morning_call_text,
        curated_window=curated_window,
        total_window_all=total_window_all,
        all_items_count=all_items_count,
        hours=window_hours,
        model=OPENAI_MODEL,
        source_meta=news_data,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
