#!/usr/bin/env python3
"""
scripts/build_morning_call.py

Generates a SOC-oriented morning call from curated news items in data/news_recent.json.

- Supports GPT-5.1 and GPT-4.1 models.
- Handles multiple response formats (string, list-of-blocks, response_text).
- Filters curated items only.
- Saves:
    data/archive/morning_call_YYYY-MM-DD.json
    data/archive/morning_call_latest.json
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from openai import OpenAI, APIError


#
# -------------------------
# Config
# -------------------------
#

NEWS_RECENT_PATH = Path(os.getenv("NEWS_JSON_PATH", "data/news_recent.json"))

DEFAULT_WINDOW_HOURS = int(os.getenv("MORNING_CALL_WINDOW_HOURS", "24"))
MAX_ITEMS_FOR_CONTEXT = int(os.getenv("MORNING_CALL_MAX_ITEMS", "100"))
OPENAI_MODEL = os.getenv("MORNING_CALL_MODEL", "gpt-5.1")
OUTPUT_BASE_DIR = Path(os.getenv("MORNING_CALL_OUTPUT_DIR", "data/archive"))


#
# -------------------------
# Utilities
# -------------------------
#

def load_news_recent(path: Path) -> Dict[str, Any]:
    print(f"[INFO] Loading {path}...")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict) or "items" not in data:
        raise ValueError("news_recent.json must be an object containing 'items' list")

    print(f"[INFO] Loaded {len(data['items'])} items.")
    return data


def filter_last_hours(items: List[Dict[str, Any]], hours: int) -> List[Dict[str, Any]]:
    now_ts = int(time.time())
    cutoff = now_ts - hours * 3600
    print(f"[INFO] Filtering items newer than epoch={cutoff} (last {hours}h)")

    filtered = []
    for it in items:
        ts = it.get("published_ts")
        if isinstance(ts, (int, float)) and ts >= cutoff:
            it["_published_ts"] = int(ts)
            filtered.append(it)

    filtered.sort(key=lambda x: x["_published_ts"], reverse=True)
    print(f"[INFO] {len(filtered)} items in the last {hours} hours")
    return filtered


def filter_curated_only(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    curated = [it for it in items if bool(it.get("curated"))]
    print(f"[INFO] Curated items within window: {len(curated)}")
    return curated


def build_context_snippet(items: List[Dict[str, Any]]) -> str:
    lines = []
    for idx, it in enumerate(items, start=1):
        ts = it.get("_published_ts") or it.get("published_ts")
        if isinstance(ts, (int, float)):
            pdt = datetime.fromtimestamp(ts, tz=timezone.utc)
            published_str = pdt.strftime("%Y-%m-%d %H:%M:%SZ")
        else:
            published_str = it.get("published") or "N/A"

        title = it.get("title") or "(no title)"
        source = it.get("source") or "Unknown"
        link = it.get("link") or "N/A"
        groups = it.get("smart_groups") or []
        if isinstance(groups, list):
            groups_str = ", ".join(groups[:5])
        else:
            groups_str = str(groups)

        lines.append(
            f"[{idx}] {published_str} | {source} | {title}\n"
            f"    Link: {link}\n"
            f"    Tags: {groups_str}"
        )
    return "\n".join(lines)


#
# -------------------------
# Prompt Builders
# -------------------------
#

def build_system_prompt() -> str:
    """
    Persona do consultor para o modelo (SOC-friendly, mais conciso).
    """
    return (
        "You are a seasoned cybersecurity consultant and threat intelligence lead "
        "supporting a 24/7 SOC for a critical financial institution.\n"
        "You have:\n"
        "- Deep experience in incident response, threat hunting and cyber defense.\n"
        "- Strong understanding of MITRE ATT&CK, ransomware operations, exploitation "
        "  of vulnerabilities, cloud security and financial sector threats.\n"
        "- The ability to quickly triage external news and translate it into concrete "
        "  operational guidance for SOC analysts (L1–L3).\n\n"
        "Your goal: Based on the last 24 hours of external security news, produce a SHORT, "
        "highly actionable *morning call* in English for the SOC team.\n"
        "Always prioritize:\n"
        "- Threats with potential direct operational impact (exploitable CVEs, active campaigns,\n"
        "  0-days, ransomware groups, supply-chain incidents, critical vendor advisories,\n"
        "  financial-sector targeting).\n"
        "- Clear recommendations on monitoring, detections, and immediate actions.\n"
        "- Brevity and clarity. The audience will read this during a very time-constrained shift handover.\n\n"
        "IMPORTANT STYLE CONSTRAINTS:\n"
        "- Aim for a total length of roughly 600–900 words.\n"
        "- Use short bullet points (one or two lines each).\n"
        "- Avoid narrative paragraphs and repeated background details.\n"
        "- Group similar items together instead of describing each news item separately.\n"
    )




def build_user_prompt(context_snippet: str, hours: int, total_items: int) -> str:
    """
    Instruções detalhadas para o modelo, com foco em saída SOC-friendly e enxuta.
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
        "STRUCTURE YOUR ANSWER AS MARKDOWN WITH THE FOLLOWING SECTIONS (KEEP IT TIGHT AND FOCUSED):\n"
        "1. `### Executive Summary`\n"
        "   - 3 bullet points MAX summarizing the most important developments.\n"
        "\n"
        "2. `### High-priority items (immediate attention)`\n"
        "   - Focus on the TOP 3–5 issues only (do not list everything).\n"
        "   - For each issue, use EXACTLY three bullets:\n"
        "     - What happened (1 short line)\n"
        "     - Why it matters operationally (1 short line)\n"
        "     - Recommended immediate actions for the SOC today (1–2 short actions, same bullet)\n"
        "   - Group similar items together (e.g. 'several critical VPN CVEs') instead of repeating similar news.\n"
        "\n"
        "3. `### Monitoring & detection recommendations`\n"
        "   - 5–8 bullets MAX.\n"
        "   - Each bullet should map 1–2 relevant news themes to:\n"
        "     - Specific log sources (EDR, firewall, VPN, email, cloud, IdP, etc.)\n"
        "     - Optional MITRE ATT&CK technique IDs when they add value.\n"
        "   - Keep bullets short and practical (what to hunt / monitor TODAY).\n"
        "\n"
        "4. `### Medium-term follow-ups`\n"
        "   - 4–6 bullets MAX.\n"
        "   - Items that are important but not urgent for TODAY (patching backlog, policy updates, awareness, "
        "     hardening tasks, vendor follow-up, etc.).\n\n"
        "CONSTRAINTS & STYLE:\n"
        "- Use concise bullet points, not long paragraphs.\n"
        "- Avoid repeating the same background explanation for multiple items.\n"
        "- If many news items relate to the same theme (e.g. multiple ransomware posts), summarize them as a group.\n"
        "- If the information is incomplete or unclear, explicitly state assumptions.\n"
        "- Do NOT invent specific IOCs (hashes, IPs, domains) unless they are clearly given in the news items.\n"
        "- You may refer to news items generically (e.g. 'a critical RCE in a mainstream VPN appliance') "
        "instead of repeating full titles.\n"
        "- Focus on *operational impact* and *what the SOC should do today*."
    )



#
# -------------------------
# GPT-5.1 Safe Response Extractor
# -------------------------
#

def extract_text_from_response(resp) -> str:
    """
    GPT-5.1 may return:
      - string in message.content
      - list of {type: "text", text: "..."}
      - or response_text field
    """
    choice = resp.choices[0]

    # Case 1: message.content is string
    if isinstance(choice.message.content, str):
        return choice.message.content.strip()

    # Case 2: list of blocks (GPT-5.x)
    if isinstance(choice.message.content, list):
        parts = []
        for block in choice.message.content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "\n".join(parts).strip()

    # Case 3: response_text fallback
    if hasattr(choice, "response_text"):
        return choice.response_text.strip()

    return ""


#
# -------------------------
# GPT Call
# -------------------------
#

def call_openai_morning_call(model: str, system_prompt: str, user_prompt: str) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")

    client = OpenAI(api_key=api_key)

    print(f"[INFO] Calling OpenAI (Responses API) with model={model}...")

    try:
        resp = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            # aumentamos para dar mais espaço para o texto
            max_output_tokens=int(os.getenv("MORNING_CALL_MAX_OUTPUT_TOKENS", "3000")),
        )

        # Responses API: texto principal costuma vir aqui
        try:
            text = resp.output[0].content[0].text.strip()
        except Exception:
            text = ""

        if not text:
            return (
                "### Morning call unavailable\n\n"
                "No text returned by the model. Check API logs or try again with a smaller context window."
            )

        # Heurística simples: se termina em heading/bullet quebrado, avisa que pode estar truncado
        if text.strip().endswith("-") or text.strip().endswith("–"):
            text += (
                "\n\n---\n\n"
                "**[Note]** The morning call text may have been truncated due to output length limits. "
                "Consider reducing the number of items in context or increasing `max_output_tokens`."
            )

        return text

    except Exception as e:
        # se for quota, devolve mensagem amigável
        if hasattr(e, "code") and getattr(e, "code") == "insufficient_quota":
            print("[WARN] insufficient_quota from OpenAI")
            return (
                "### Morning call unavailable\n\n"
                "OpenAI API quota exceeded — morning call could not be generated today."
            )
        # demais erros, deixa estourar
        raise




#
# -------------------------
# Save Output JSON
# -------------------------
#

def save_output_json(
    morning_call: str,
    curated_items: List[Dict[str, Any]],
    total_items_all: int,
    window_hours: int,
    meta: Dict[str, Any],
) -> Path:

    now = datetime.now(timezone.utc)
    date_str = now.date().isoformat()
    generated_at = now.isoformat()

    OUTPUT_BASE_DIR.mkdir(parents=True, exist_ok=True)

    daily_path = OUTPUT_BASE_DIR / f"morning_call_{date_str}.json"
    latest_path = OUTPUT_BASE_DIR / "morning_call_latest.json"

    highlights = []
    for it in curated_items[:10]:
        ts = it.get("_published_ts")
        if ts:
            ts_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        else:
            ts_iso = it.get("published")

        highlights.append(
            {
                "title": it.get("title"),
                "link": it.get("link"),
                "source": it.get("source"),
                "published": ts_iso,
                "smart_groups": it.get("smart_groups") or [],
                "curated": bool(it.get("curated")),
            }
        )

    payload = {
        "generated_at": generated_at,
        "analysis_date": date_str,
        "model": OPENAI_MODEL,
        "window_hours": window_hours,
        "source_file": str(NEWS_RECENT_PATH),
        "source_generated_at": meta.get("generated_at"),
        "source_days_back": meta.get("days_back"),
        "source_total_items": meta.get("total_items"),
        "total_items_in_window_all": total_items_all,
        "total_items_in_window_curated": len(curated_items),
        "morning_call_markdown": morning_call,
        "highlights": highlights,
    }

    with daily_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    with latest_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"[INFO] Morning call saved → {daily_path}")
    print(f"[INFO] Updated alias → {latest_path}")
    return daily_path


#
# -------------------------
# Main
# -------------------------
#

def main():
    news = load_news_recent(NEWS_RECENT_PATH)
    items = news["items"]
    all_items_count = len(items)

    window_hours = DEFAULT_WINDOW_HOURS

    print("[INFO] Filtering last-hours window…")
    window_items = filter_last_hours(items, window_hours)
    total_window_all = len(window_items)

    curated = filter_curated_only(window_items)
    if not curated:
        print("[WARN] No curated items found — falling back to all items.")
        curated = window_items

    subset = curated[:MAX_ITEMS_FOR_CONTEXT]
    print(f"[INFO] Using {len(subset)} curated items for model context.")

    context = build_context_snippet(subset)
    sys_prompt = build_system_prompt()
    user_prompt = build_user_prompt(context, window_hours, len(curated))

    morning_call = call_openai_morning_call(OPENAI_MODEL, sys_prompt, user_prompt)

    save_output_json(
        morning_call=morning_call,
        curated_items=curated,
        total_items_all=total_window_all,
        window_hours=window_hours,
        meta=news,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
