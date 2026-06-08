#!/usr/bin/env python3
"""
scripts/build_morning_call.py

Generates a SOC-oriented morning call from high-signal news items in data/news_recent.json.

- Supports configurable providers: OpenAI (default), Anthropic/Claude, and Gemini.
- Builds a high-signal context led by curated items, with critical/high/watch fallbacks.
- Saves:
    data/morning_call_latest.json
    data/archive/morning_call_YYYY-MM-DD.json   (flat; later moved by build_news_archive.py)
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


#
# -------------------------
# Config
# -------------------------
#

SUPPORTED_PROVIDERS = {"openai", "anthropic", "gemini"}
PROVIDER_ALIASES = {
    "openai": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "gemini": "gemini",
    "google": "gemini",
}
DEFAULT_MODELS = {
    "openai": "gpt-5.2",
    "anthropic": "claude-sonnet-4-5",
    "gemini": "gemini-2.5-pro",
}


def normalize_provider(value: str) -> str:
    provider = (value or "openai").strip().lower()
    provider = PROVIDER_ALIASES.get(provider, provider)
    if provider not in SUPPORTED_PROVIDERS:
        supported = ", ".join(sorted(SUPPORTED_PROVIDERS))
        raise ValueError(f"Unsupported MORNING_CALL_PROVIDER={value!r}. Supported providers: {supported}")
    return provider


NEWS_RECENT_PATH = Path(os.getenv("NEWS_JSON_PATH", "data/news_recent.json"))

DEFAULT_WINDOW_HOURS = int(os.getenv("MORNING_CALL_WINDOW_HOURS", "24"))
MAX_ITEMS_FOR_CONTEXT = int(os.getenv("MORNING_CALL_MAX_ITEMS", "100"))
MIN_ITEMS_FOR_CONTEXT = int(os.getenv("MORNING_CALL_MIN_ITEMS", "40"))
MORNING_CALL_MIN_SIGNAL_SCORE = float(os.getenv("MORNING_CALL_MIN_SIGNAL_SCORE", "50"))
MORNING_CALL_MIN_WATCH_SIGNAL_SCORE = float(os.getenv("MORNING_CALL_MIN_WATCH_SIGNAL_SCORE", "35"))
MORNING_CALL_MIN_PRIORITY_SCORE = float(os.getenv("MORNING_CALL_MIN_PRIORITY_SCORE", "55"))
MORNING_CALL_SUMMARY_CHARS = int(os.getenv("MORNING_CALL_SUMMARY_CHARS", "360"))
MORNING_CALL_PROVIDER = normalize_provider(os.getenv("MORNING_CALL_PROVIDER", "openai"))
MORNING_CALL_MODEL = os.getenv("MORNING_CALL_MODEL") or DEFAULT_MODELS[MORNING_CALL_PROVIDER]
MORNING_CALL_MAX_OUTPUT_TOKENS = int(os.getenv("MORNING_CALL_MAX_OUTPUT_TOKENS", "3000"))
MORNING_CALL_API_TIMEOUT_SECONDS = int(os.getenv("MORNING_CALL_API_TIMEOUT_SECONDS", "120"))
ANTHROPIC_API_URL = os.getenv("ANTHROPIC_API_URL", "https://api.anthropic.com/v1/messages")
ANTHROPIC_VERSION = os.getenv("ANTHROPIC_VERSION", "2023-06-01")
GEMINI_API_URL_TEMPLATE = os.getenv(
    "GEMINI_API_URL",
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
)
OUTPUT_BASE_DIR = Path(os.getenv("MORNING_CALL_OUTPUT_DIR", "data/archive"))
MORNING_CALL_SELECTION_POLICY = "curated-plus-operational-signal-v1"
HIGH_SIGNAL_TIERS = {"critical", "high"}
WATCH_SIGNAL_TIERS = {"watch"}


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


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def compact_text(value: Any, limit: int) -> str:
    text = " ".join(str(value or "").split())
    if limit > 0 and len(text) > limit:
        return text[: max(0, limit - 3)].rstrip() + "..."
    return text


def item_identity(item: Dict[str, Any]) -> str:
    return str(item.get("link") or item.get("title") or id(item))


def signal_tier_rank(item: Dict[str, Any]) -> int:
    tier = str(item.get("signal_tier") or "").lower()
    return {
        "critical": 4,
        "high": 3,
        "watch": 2,
        "low": 1,
    }.get(tier, 0)


def morning_call_sort_key(item: Dict[str, Any]) -> Tuple[int, float, float, float, float, float]:
    ts = item.get("_published_ts") or item.get("published_ts")
    return (
        signal_tier_rank(item),
        to_float(item.get("signal_score")),
        1.0 if item.get("curated") else 0.0,
        to_float(item.get("priority_score")),
        to_float(item.get("source_quality_score")),
        to_float(ts),
    )


def is_morning_call_candidate(item: Dict[str, Any]) -> bool:
    tier = str(item.get("signal_tier") or "").lower()
    signal_score = to_float(item.get("signal_score"))
    return bool(item.get("curated")) or tier in HIGH_SIGNAL_TIERS or signal_score >= MORNING_CALL_MIN_SIGNAL_SCORE


def is_watch_fallback_candidate(item: Dict[str, Any]) -> bool:
    tier = str(item.get("signal_tier") or "").lower()
    signal_score = to_float(item.get("signal_score"))
    priority_score = to_float(item.get("priority_score"))
    return (
        tier in WATCH_SIGNAL_TIERS
        or signal_score >= MORNING_CALL_MIN_WATCH_SIGNAL_SCORE
        or priority_score >= MORNING_CALL_MIN_PRIORITY_SCORE
    )


def select_morning_call_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    candidates = [it for it in items if is_morning_call_candidate(it)]
    selected: List[Dict[str, Any]] = []
    seen = set()

    def add(item: Dict[str, Any]) -> None:
        if len(selected) >= MAX_ITEMS_FOR_CONTEXT:
            return
        key = item_identity(item)
        if key in seen:
            return
        seen.add(key)
        selected.append(item)

    for item in sorted(candidates, key=morning_call_sort_key, reverse=True):
        add(item)

    minimum_context = min(MAX_ITEMS_FOR_CONTEXT, max(0, MIN_ITEMS_FOR_CONTEXT))
    if len(selected) < minimum_context:
        print(
            "[INFO] Morning call context below target; adding watch/high-priority fallback items "
            f"({len(selected)}/{minimum_context})."
        )
        fallback_pool = [
            it
            for it in items
            if item_identity(it) not in seen and is_watch_fallback_candidate(it)
        ]
        for item in sorted(fallback_pool, key=morning_call_sort_key, reverse=True):
            add(item)
            if len(selected) >= minimum_context:
                break

    if len(selected) < minimum_context:
        print(
            "[INFO] Morning call context still below target; adding best remaining recent items "
            f"({len(selected)}/{minimum_context})."
        )
        remaining_pool = [it for it in items if item_identity(it) not in seen]
        for item in sorted(remaining_pool, key=morning_call_sort_key, reverse=True):
            add(item)
            if len(selected) >= minimum_context:
                break

    if not selected and items:
        print("[WARN] No high-signal morning call candidates found; falling back to newest items.")
        for item in sorted(items, key=morning_call_sort_key, reverse=True):
            add(item)

    print(
        "[INFO] Morning call context selection: "
        f"policy={MORNING_CALL_SELECTION_POLICY}, candidates={len(candidates)}, selected={len(selected)}"
    )
    return selected


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
        signal_tier = it.get("signal_tier") or "n/a"
        signal_score = it.get("signal_score")
        priority_score = it.get("priority_score")
        groups = it.get("smart_groups") or []
        if isinstance(groups, list):
            groups_str = ", ".join(groups[:5])
        else:
            groups_str = str(groups)
        reasons = it.get("curation_reasons") or it.get("signal_reasons") or []
        if isinstance(reasons, list):
            reasons_str = ", ".join(str(r) for r in reasons[:4])
        else:
            reasons_str = str(reasons)
        summary = compact_text(it.get("summary"), MORNING_CALL_SUMMARY_CHARS)

        item_lines = [
            f"[{idx}] {published_str} | {source} | {title}\n"
            f"    Link: {link}\n"
            f"    Signal: tier={signal_tier}, score={signal_score}, priority={priority_score}, "
            f"curated={'yes' if it.get('curated') else 'no'}\n"
            f"    Tags: {groups_str}"
        ]
        if reasons_str:
            item_lines.append(f"    Reasons: {reasons_str}")
        if summary:
            item_lines.append(f"    Summary: {summary}")
        lines.append("\n".join(item_lines))
    return "\n".join(lines)


#
# -------------------------
# Prompt Builders
# -------------------------
#

def build_system_prompt() -> str:
    """
    Consultant persona for the model (SOC-friendly and concise).
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




def build_user_prompt(
    context_snippet: str,
    hours: int,
    selected_items: int,
    total_window_items: int,
    curated_items: int,
) -> str:
    """
    Detailed model instructions focused on concise SOC-friendly output.
    """
    return (
        f"The following list summarizes selected high-signal security news items collected during the last "
        f"{hours} hours.\n"
        f"There are {total_window_items} total items and {curated_items} curated items in that time window. "
        f"The {selected_items} items below were selected for briefing context using "
        f"`{MORNING_CALL_SELECTION_POLICY}`: curated items plus critical/high operational-signal items, "
        "with watch-level fallbacks if the context would otherwise be too small.\n\n"
        "NEWS CONTEXT (each item includes timestamp, source, title, link, signal, tags and summary):\n"
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
# Model Provider Calls
# -------------------------
#


def require_env(name: str, fallback_names: Optional[List[str]] = None) -> str:
    names = [name] + (fallback_names or [])
    for candidate in names:
        value = os.getenv(candidate)
        if value:
            return value
    joined = " or ".join(names)
    raise RuntimeError(f"{joined} not set")


def post_json(url: str, headers: Dict[str, str], payload: Dict[str, Any], provider_label: str) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=MORNING_CALL_API_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{provider_label} API HTTP {exc.code}: {error_body[:1000]}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{provider_label} API returned non-JSON response: {raw[:1000]}") from exc

    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(f"{provider_label} API error: {data['error']}")

    return data


def unavailable_message(reason: str) -> str:
    return (
        "### Morning call unavailable\n\n"
        f"{reason} Check API logs or try again with a smaller context window."
    )


def ensure_not_truncated(text: str) -> str:
    if text.strip().endswith("-") or text.strip().endswith("–"):
        text += (
            "\n\n---\n\n"
            "**[Note]** The morning call text may have been truncated due to output length limits. "
            "Consider reducing the number of items in context or increasing `MORNING_CALL_MAX_OUTPUT_TOKENS`."
        )
    return text


def extract_openai_text(resp: Any) -> str:
    output_text = getattr(resp, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    try:
        parts = []
        for item in resp.output:
            for content in getattr(item, "content", []) or []:
                text = getattr(content, "text", None)
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts).strip()
    except Exception:
        return ""


def extract_anthropic_text(data: Dict[str, Any]) -> str:
    parts = []
    for block in data.get("content", []) or []:
        if isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text") or ""))
    return "\n".join(parts).strip()


def extract_gemini_text(data: Dict[str, Any]) -> str:
    parts = []
    for candidate in data.get("candidates", []) or []:
        content = candidate.get("content") or {}
        for part in content.get("parts", []) or []:
            text = part.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts).strip()


def call_openai_morning_call(model: str, system_prompt: str, user_prompt: str) -> str:
    api_key = require_env("OPENAI_API_KEY")

    from openai import OpenAI

    client_kwargs: Dict[str, Any] = {"api_key": api_key}
    base_url = os.getenv("OPENAI_BASE_URL")
    if base_url:
        client_kwargs["base_url"] = base_url

    client = OpenAI(**client_kwargs)

    print(f"[INFO] Calling OpenAI (Responses API) with model={model}...")

    try:
        resp = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_output_tokens=MORNING_CALL_MAX_OUTPUT_TOKENS,
        )

        text = extract_openai_text(resp)
        if not text:
            return unavailable_message("No text returned by the model.")

        return ensure_not_truncated(text)

    except Exception as e:
        # For quota errors, return a friendly message in the generated artifact.
        if hasattr(e, "code") and getattr(e, "code") == "insufficient_quota":
            print("[WARN] insufficient_quota from OpenAI")
            return (
                "### Morning call unavailable\n\n"
                "OpenAI API quota exceeded — morning call could not be generated today."
            )
        # Let other errors bubble up.
        raise


def call_anthropic_morning_call(model: str, system_prompt: str, user_prompt: str) -> str:
    api_key = require_env("ANTHROPIC_API_KEY")
    print(f"[INFO] Calling Anthropic Messages API with model={model}...")

    data = post_json(
        ANTHROPIC_API_URL,
        {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        },
        {
            "model": model,
            "max_tokens": MORNING_CALL_MAX_OUTPUT_TOKENS,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        },
        "Anthropic",
    )

    text = extract_anthropic_text(data)
    if not text:
        return unavailable_message("No text returned by the model.")
    return ensure_not_truncated(text)


def call_gemini_morning_call(model: str, system_prompt: str, user_prompt: str) -> str:
    api_key = require_env("GEMINI_API_KEY", ["GOOGLE_API_KEY"])
    print(f"[INFO] Calling Gemini generateContent API with model={model}...")

    model_path = urllib.parse.quote(model, safe="")
    url = GEMINI_API_URL_TEMPLATE.format(model=model_path)
    separator = "&" if "?" in url else "?"
    url = f"{url}{separator}key={urllib.parse.quote(api_key, safe='')}"

    data = post_json(
        url,
        {"Content-Type": "application/json"},
        {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"maxOutputTokens": MORNING_CALL_MAX_OUTPUT_TOKENS},
        },
        "Gemini",
    )

    text = extract_gemini_text(data)
    if not text:
        return unavailable_message("No text returned by the model.")
    return ensure_not_truncated(text)


def call_morning_call_model(provider: str, model: str, system_prompt: str, user_prompt: str) -> str:
    if provider == "openai":
        return call_openai_morning_call(model, system_prompt, user_prompt)
    if provider == "anthropic":
        return call_anthropic_morning_call(model, system_prompt, user_prompt)
    if provider == "gemini":
        return call_gemini_morning_call(model, system_prompt, user_prompt)
    raise ValueError(f"Unsupported provider: {provider}")


#
# -------------------------
# Save Output JSON
# -------------------------
#

def save_output_json(
    morning_call: str,
    context_items: List[Dict[str, Any]],
    total_items_all: int,
    total_items_curated: int,
    window_hours: int,
    meta: Dict[str, Any],
) -> Path:

    now = datetime.now(timezone.utc)
    date_str = now.date().isoformat()
    generated_at = now.isoformat()

    archive_dir = OUTPUT_BASE_DIR  # Defaults to data/archive.
    archive_dir.mkdir(parents=True, exist_ok=True)

    daily_path = archive_dir / f"morning_call_{date_str}.json"
    latest_path = Path("data/morning_call_latest.json")
    latest_path.parent.mkdir(parents=True, exist_ok=True)


    highlights = []
    for it in context_items[:10]:
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
                "signal_tier": it.get("signal_tier"),
                "signal_score": it.get("signal_score"),
                "priority_score": it.get("priority_score"),
            }
        )

    payload = {
        "generated_at": generated_at,
        "analysis_date": date_str,
        "provider": MORNING_CALL_PROVIDER,
        "model": MORNING_CALL_MODEL,
        "window_hours": window_hours,
        "source_file": str(NEWS_RECENT_PATH),
        "source_generated_at": meta.get("generated_at"),
        "source_days_back": meta.get("days_back"),
        "source_total_items": meta.get("total_items"),
        "total_items_in_window_all": total_items_all,
        "total_items_in_window_curated": total_items_curated,
        "total_items_in_window_selected": len(context_items),
        "context_selection_policy": MORNING_CALL_SELECTION_POLICY,
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

    window_hours = DEFAULT_WINDOW_HOURS

    print("[INFO] Filtering last-hours window…")
    window_items = filter_last_hours(items, window_hours)
    total_window_all = len(window_items)

    curated = filter_curated_only(window_items)
    context_items = select_morning_call_items(window_items)
    print(f"[INFO] Using {len(context_items)} selected items for model context.")

    context = build_context_snippet(context_items)
    sys_prompt = build_system_prompt()
    user_prompt = build_user_prompt(
        context_snippet=context,
        hours=window_hours,
        selected_items=len(context_items),
        total_window_items=total_window_all,
        curated_items=len(curated),
    )

    print(f"[INFO] Morning call provider={MORNING_CALL_PROVIDER}, model={MORNING_CALL_MODEL}")
    morning_call = call_morning_call_model(MORNING_CALL_PROVIDER, MORNING_CALL_MODEL, sys_prompt, user_prompt)

    save_output_json(
        morning_call=morning_call,
        context_items=context_items,
        total_items_all=total_window_all,
        total_items_curated=len(curated),
        window_hours=window_hours,
        meta=news,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
