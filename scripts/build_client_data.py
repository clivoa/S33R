#!/usr/bin/env python3
"""Build small, browser-oriented datasets from ``news_recent.json``.

The ingestion dataset intentionally keeps rich records for archive and analytics
jobs.  The live dashboard does not need all of those fields up front, so this
script creates non-overlapping, progressively loaded feed segments plus a
metadata-only source-health payload.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
INPUT_PATH = DATA_DIR / "news_recent.json"
LATEST_PATH = DATA_DIR / "news_feed.json"
HOURS_72_PATH = DATA_DIR / "news_feed_72h.json"
WEEK_PATH = DATA_DIR / "news_feed_7d.json"
SOURCE_HEALTH_PATH = DATA_DIR / "source_health.json"
SUMMARY_MAX_CHARS = int(os.environ.get("CLIENT_SUMMARY_MAX_CHARS", "600"))

CLIENT_ITEM_FIELDS = (
    "title",
    "summary",
    "link",
    "source",
    "type",
    "published_ts",
    "smart_groups",
    "curated",
    "curation_reasons",
    "source_quality_score",
    "signal_score",
    "signal_tier",
    "priority_score",
)


def parse_generated_at(value: Any) -> float:
    if not value:
        return datetime.now(timezone.utc).timestamp()
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


def compact_item(item: Dict[str, Any]) -> Dict[str, Any]:
    compact = {key: item[key] for key in CLIENT_ITEM_FIELDS if key in item}
    summary = str(compact.get("summary") or "")
    if SUMMARY_MAX_CHARS > 0 and len(summary) > SUMMARY_MAX_CHARS:
        compact["summary"] = summary[:SUMMARY_MAX_CHARS].rstrip() + "…"
    return compact


def in_window(items: Iterable[Dict[str, Any]], start: float, end: float | None) -> List[Dict[str, Any]]:
    selected = []
    for item in items:
        timestamp = item.get("published_ts")
        if not isinstance(timestamp, (int, float)) or timestamp < start:
            continue
        if end is not None and timestamp >= end:
            continue
        selected.append(compact_item(item))
    return selected


def dump(path: Path, payload: Dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    path.write_text(text, encoding="utf-8")
    print(f"[OK] Wrote {path.relative_to(BASE_DIR)} ({len(text.encode('utf-8'))} bytes)")


def dashboard_stats(items: List[Dict[str, Any]], reference_ts: float) -> Dict[str, Any]:
    cves = set()
    high_signal = 0
    for item in items:
        tier = str(item.get("signal_tier") or "").lower()
        score = float(item.get("signal_score") or item.get("priority_score") or 0)
        if tier in {"critical", "high"} or (not tier and score >= 90 and item.get("curated")):
            high_signal += 1
        text = f"{item.get('title') or ''} {item.get('summary') or ''}".upper()
        cves.update(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text))

    return {
        "total_items": len(items),
        "items_24h": sum((item.get("published_ts") or 0) >= reference_ts - 24 * 3600 for item in items),
        "items_7d": sum((item.get("published_ts") or 0) >= reference_ts - 7 * 24 * 3600 for item in items),
        "high_signal_items": high_signal,
        "unique_cves": len(cves),
    }


def main() -> None:
    if not INPUT_PATH.exists():
        raise SystemExit(f"Input file not found: {INPUT_PATH}")

    data = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    items = data.get("items") or []
    if not isinstance(items, list):
        raise SystemExit("news_recent.json must contain an 'items' list")

    generated_at = data.get("generated_at")
    reference_ts = parse_generated_at(generated_at)
    common = {
        "generated_at": generated_at,
        "source_catalog": data.get("source_catalog"),
    }

    latest = in_window(items, reference_ts - 24 * 3600, None)
    hours_72 = in_window(items, reference_ts - 72 * 3600, reference_ts - 24 * 3600)
    week = in_window(items, reference_ts - 7 * 24 * 3600, reference_ts - 72 * 3600)

    dump(LATEST_PATH, {
        **common,
        "window": {"from_hours": 0, "to_hours": 24},
        "feed_stats": dashboard_stats(items, reference_ts),
        "items": latest,
    })
    dump(HOURS_72_PATH, {
        "generated_at": generated_at,
        "window": {"from_hours": 24, "to_hours": 72},
        "items": hours_72,
    })
    dump(WEEK_PATH, {
        "generated_at": generated_at,
        "window": {"from_hours": 72, "to_hours": 168},
        "items": week,
    })
    dump(SOURCE_HEALTH_PATH, {
        **common,
        "source_quality": data.get("source_quality") or [],
        "feed_attempts": data.get("feed_attempts") or [],
    })


if __name__ == "__main__":
    main()
