#!/usr/bin/env python3
"""
Sync S33R's feed inputs from clivoa/awesome-security-feeds.

The upstream repo keeps the full roster and daily health checks. S33R uses the
active-only OPML for ingestion, while Source Health can render the full catalog.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_BASE_URL = "https://raw.githubusercontent.com/clivoa/awesome-security-feeds/main/data"
DEFAULT_FEEDS_JSON_URL = f"{DEFAULT_BASE_URL}/feeds.json"
DEFAULT_FEED_STATUS_URL = f"{DEFAULT_BASE_URL}/feed_status.json"
DEFAULT_ACTIVE_OPML_URL = f"{DEFAULT_BASE_URL}/sec_feeds_active.xml"


def fetch_text(url: str, timeout: int) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "S33R-feed-sync/1.0 (+https://github.com/clivoa/S33R)",
            "Accept": "application/json, application/xml, text/xml, text/plain;q=0.8, */*;q=0.5",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as res:
        charset = res.headers.get_content_charset() or "utf-8"
        return res.read().decode(charset, errors="replace")


def load_json_url(url: str, timeout: int) -> Dict[str, Any]:
    text = fetch_text(url, timeout)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object from {url}")
    return data


def normalize_status(value: Any) -> str:
    status = str(value or "unknown").strip().lower()
    if status in {"ok", "healthy"}:
        return "active"
    if status in {"disabled", "inactive", "dead", "failed"}:
        return "down"
    if status in {"limited", "rate-limit", "ratelimited"}:
        return "rate_limited"
    if status in {"active", "down", "rate_limited", "unknown"}:
        return status
    return "unknown"


def count_opml_feeds(opml_text: str) -> int:
    try:
        root = ET.fromstring(opml_text)
    except ET.ParseError:
        return 0
    body = root.find("body")
    if body is None:
        return 0
    return sum(1 for node in body.iter("outline") if node.attrib.get("xmlUrl"))


def iter_feed_rows(feeds_data: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    rows = feeds_data.get("feeds", [])
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]


def build_catalog(
    feeds_data: Dict[str, Any],
    status_data: Dict[str, Any],
    active_opml_text: str,
    source_urls: Dict[str, str],
) -> Dict[str, Any]:
    status_results = status_data.get("results", {})
    if not isinstance(status_results, dict):
        status_results = {}

    now = datetime.now(timezone.utc).isoformat()
    feeds: List[Dict[str, Any]] = []
    status_counts: Dict[str, int] = {}

    for feed in iter_feed_rows(feeds_data):
        url = str(feed.get("url") or feed.get("xmlUrl") or feed.get("xml_url") or "").strip()
        if not url:
            continue

        status_info = status_results.get(url, {})
        if not isinstance(status_info, dict):
            status_info = {}

        source_status = normalize_status(status_info.get("status"))
        status_counts[source_status] = status_counts.get(source_status, 0) + 1

        title = str(feed.get("title") or feed.get("text") or url).strip()
        category = str(feed.get("category") or "General").strip()
        feed_type = str(feed.get("type") or "rss").strip().lower() or "rss"

        feeds.append(
            {
                "title": title,
                "url": url,
                "xml_url": url,
                "html_url": str(feed.get("htmlUrl") or feed.get("html_url") or url).strip(),
                "type": feed_type,
                "category": category,
                "description": str(feed.get("description") or "").strip(),
                "source_status": source_status,
                "ingest_enabled": source_status == "active",
                "http_status": status_info.get("http_status"),
                "error": status_info.get("error"),
                "bozo": status_info.get("bozo"),
                "entries": status_info.get("entries"),
                "final_url": status_info.get("final_url"),
                "content_type": status_info.get("content_type"),
                "latency_ms": status_info.get("latency_ms"),
                "consecutive_failures": status_info.get("consecutive_failures"),
                "down_since": status_info.get("down_since"),
                "last_seen_active": status_info.get("last_seen_active"),
            }
        )

    active_count = sum(1 for feed in feeds if feed["ingest_enabled"])
    return {
        "generated_at": now,
        "source": {
            "repository": "clivoa/awesome-security-feeds",
            "feeds_json_url": source_urls["feeds_json_url"],
            "feed_status_url": source_urls["feed_status_url"],
            "active_opml_url": source_urls["active_opml_url"],
        },
        "upstream": {
            "feeds_generated_at": feeds_data.get("generated_at"),
            "feed_status_checked_at": status_data.get("checked_at"),
            "total": status_data.get("total"),
            "active": status_data.get("active"),
            "down": status_data.get("down"),
            "rate_limited": status_data.get("rate_limited"),
        },
        "total_feeds": len(feeds),
        "active_feeds": active_count,
        "active_opml_feeds": count_opml_feeds(active_opml_text),
        "ingest_enabled_statuses": ["active"],
        "status_counts": status_counts,
        "feeds": feeds,
    }


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else f"{text}\n", encoding="utf-8")


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync active OPML and full source catalog for S33R.")
    parser.add_argument("--feeds-json-url", default=DEFAULT_FEEDS_JSON_URL)
    parser.add_argument("--feed-status-url", default=DEFAULT_FEED_STATUS_URL)
    parser.add_argument("--active-opml-url", default=DEFAULT_ACTIVE_OPML_URL)
    parser.add_argument("--out-opml", default=str(BASE_DIR / "sec_feeds.xml"))
    parser.add_argument("--out-catalog", default=str(BASE_DIR / "data" / "source_catalog.json"))
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        feeds_data = load_json_url(args.feeds_json_url, args.timeout)
        status_data = load_json_url(args.feed_status_url, args.timeout)
        active_opml_text = fetch_text(args.active_opml_url, args.timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        print(f"[ERROR] Could not sync upstream feed catalog: {exc}", file=sys.stderr)
        return 1

    catalog = build_catalog(
        feeds_data,
        status_data,
        active_opml_text,
        {
            "feeds_json_url": args.feeds_json_url,
            "feed_status_url": args.feed_status_url,
            "active_opml_url": args.active_opml_url,
        },
    )

    print(
        "[INFO] Synced feed catalog: "
        f"{catalog['active_feeds']} active / {catalog['total_feeds']} total "
        f"(active OPML entries: {catalog['active_opml_feeds']})"
    )

    if args.dry_run:
        return 0

    write_text(Path(args.out_opml), active_opml_text)
    write_json(Path(args.out_catalog), catalog)
    print(f"[INFO] Wrote active OPML to {args.out_opml}")
    print(f"[INFO] Wrote source catalog to {args.out_catalog}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
