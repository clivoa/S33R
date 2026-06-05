#!/usr/bin/env python3
"""
Build data/morning_call_index.json from all archived morning call JSONs.

Produces a searchable index with:
- Date, model, word count per entry
- Extracted executive summary (first 500 chars, plain text)
- Structured highlights
- Full markdown (for client-side full-text search and rendering)
"""

import json
import re
import glob
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
MC_DIR = BASE_DIR / "data" / "archive" / "morning_call"
OUTPUT_PATH = BASE_DIR / "data" / "morning_call_index.json"


def extract_exec_summary(markdown: str, max_chars: int = 500) -> str:
    lines = markdown.split("\n")
    capture = False
    summary_lines: List[str] = []
    for line in lines:
        if re.match(r"^#{1,3}\s*executive summary", line, re.IGNORECASE):
            capture = True
            continue
        if capture:
            if re.match(r"^#{1,3}\s", line):
                break
            stripped = line.strip()
            if stripped:
                summary_lines.append(stripped)
    raw = " ".join(summary_lines)
    # Strip markdown formatting
    raw = re.sub(r"\*\*(.+?)\*\*", r"\1", raw)
    raw = re.sub(r"\*(.+?)\*", r"\1", raw)
    raw = re.sub(r"`(.+?)`", r"\1", raw)
    raw = re.sub(r"\[(.+?)\]\(.+?\)", r"\1", raw)
    raw = re.sub(r"^[-*]\s+", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw[:max_chars]


def extract_cves(text: str) -> List[str]:
    return sorted({m.upper() for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.IGNORECASE)})


def main() -> None:
    mc_files = sorted(glob.glob(str(MC_DIR / "**" / "*.json"), recursive=True))

    entries: List[Dict[str, Any]] = []
    seen_dates: set = set()

    for f in mc_files:
        path = Path(f)
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[WARN] Could not read {path}: {exc}")
            continue

        date: Optional[str] = d.get("analysis_date") or path.stem.replace("morning_call_", "")
        if not date or not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
            continue
        if date in seen_dates:
            continue
        seen_dates.add(date)

        markdown = d.get("morning_call_markdown", "")
        highlights = d.get("highlights") or []
        cves_in_markdown = extract_cves(markdown)

        entries.append({
            "date": date,
            "generated_at": d.get("generated_at"),
            "provider": d.get("provider", "openai" if d.get("model") else ""),
            "model": d.get("model", ""),
            "window_hours": d.get("window_hours", 24),
            "total_items": d.get("total_items_in_window_all") or d.get("source_total_items", 0),
            "curated_items": d.get("total_items_in_window_curated", 0),
            "exec_summary": extract_exec_summary(markdown),
            "cves": cves_in_markdown[:10],
            "highlights": highlights[:8],
            "markdown": markdown,
            "word_count": len(markdown.split()),
        })

    entries.sort(key=lambda x: x["date"], reverse=True)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(entries),
        "date_range": {
            "oldest": entries[-1]["date"] if entries else None,
            "newest": entries[0]["date"] if entries else None,
        },
        "entries": entries,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Written {len(entries)} entries to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
