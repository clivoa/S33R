#!/usr/bin/env python3
"""
build_news_archive.py

Lê data/news_recent.json (estrutura:
{
  "generated_at": "...",
  "days_back": 30,
  "total_items": ...,
  "items": [ ... ]
}
)
e atualiza arquivos de arquivo mensal e anual em:

- data/archive/monthly/<ano>/<ano>-<mes>.json
- data/archive/yearly/<ano>.json

Cada arquivo é uma LISTA de itens (mesma estrutura de item do news_recent.json).
O script é idempotente: pode rodar todo dia sem duplicar notícias.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Caminhos base
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RECENT_PATH = DATA_DIR / "news_recent.json"

ARCHIVE_DIR = DATA_DIR / "archive"
MONTHLY_DIR = ARCHIVE_DIR / "monthly"
YEARLY_DIR = ARCHIVE_DIR / "yearly"


# ---------- Utilidades de I/O ----------

def load_json_any(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_json_list(path: Path, root_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Carrega um JSON e retorna uma lista de itens.

    - Se for uma lista na raiz, retorna direto.
    - Se for um dict com a chave `root_key` (ou 'items' por padrão), retorna essa lista.
    """
    if not path.exists():
        return []

    data = load_json_any(path)

    # Caso mais simples: já é lista
    if isinstance(data, list):
        return data

    # Caso dict (como news_recent.json)
    if isinstance(data, dict):
        # se root_key foi informado, tentar ela primeiro
        if root_key and isinstance(data.get(root_key), list):
            return data[root_key]

        # fallback padrão para "items"
        if isinstance(data.get("items"), list):
            return data["items"]

        raise ValueError(
            f"Esperado lista ou dict com chave 'items' em {path}, "
            f"mas encontrei dict com chaves: {list(data.keys())}"
        )

    raise ValueError(f"Esperado lista ou dict em {path}, mas encontrei {type(data)}")


def save_json_list(path: Path, items: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


# ---------- Parser de datas ----------

def parse_published_dt(item: Dict[str, Any]) -> Optional[datetime]:
    """
    Converte os campos de data do item em datetime com timezone UTC.

    news_recent.json tem:
      - published_ts: epoch seconds (int)
      - published: "2025-11-29T22:15:46+00:00" (ou None)

    Ordem:
      1) usar published_ts se estiver preenchido
      2) usar published em ISO-8601
      3) se nada der certo, retorna None
    """
    # 1) published_ts
    ts = item.get("published_ts")
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            pass

    # 2) published (string ISO)
    published = item.get("published")
    if isinstance(published, str) and published.strip():
        s = published.strip()
        # normaliza Z -> +00:00 se aparecer
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"

        # Tentar fromisoformat primeiro
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            # fallback: tentar alguns formatos comuns se algum feed vier diferente
            fmts = [
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S",
            ]
            for fmt in fmts:
                try:
                    dt = datetime.strptime(s, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

    # Sem data confiável
    return None


# ---------- Lógica de bucketização ----------

def bucket_items_by_month(items: List[Dict[str, Any]]) -> Dict[Tuple[int, int], List[Dict[str, Any]]]:
    buckets: Dict[Tuple[int, int], List[Dict[str, Any]]] = defaultdict(list)

    for item in items:
        dt = parse_published_dt(item)
        if not dt:
            # sem data; pular para não quebrar o arquivo mensal
            continue
        buckets[(dt.year, dt.month)].append(item)

    return buckets


def bucket_items_by_year(items: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    buckets: Dict[int, List[Dict[str, Any]]] = defaultdict(list)

    for item in items:
        dt = parse_published_dt(item)
        if not dt:
            continue
        buckets[dt.year].append(item)

    return buckets


# ---------- Deduplicação e ordenação ----------

def merge_and_dedup(existing: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Junta listas existente + nova, deduplicando principalmente por `link`.
    Se não tiver link, tenta (title, source) como fallback.
    """
    merged: Dict[Any, Dict[str, Any]] = {}

    def key_for(item: Dict[str, Any]) -> Any:
        link = item.get("link")
        if link:
            return ("link", link)
        return ("title_source", item.get("title"), item.get("source"))

    for item in existing + new:
        k = key_for(item)
        merged[k] = item

    result = list(merged.values())

    # Ordena por published_ts (desc) se existir, ou published_dt
    def sort_key(it: Dict[str, Any]):
        dt = parse_published_dt(it)
        if dt:
            return dt.timestamp()
        ts = it.get("published_ts")
        if isinstance(ts, (int, float)):
            return float(ts)
        return 0.0

    result.sort(key=sort_key, reverse=True)
    return result


# ---------- Função principal ----------

def main() -> None:
    if not RECENT_PATH.exists():
        raise FileNotFoundError(f"Arquivo recente não encontrado: {RECENT_PATH}")

    # news_recent.json é um dict com "items"
    recent_items = load_json_list(RECENT_PATH, root_key="items")
    print(f"[INFO] Carregados {len(recent_items)} itens recentes de {RECENT_PATH}")

    if not recent_items:
        print("[INFO] Nenhum item recente para arquivar. Encerrando.")
        return

    # Buckets por mês e ano
    monthly_buckets = bucket_items_by_month(recent_items)
    yearly_buckets = bucket_items_by_year(recent_items)

    # --------- Atualiza arquivos mensais ---------
    for (year, month), items in sorted(monthly_buckets.items()):
        year_str = f"{year}"
        month_str = f"{month:02d}"

        month_dir = MONTHLY_DIR / year_str
        month_path = month_dir / f"{year_str}-{month_str}.json"

        existing = load_json_list(month_path)
        merged = merge_and_dedup(existing, items)
        save_json_list(month_path, merged)

        print(
            f"[INFO] Arquivo mensal atualizado: {month_path} "
            f"(+{len(items)} itens, total {len(merged)})"
        )

    # --------- Atualiza arquivos anuais ---------
    for year, items in sorted(yearly_buckets.items()):
        year_str = f"{year}"
        year_path = YEARLY_DIR / f"{year_str}.json"

        existing = load_json_list(year_path)
        merged = merge_and_dedup(existing, items)
        save_json_list(year_path, merged)

        print(
            f"[INFO] Arquivo anual atualizado: {year_path} "
            f"(+{len(items)} itens, total {len(merged)})"
        )

    print("[INFO] build_news_archive.py concluído com sucesso.")


if __name__ == "__main__":
    main()
