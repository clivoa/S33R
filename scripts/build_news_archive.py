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
O script é idempotente: pode ser executado várias vezes, pois faz merge + dedup.

Além disso, processa arquivos de debug `promo_filtered_*.json` gerados pelo
build_news_json.py, agregando-os em arquivos mensais de promo:

- data/archive/promo/monthly/<ano>/promo_<ano>-<mes>.json

Após o processamento, os arquivos `data/archive/promo_filtered_*.json` são apagados.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from json import JSONDecodeError


# Caminhos base
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RECENT_PATH = DATA_DIR / "news_recent.json"

ARCHIVE_DIR = DATA_DIR / "archive"
MONTHLY_DIR = ARCHIVE_DIR / "monthly"
YEARLY_DIR = ARCHIVE_DIR / "yearly"
ARCHIVE_INDEX_PATH = ARCHIVE_DIR / "archive_index.json"
ARCHIVE_GLOBAL_INDEX_PATH = ARCHIVE_DIR / "index.json"

PROMO_DIR = ARCHIVE_DIR / "promo"
PROMO_MONTHLY_DIR = PROMO_DIR / "monthly"

MORNING_CALL_DIR = ARCHIVE_DIR / "morning_call"


# ---------- Utilidades de I/O ----------



def load_json_any(path: Path) -> Any:
    if not path.exists():
        return None

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"[WARN] Falha ao ler {path}: {e}")
        return None

    # Arquivo existe mas está vazio / whitespace
    if not raw.strip():
        print(f"[WARN] JSON vazio em {path}. Tratando como 'None'.")
        return None

    try:
        return json.loads(raw)
    except JSONDecodeError as e:
        # Renomeia o arquivo corrompido para não quebrar execuções futuras
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        corrupt = path.with_suffix(path.suffix + f".corrupt_{ts}")
        try:
            path.rename(corrupt)
            print(f"[WARN] JSON inválido em {path}. Renomeado para {corrupt}. Erro: {e}")
        except OSError:
            print(f"[WARN] JSON inválido em {path} (não consegui renomear). Erro: {e}")
        return None

def load_json_list(path: Path, root_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Carrega JSON e garante retorno como lista de dicts.
    - Se root_key for informado (ex: 'items'), lê de um objeto {root_key: [...]}
    - Se o arquivo já for uma lista, retorna direto
    - Se estiver vazio/corrompido, retorna []
    """
    data = load_json_any(path)
    if data is None:
        return []

    if root_key:
        if isinstance(data, dict):
            val = data.get(root_key, [])
            return val if isinstance(val, list) else []
        return []

    # Sem root_key: aceitamos lista direto
    if isinstance(data, list):
        return data

    # Caso alguém salve como dict por engano, tentamos fallback comum
    if isinstance(data, dict):
        val = data.get("items")
        if isinstance(val, list):
            return val

    print(f"[WARN] JSON em {path} não é lista (nem contém '{root_key or 'items'}'). Ignorando.")
    return []


def save_json_list(path: Path, items: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    # Escrita atômica: escreve em tmp e depois substitui
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

    tmp.replace(path)



# ---------- Helpers para datas ----------

def parse_datetime(value: Any) -> Optional[datetime]:
    """
    Tenta converter um campo de data (string ISO ou timestamp numérico) em datetime.
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        # assume timestamp em segundos
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    if isinstance(value, str):
        # tenta ISO 8601
        try:
            # datetime.fromisoformat pode não entender 'Z', então tratamos
            if value.endswith("Z"):
                value = value[:-1] + "+00:00"
            return datetime.fromisoformat(value)
        except Exception:
            return None

    return None


def ensure_timestamp(item: Dict[str, Any]) -> float:
    """
    Garante que cada item tenha um campo numérico 'published_ts' (epoch em segundos)
    derivado de 'published' (string ISO) ou 'published_ts' já existente.
    """
    ts = item.get("published_ts")
    if isinstance(ts, (int, float)):
        return float(ts)

    dt = parse_datetime(item.get("published")) or parse_datetime(item.get("updated"))
    if dt is None:
        # fallback: agora
        dt = datetime.now(timezone.utc)

    item["published_ts"] = dt.timestamp()
    return item["published_ts"]


def _summarize_items(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(items)
    if total == 0:
        return {
            "item_count": 0,
            "range_start": None,
            "range_end": None,
        }

    min_ts = None
    max_ts = None
    for it in items:
        ts = ensure_timestamp(it)
        if min_ts is None or ts < min_ts:
            min_ts = ts
        if max_ts is None or ts > max_ts:
            max_ts = ts

    range_start = datetime.fromtimestamp(min_ts, tz=timezone.utc).isoformat() if min_ts is not None else None
    range_end = datetime.fromtimestamp(max_ts, tz=timezone.utc).isoformat() if max_ts is not None else None
    return {
        "item_count": total,
        "range_start": range_start,
        "range_end": range_end,
    }


# ---------- Bucketização por mês/ano ----------

def bucket_items_by_month(items: List[Dict[str, Any]]) -> Dict[Tuple[int, int], List[Dict[str, Any]]]:
    """
    Agrupa itens por (ano, mês) com base em published_ts / published.
    """
    buckets: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}

    for it in items:
        ts = ensure_timestamp(it)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        key = (dt.year, dt.month)
        buckets.setdefault(key, []).append(it)

    return buckets


def bucket_items_by_year(items: List[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    """
    Agrupa itens por ano.
    """
    buckets: Dict[int, List[Dict[str, Any]]] = {}

    for it in items:
        ts = ensure_timestamp(it)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        key = dt.year
        buckets.setdefault(key, []).append(it)

    return buckets


# ---------- Merge + dedup por link ----------

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

    # Converte de volta para lista e ordena por published_ts desc
    result = list(merged.values())

    def sort_key(it: Dict[str, Any]) -> float:
        dt = parse_datetime(it.get("published")) or parse_datetime(it.get("updated"))
        if dt is not None:
            return dt.timestamp()
        ts = it.get("published_ts")
        if isinstance(ts, (int, float)):
            return float(ts)
        return 0.0

    result.sort(key=sort_key, reverse=True)
    return result


# ---------- Processamento de promo_filtered_* (feeds com conteúdo promocional) ----------

def _normalize_promo_item(item: Dict[str, Any], seen_at: datetime) -> Dict[str, Any]:
    """
    Normaliza um item de promo para o formato usado nos arquivos mensais.

    Campos de saída:
      - feed_title
      - xml_url
      - type_label
      - first_seen / last_seen (ISO8601)
      - total_hits
      - examples (lista de strings, no máximo 10)
    """
    def _to_int(val: Any) -> int:
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0

    promo_count = _to_int(item.get("promo_count", item.get("count", 0)))

    examples = item.get("examples") or []
    if not isinstance(examples, list):
        examples = [examples]
    examples = [str(e) for e in examples][:10]

    return {
        "feed_title": item.get("feed_title"),
        "xml_url": item.get("xml_url"),
        "type_label": item.get("type_label"),
        "first_seen": seen_at.isoformat(),
        "last_seen": seen_at.isoformat(),
        "total_hits": promo_count,
        "examples": examples,
    }


def _merge_promo_month_entries(
    existing: List[Dict[str, Any]],
    new_entries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Junta entradas de promo para um mesmo mês, agregando por feed (chave xml_url ou feed_title).
    Soma total_hits, mescla exemplos e ajusta first_seen/last_seen.
    """
    merged: Dict[str, Dict[str, Any]] = {}

    def key_for(it: Dict[str, Any]) -> Optional[str]:
        return it.get("xml_url") or it.get("feed_title")

    def to_int(val: Any) -> int:
        try:
            return int(val)
        except (TypeError, ValueError):
            return 0

    def merge_one(target: Dict[str, Any], src: Dict[str, Any]) -> None:
        # Soma total_hits
        target["total_hits"] = to_int(target.get("total_hits")) + to_int(
            src.get("total_hits", src.get("promo_count", 0))
        )

        # Mescla exemplos (limitando em 10)
        existing_examples = [str(e) for e in (target.get("examples") or [])]
        seen = set(existing_examples)
        src_examples = src.get("examples") or []
        for ex in src_examples:
            ex_str = str(ex)
            if ex_str not in seen:
                existing_examples.append(ex_str)
                seen.add(ex_str)
            if len(existing_examples) >= 10:
                break
        target["examples"] = existing_examples

        # Ajusta first_seen / last_seen se presentes e em formato ISO
        src_first = src.get("first_seen")
        src_last = src.get("last_seen")

        if src_first:
            if not target.get("first_seen") or str(src_first) < str(target["first_seen"]):
                target["first_seen"] = src_first
        if src_last:
            if not target.get("last_seen") or str(src_last) > str(target["last_seen"]):
                target["last_seen"] = src_last

        # Mantém feed_title/xml_url/type_label mais recentes se vierem preenchidos
        for field in ("feed_title", "xml_url", "type_label"):
            if src.get(field):
                target[field] = src[field]

    # Primeiro, copiar existentes
    for it in existing:
        k = key_for(it)
        if not k:
            continue
        merged[k] = dict(it)

    # Depois, agregar novos
    for it in new_entries:
        k = key_for(it)
        if not k:
            continue
        if k in merged:
            merge_one(merged[k], it)
        else:
            # garantir campos padrão
            base = dict(it)
            base.setdefault("total_hits", to_int(it.get("total_hits", it.get("promo_count", 0))))
            base.setdefault("examples", it.get("examples") or [])
            merged[k] = base

    return list(merged.values())


def process_promo_filtered_files() -> None:
    """
    Procura por arquivos data/archive/promo_filtered_*.json, bucketiza por mês
    (com base no mtime do arquivo) e grava/atualiza:

        data/archive/promo/monthly/<ano>/promo_<ano>-<mes>.json

    Após o processamento bem-sucedido, os arquivos promo_filtered_* são apagados.
    """
    promo_files = sorted(ARCHIVE_DIR.glob("promo_filtered_*.json"))

    if not promo_files:
        print("[INFO] Nenhum arquivo promo_filtered_* para processar.")
        return

    monthly_new: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}

    for path in promo_files:
        try:
            raw = load_json_any(path)
        except Exception as e:
            print(f"[WARN] Falha ao ler {path}: {e}")
            continue

        if raw is None:
            continue

        # Determina os itens dentro do arquivo
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            # tentar algumas chaves comuns
            if isinstance(raw.get("items"), list):
                items = raw["items"]
            elif isinstance(raw.get("feeds"), list):
                items = raw["feeds"]
            else:
                # Último recurso: tentar interpretar valores de dict como lista de itens
                values = list(raw.values())
                if values and isinstance(values[0], list):
                    items = values[0]
                else:
                    print(f"[WARN] Formato inesperado em {path}, ignorando.")
                    continue
        else:
            print(f"[WARN] Formato inesperado em {path}, ignorando.")
            continue

        # Usa o mtime do arquivo para determinar ano/mês
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        year, month = mtime.year, mtime.month

        bucket_key = (year, month)
        bucket = monthly_new.setdefault(bucket_key, [])

        for it in items:
            if not isinstance(it, dict):
                continue
            norm = _normalize_promo_item(it, mtime)
            bucket.append(norm)

    # Atualiza arquivos mensais de promo
    for (year, month), new_entries in sorted(monthly_new.items()):
        year_str = f"{year}"
        month_str = f"{month:02d}"

        month_dir = PROMO_MONTHLY_DIR / year_str
        month_dir.mkdir(parents=True, exist_ok=True)
        promo_month_path = month_dir / f"promo_{year_str}-{month_str}.json"

        existing = load_json_list(promo_month_path)
        merged = _merge_promo_month_entries(existing, new_entries)
        save_json_list(promo_month_path, merged)

        print(
            f"[INFO] Arquivo mensal de promo atualizado: {promo_month_path} "
            f"(+{len(new_entries)} registros, total {len(merged)})"
        )

    # Limpa arquivos de entrada após o processamento
    for path in promo_files:
        try:
            path.unlink()
            print(f"[INFO] Arquivo processado e removido: {path}")
        except OSError as e:
            print(f"[WARN] Não foi possível apagar {path}: {e}")


def process_morning_call_files() -> None:
    """
    Move arquivos flat:
      data/archive/morning_call_YYYY-MM-DD.json
    para:
      data/archive/morning_call/<ano>/<mes>/morning_call_YYYY-MM-DD.json
    """
    mc_files = sorted(ARCHIVE_DIR.glob("morning_call_*.json"))
    if not mc_files:
        print("[INFO] Nenhum morning_call_*.json (flat) para organizar.")
        return

    for src in mc_files:
        # segurança: ignore qualquer coisa que não seja arquivo normal
        if not src.is_file():
            continue

        # tenta extrair data do próprio JSON (analysis_date / generated_at), senão usa mtime
        dt = None
        try:
            raw = load_json_any(src)
            if isinstance(raw, dict):
                if raw.get("analysis_date"):
                    dt = parse_datetime(str(raw["analysis_date"]) + "T00:00:00Z")
                if dt is None and raw.get("generated_at"):
                    dt = parse_datetime(raw.get("generated_at"))
        except Exception:
            dt = None

        if dt is None:
            dt = datetime.fromtimestamp(src.stat().st_mtime, tz=timezone.utc)

        year_str = f"{dt.year}"
        month_str = f"{dt.month:02d}"

        dest_dir = MORNING_CALL_DIR / year_str / month_str
        dest_dir.mkdir(parents=True, exist_ok=True)

        dest = dest_dir / src.name
        if dest.exists():
            # evita sobrescrever sem necessidade
            print(f"[INFO] Destino já existe, removendo duplicado: {src} -> {dest}")
            src.unlink()
            continue

        src.rename(dest)
        print(f"[INFO] Morning call movido: {src} -> {dest}")


def build_archive_indices() -> None:
    """
    Gera índices globais para navegação rápida no frontend:
      - data/archive/archive_index.json
      - data/archive/index.json (alias com mesmo conteúdo)
    """
    years_map: Dict[int, Dict[str, Any]] = {}

    # 1) Resumos mensais
    for monthly_file in sorted(MONTHLY_DIR.glob("*/*.json")):
        try:
            year_str = monthly_file.parent.name
            file_name = monthly_file.stem  # YYYY-MM
            if "-" not in file_name:
                continue
            _, month_str = file_name.split("-", 1)
            year = int(year_str)
            month = int(month_str)
        except (ValueError, TypeError):
            continue

        items = load_json_list(monthly_file)
        month_summary = _summarize_items(items)

        y = years_map.setdefault(
            year,
            {
                "year": year,
                "item_count": 0,
                "range_start": None,
                "range_end": None,
                "months": [],
                "yearly_path": f"archive/yearly/{year}.json",
            },
        )

        y["months"].append(
            {
                "month": f"{month:02d}",
                "item_count": month_summary["item_count"],
                "range_start": month_summary["range_start"],
                "range_end": month_summary["range_end"],
                "path": f"archive/monthly/{year}/{year}-{month:02d}.json",
            }
        )
        y["item_count"] += int(month_summary["item_count"])

        # Atualiza range anual a partir dos meses
        start = month_summary["range_start"]
        end = month_summary["range_end"]
        if start and (not y["range_start"] or start < y["range_start"]):
            y["range_start"] = start
        if end and (not y["range_end"] or end > y["range_end"]):
            y["range_end"] = end

    # 2) Ajusta metadados com base no yearly, se disponível
    for yearly_file in sorted(YEARLY_DIR.glob("*.json")):
        try:
            year = int(yearly_file.stem)
        except ValueError:
            continue

        items = load_json_list(yearly_file)
        summary = _summarize_items(items)
        y = years_map.setdefault(
            year,
            {
                "year": year,
                "item_count": 0,
                "range_start": None,
                "range_end": None,
                "months": [],
                "yearly_path": f"archive/yearly/{year}.json",
            },
        )

        if summary["item_count"] > y["item_count"]:
            y["item_count"] = int(summary["item_count"])
        if summary["range_start"] and (not y["range_start"] or summary["range_start"] < y["range_start"]):
            y["range_start"] = summary["range_start"]
        if summary["range_end"] and (not y["range_end"] or summary["range_end"] > y["range_end"]):
            y["range_end"] = summary["range_end"]

    # Ordena anos/meses
    years = []
    for year in sorted(years_map.keys()):
        row = years_map[year]
        row["months"] = sorted(row["months"], key=lambda m: m["month"])
        years.append(row)

    # Totais e latest month
    total_months = sum(len(y["months"]) for y in years)
    total_items = sum(int(y["item_count"]) for y in years)

    latest = None
    for y in sorted(years, key=lambda r: r["year"], reverse=True):
        if not y["months"]:
            continue
        last_month = sorted(y["months"], key=lambda m: m["month"], reverse=True)[0]
        latest = {
            "year": y["year"],
            "month": last_month["month"],
            "item_count": int(last_month["item_count"]),
            "path": last_month["path"],
        }
        break

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "latest": latest,
        "totals": {
            "years": len(years),
            "months": total_months,
            "items": total_items,
        },
        "years": years,
    }

    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_INDEX_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    ARCHIVE_GLOBAL_INDEX_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[INFO] Índice de archive gerado: {ARCHIVE_INDEX_PATH}")
    print(f"[INFO] Índice global gerado: {ARCHIVE_GLOBAL_INDEX_PATH}")


# ---------- Função principal ----------

def main() -> None:
    if not RECENT_PATH.exists():
        raise FileNotFoundError(f"Arquivo recente não encontrado: {RECENT_PATH}")

    # news_recent.json é um dict com "items"
    recent_items = load_json_list(RECENT_PATH, root_key="items")
    print(f"[INFO] Carregados {len(recent_items)} itens recentes de {RECENT_PATH}")

    if not recent_items:
        print("[INFO] Nenhum item recente para arquivar. Atualizando apenas índices/auxiliares.")
        process_morning_call_files()
        process_promo_filtered_files()
        build_archive_indices()
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

    # --------- Processa arquivos promo_filtered_* ---------
    process_morning_call_files()
    process_promo_filtered_files()
    build_archive_indices()

    print("[INFO] build_news_archive.py concluído com sucesso.")


if __name__ == "__main__":
    main()
