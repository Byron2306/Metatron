"""
Zeek NDR Router
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Dict, List, Tuple
import json

from fastapi import APIRouter, Depends, Query

from .dependencies import get_current_user

router = APIRouter(prefix="/zeek", tags=["Zeek NDR"])

ZEEK_LOG_DIR = Path("/var/log/zeek/current")


def _zeek_log_file(log_type: str) -> Path:
    return ZEEK_LOG_DIR / f"{log_type}.log"


def _parse_zeek_tsv(lines: List[str]) -> List[Dict]:
    fields: List[str] = []
    rows: List[Dict] = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue

        if not fields:
            continue

        parts = line.split("\t")
        rec: Dict = {}
        for idx, field in enumerate(fields):
            rec[field] = parts[idx] if idx < len(parts) else None
        rows.append(rec)

    return rows


def _parse_zeek_log(log_type: str, limit: int) -> Tuple[List[Dict], bool, str]:
    log_path = _zeek_log_file(log_type)
    if not log_path.exists():
        return [], False, f"{log_path} not found"

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except Exception as exc:
        return [], True, str(exc)

    # Prefer JSON lines when Zeek is configured with LogAscii::use_json=T.
    json_rows: List[Dict] = []
    for raw in reversed(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                json_rows.append(json.loads(stripped))
            except json.JSONDecodeError:
                json_rows = []
                break
        else:
            json_rows = []
            break
        if len(json_rows) >= limit:
            break

    if json_rows:
        return json_rows[:limit], True, ""

    tsv_rows = _parse_zeek_tsv(lines)
    if not tsv_rows:
        return [], True, ""
    return list(reversed(tsv_rows))[:limit], True, ""


@router.get("/status")
async def zeek_status(current_user: dict = Depends(get_current_user)):
    available = ZEEK_LOG_DIR.exists()
    existing_logs = []
    if available:
        existing_logs = sorted([p.stem for p in ZEEK_LOG_DIR.glob("*.log")])

    return {
        "available": available,
        "log_dir": str(ZEEK_LOG_DIR),
        "log_count": len(existing_logs),
        "log_types": existing_logs,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/log-types")
async def zeek_log_types(current_user: dict = Depends(get_current_user)):
    defaults = ["conn", "dns", "http", "ssl", "notice", "files", "weird"]
    discovered = sorted([p.stem for p in ZEEK_LOG_DIR.glob("*.log")]) if ZEEK_LOG_DIR.exists() else []
    return {
        "defaults": defaults,
        "discovered": discovered,
    }


@router.get("/logs/{log_type}")
async def zeek_logs(
    log_type: str,
    limit: int = Query(100, ge=1, le=500),
    current_user: dict = Depends(get_current_user),
):
    records, available, message = _parse_zeek_log(log_type, limit)
    return {
        "available": available,
        "log_type": log_type,
        "count": len(records),
        "records": records,
        "message": message,
    }


@router.get("/stats")
async def zeek_stats(current_user: dict = Depends(get_current_user)):
    conn_records, available, message = _parse_zeek_log("conn", 1000)
    dns_records, _, _ = _parse_zeek_log("dns", 1000)
    notice_records, _, _ = _parse_zeek_log("notice", 200)

    unique_sources = set()
    total_bytes = 0.0

    for rec in conn_records:
        src = rec.get("id.orig_h") or rec.get("src_ip")
        if src:
            unique_sources.add(src)

        ob = rec.get("orig_bytes") or rec.get("orig_ip_bytes") or 0
        rb = rec.get("resp_bytes") or rec.get("resp_ip_bytes") or 0
        try:
            total_bytes += float(ob) + float(rb)
        except Exception:
            pass

    return {
        "available": available,
        "message": message,
        "conn_events": len(conn_records),
        "dns_events": len(dns_records),
        "notice_events": len(notice_records),
        "unique_sources": len(unique_sources),
        "traffic_bytes": int(total_bytes),
    }


@router.get("/detections/beaconing")
async def zeek_beaconing(
    min_events: int = Query(8, ge=3, le=200),
    max_jitter_seconds: float = Query(3.0, ge=0.5, le=60.0),
    limit: int = Query(25, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    conn_records, available, message = _parse_zeek_log("conn", 3000)
    if not available:
        return {"available": False, "message": message, "detections": []}

    buckets: Dict[Tuple[str, str], List[float]] = {}
    for rec in conn_records:
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h")
        ts = rec.get("ts")
        if not src or not dst or ts is None:
            continue
        try:
            tsf = float(ts)
        except Exception:
            continue
        buckets.setdefault((src, dst), []).append(tsf)

    detections = []
    for (src, dst), times in buckets.items():
        if len(times) < min_events:
            continue
        times.sort()
        intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
        if not intervals:
            continue
        avg_interval = mean(intervals)
        jitter = max(intervals) - min(intervals)
        if avg_interval > 0 and jitter <= max_jitter_seconds:
            detections.append(
                {
                    "src_ip": src,
                    "dest_ip": dst,
                    "events": len(times),
                    "avg_interval_seconds": round(avg_interval, 3),
                    "jitter_seconds": round(jitter, 3),
                    "confidence": "high" if jitter < 1.0 else "medium",
                }
            )

    detections.sort(key=lambda d: d["events"], reverse=True)
    return {
        "available": True,
        "count": len(detections),
        "detections": detections[:limit],
    }


@router.get("/detections/dns-tunneling")
async def zeek_dns_tunneling(
    min_queries: int = Query(20, ge=5, le=500),
    min_avg_length: int = Query(40, ge=10, le=250),
    limit: int = Query(25, ge=1, le=100),
    current_user: dict = Depends(get_current_user),
):
    dns_records, available, message = _parse_zeek_log("dns", 5000)
    if not available:
        return {"available": False, "message": message, "detections": []}

    by_source: Dict[str, List[str]] = {}
    for rec in dns_records:
        src = rec.get("id.orig_h")
        query = rec.get("query")
        if src and query:
            by_source.setdefault(src, []).append(query)

    detections = []
    for src, queries in by_source.items():
        if len(queries) < min_queries:
            continue
        avg_len = mean([len(q) for q in queries])
        unique_ratio = len(set(queries)) / len(queries)
        top_tlds = Counter([q.split(".")[-1] for q in queries if "." in q]).most_common(3)
        if avg_len >= min_avg_length and unique_ratio > 0.8:
            detections.append(
                {
                    "src_ip": src,
                    "queries": len(queries),
                    "avg_query_length": round(avg_len, 2),
                    "unique_ratio": round(unique_ratio, 3),
                    "top_tlds": [t[0] for t in top_tlds],
                    "confidence": "high" if avg_len > 60 else "medium",
                }
            )

    detections.sort(key=lambda d: (d["queries"], d["avg_query_length"]), reverse=True)
    return {
        "available": True,
        "count": len(detections),
        "detections": detections[:limit],
    }
