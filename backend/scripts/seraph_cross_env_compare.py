#!/usr/bin/env python3
"""Compare Seraph validation outputs across environments.

Inputs are scorecard JSON files produced by seraph_confidence_scorecard.py.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def _load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run(args: argparse.Namespace) -> int:
    files = [Path(p).resolve() for p in args.scorecards]
    if len(files) < 2:
        raise SystemExit("Provide at least two scorecard files")

    payloads: List[Dict[str, Any]] = []
    for f in files:
        if not f.exists():
            raise SystemExit(f"Missing scorecard: {f}")
        d = _load(f)
        payloads.append(
            {
                "path": str(f),
                "score": float(d.get("composite_score_10") or 0.0),
                "grade": d.get("grade"),
                "atomic_coverage": int((((d.get("core_metrics") or {}).get("prevention") or {}).get("unique_techniques") or 0)),
                "dagor_hostile_total": int(((((d.get("core_metrics") or {}).get("dagor") or {}).get("hostile_total")) or 0)),
                "dagor_hostile_denied": int(((((d.get("core_metrics") or {}).get("dagor") or {}).get("hostile_denied")) or 0)),
            }
        )

    scores = [p["score"] for p in payloads]
    spread = max(scores) - min(scores)

    out = {
        "scorecard_count": len(payloads),
        "scores": payloads,
        "spread": round(spread, 4),
        "consistency": "high" if spread <= args.max_spread else "low",
        "max_allowed_spread": args.max_spread,
    }

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(json.dumps({"output": str(out_path), "spread": out["spread"], "consistency": out["consistency"]}, indent=2))
    return 0 if out["consistency"] == "high" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Seraph scorecards across environments")
    parser.add_argument("scorecards", nargs="+", help="Scorecard JSON files")
    parser.add_argument("--max-spread", type=float, default=0.5, help="Max acceptable score spread")
    parser.add_argument(
        "--output",
        default="backend/scripts/telemetry_logs/seraph_cross_env_compare_latest.json",
        help="Output path",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
