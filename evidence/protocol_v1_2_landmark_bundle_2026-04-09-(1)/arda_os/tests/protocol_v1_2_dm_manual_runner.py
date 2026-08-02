#!/usr/bin/env python3
"""
Manual DM family verifier.

Runs the delayed-memory family sequentially against a single fixed presence
session token and saves a normal per-condition artifact. This avoids the flaky
outer benchmark loop while preserving the same judge and row schema.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
import urllib.request
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_PATH = PROJECT_ROOT / "arda_os" / "tests" / "speech_calibration_multimodal_comparison.py"


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location("protocol_benchmark", BENCHMARK_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("benchmark_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _get_session_token(health_url: str) -> str:
    req = urllib.request.Request(health_url, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    token = str(payload.get("session_token") or "")
    if not token:
        raise RuntimeError("presence_session_token_unavailable")
    return token


def main() -> None:
    benchmark = _load_benchmark_module()
    health_url = os.environ.get("PRESENCE_HEALTH_URL", "http://localhost:7070/api/health")
    fixed_token = os.environ.get("PRESENCE_SESSION_TOKEN") or _get_session_token(health_url)
    os.environ["PRESENCE_SESSION_TOKEN"] = fixed_token
    benchmark._CACHED_SESSION_TOKEN = fixed_token

    cases = [
        case
        for case in benchmark._load_cases()
        if str(case.get("event_id") or "").startswith("DM")
    ]
    condition = "sophia_full"
    rows = []
    scenario_states = {}

    for case in cases:
        scenario_id = str(case.get("scenario_id") or case["event_id"])
        scenario_state = scenario_states.get(scenario_id) if case.get("continuity_mode") == "scenario_chain" else None
        result = benchmark._execute_case(condition, case, scenario_state=scenario_state)
        judge = benchmark._judge_result(case, result)
        row = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "model_tag": benchmark.MODEL,
            "condition_tag": condition,
            "replicate": benchmark.REPLICATE,
            "probe_id": case["probe_id"],
            "event_id": case["event_id"],
            "prompt": case["prompt"],
            "evidence_task": case.get("evidence_task"),
            "sources": case.get("sources"),
            "decoding_parameters": {
                "temperature": 0.2,
                "top_p": 0.9,
                "max_tokens": 500,
            },
            "result": result,
            "case": benchmark._case_projection(case),
            "judge": judge,
            "benchmark_axes": benchmark._benchmark_axes(case),
            "rubric": benchmark._score_probe(case, result, judge),
        }
        row.update(benchmark._project_result_summary(result))
        rows.append(row)
        if case.get("continuity_mode") == "scenario_chain":
            transcript = list((scenario_states.get(scenario_id) or {}).get("transcript") or [])
            transcript.append(
                {
                    "event_id": case["event_id"],
                    "prompt": case["prompt"],
                    "response": row.get("response", ""),
                }
            )
            scenario_states[scenario_id] = {"transcript": transcript}
        benchmark._write_condition_rows(condition, rows, partial=True)

    benchmark._write_condition_rows(condition, rows, partial=False)
    summary = {
        "saved_conditions": [condition],
        "model_tag": benchmark.MODEL,
        "replicate": benchmark.REPLICATE,
        "rows": len(rows),
        "judge_passes": sum(1 for row in rows if (row.get("judge") or {}).get("passed")),
        "cases_path": str(benchmark.CASES_PATH),
        "event_ids": [case["event_id"] for case in cases],
        "overwrite_existing": True,
        "rejudge_existing": False,
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
