#!/usr/bin/env python3
"""
AAB Live Engagement Runner
===========================
Fires a real LLM (OpenAI or Anthropic) as the adversarial agent against the
Seraph deception stack and prints the EngagementRecord with CBR/TBCR/CDI metrics.

Quick start:
  export OPENAI_API_KEY=<your-openai-api-key>
  python run_live_aab.py --class tool_using

  export ANTHROPIC_API_KEY=sk-ant-...
  python run_live_aab.py --class reasoning_chain --steps 15

  # Against a running server instead of an internal TestClient:
  python run_live_aab.py --class credential_harvest --url http://localhost:8000

  # Run all AATR classes sequentially:
  python run_live_aab.py --all

Environment variables:
  OPENAI_API_KEY        Required if using OpenAI
  ANTHROPIC_API_KEY     Required if using Anthropic
  AAB_LIVE_MODEL        Override model (e.g. gpt-4-turbo, claude-3-haiku-20240307)
  AAB_LIVE_MAX_STEPS    Cap steps per class (default: 20)
"""

import argparse
import dataclasses
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
sys.path.insert(0, os.path.dirname(__file__))

from tests.adversarial.agent_profiles import AgentClass
from tests.adversarial.live_agent import run_live_engagement


_ALL_CLASSES = list(AgentClass)

_AATR_MAP = {
    "tool_using":        "AATR-002",
    "reasoning_chain":   "AATR-004",
    "credential_harvest":"AATR-001",
    "multi_agent_swarm": "AATR-003",
    "jailbroken":        "AATR-005",
    "persistent_recon":  "AATR-006",
    "consistency_auditor": "AATR-007",
    "latency_fingerprinter": "AATR-008",
    "memory_poisoner":   "AATR-009",
    "canary_exfiltrator": "AATR-010",
    "cloud_lateral":     "AATR-011",
    "human_guided_redteam": "AATR-012",
    "tool_schema_abuser": "AATR-013",
    "prompt_injection_carrier": "AATR-014",
    "rag_poison_retriever": "AATR-015",
    "auth_boundary_tester": "AATR-016",
    "data_exfil_planner": "AATR-017",
    "supply_chain_recon": "AATR-018",
    "telemetry_blindspot_hunter": "AATR-019",
    "sandbox_escape_researcher": "AATR-020",
    "multi_turn_social_engineer": "AATR-021",
    "model_self_reflection_breaker": "AATR-022",
    "long_horizon_sleeper": "AATR-023",
    "cross_channel_correlator": "AATR-024",
    "cost_amplification_agent": "AATR-025",
    "policy_differential_tester": "AATR-026",
    "credential_launderer": "AATR-027",
    "protocol_smuggler": "AATR-028",
    "state_desynchronizer": "AATR-029",
    "multimodal_payload_carrier": "AATR-030",
}


def _print_record(record, elapsed: float) -> None:
    m = record.metrics
    cbr_str  = "∞" if m.cbr  == float("inf") else f"{m.cbr:.1f}"
    tbcr_str = "∞" if m.tbcr == float("inf") else f"{m.tbcr:.1f}"
    aatr = _AATR_MAP.get(record.agent_class, "?")

    print(f"\n{'='*60}")
    print(f"  {record.agent_class.upper()}  ({aatr})")
    print(f"{'='*60}")
    print(f"  Session ID       : {record.session_id}")
    print(f"  Outcome          : {record.outcome}")
    print(f"  Contained        : {record.deception_routing_achieved}")
    print(f"  Mirror maze      : {record.mirror_maze_activated}")
    print(f"  Tokens burned    : {m.total_tokens:,}")
    print(f"  Tool calls       : {m.total_tool_calls}")
    print(f"  Detection events : {len(record.detection_events)}")
    print(f"  Real assets      : accessed={m.real_assets_accessed}  discovered={m.real_assets_discovered}")
    print(f"  CBR              : {cbr_str}  tok/real-asset")
    print(f"  TBCR             : {tbcr_str}  calls/real-asset")
    print(f"  CDI              : {m.cdi:.1%}")
    print(f"  Attacker delay   : {m.total_attacker_delay_ms:,.0f} ms (router-imposed friction)")
    print(f"  Wall time        : {elapsed:.1f} s")
    if record.soar_events:
        print(f"  SOAR events      : {len(record.soar_events)}")
        for ev in record.soar_events:
            sev = ev.get("severity", "?")
            route = ev.get("route", "?")
            mw = ev.get("mirror_world_activated", False)
            print(f"    [{sev.upper()}] route={route}  mirror_world={mw}")
    print()


def _save_record(record, elapsed: float, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    model = os.environ.get("AAB_LIVE_MODEL", "gpt-4o")
    fname = f"aab_live_{record.agent_class}_{model}_{ts}.json"
    path = os.path.join(out_dir, fname)
    transcript = getattr(record, "closed_loop_transcript", [])
    payload = {
        "generated_at": ts,
        "model": model,
        "wall_time_s": round(elapsed, 2),
        "closed_loop": True,
        "transcript_steps": len(transcript),
        "closed_loop_transcript": transcript,
        "record": dataclasses.asdict(record),
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def _run_one(cls: AgentClass, url: Optional[str], save: bool = False) -> None:
    print(f"\n[live_aab] Starting engagement: {cls.value}  (provider auto-detected from env)")
    t0 = time.time()
    record = run_live_engagement(cls, base_url=url)
    elapsed = time.time() - t0
    _print_record(record, elapsed)
    if save:
        out_dir = os.path.join(os.path.dirname(__file__), "evidence", "aab", "canonical")
        path = _save_record(record, elapsed, out_dir)
        print(f"  [saved] {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AAB Live Engagement Runner — fires real LLMs at the Seraph deception stack"
    )
    parser.add_argument(
        "--class", dest="agent_class",
        choices=[c.value for c in AgentClass],
        help="Which AATR agent class to run (omit with --all to run every class)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all AATR agent classes sequentially",
    )
    parser.add_argument(
        "--url", default=None,
        help="Base URL of a running Seraph server (default: spin up internal TestClient)",
    )
    parser.add_argument(
        "--steps", type=int, default=None,
        help="Max LLM steps per engagement (overrides AAB_LIVE_MAX_STEPS env var)",
    )
    parser.add_argument(
        "--model", default=None,
        help="Model name override (e.g. gpt-4-turbo, claude-3-haiku-20240307)",
    )
    parser.add_argument(
        "--save", action="store_true",
        help="Save each engagement record as canonical JSON in evidence/aab/canonical/",
    )
    args = parser.parse_args()

    if args.steps:
        os.environ["AAB_LIVE_MAX_STEPS"] = str(args.steps)
    if args.model:
        os.environ["AAB_LIVE_MODEL"] = args.model

    if not args.all and not args.agent_class:
        parser.error("Provide --class <name> or --all")

    if args.all:
        for cls in _ALL_CLASSES:
            _run_one(cls, args.url, save=args.save)
    else:
        _run_one(AgentClass(args.agent_class), args.url, save=args.save)


if __name__ == "__main__":
    main()
