"""
Adversarial Harness — CBR / TBCR / CDI Measurement Engine
===========================================================
Implements the three formal exhaustion metrics from the strategic roadmap:

  CBR  (Context Burn Rate)          = total_tokens_consumed / real_assets_accessed
  TBCR (Tool Budget Consumption Rate) = total_tool_calls / real_assets_discovered
  CDI  (Confidence Degradation Index) = 1 - (final_confidence / initial_confidence)

The harness fires a configured AgentProfile at the live Seraph deception stack,
records every interaction, and emits a structured EngagementRecord — the unit of
the TVR (Technique Validation Record) evidence corpus.

Usage:
    from tests.adversarial.harness import AdversarialHarness, run_engagement
    from tests.adversarial.agent_profiles import AgentClass, build_profile

    profile = build_profile(AgentClass.REASONING_CHAIN)
    record  = run_engagement(profile, app=seraph_fastapi_app)
    print(record.summary())
"""

from __future__ import annotations

import json
import hashlib
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Ensure backend is importable
sys.path.insert(0, "backend")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.adversarial.agent_profiles import AgentAction, AgentClass, AgentProfile

# Routing decisions that mean the agent was captured / routed to deception
_DECEPTION_ROUTES = {"trap_sink", "honeypot", "disinformation"}

# Per-class representative timing signatures.
# These encode the *hypothetical real-world* request cadence each agent class
# would exhibit so the AATL machine-tempo detector can distinguish them.
# The AATL MACHINE_TIMING thresholds are: min_human_delay=200ms, max_machine_variance=50ms.
_AGENT_TIMING: Dict[str, Dict[str, float]] = {
    #                        inter_req_ms  variance_ms  req/s
    "tool_using":        {"inter_request_ms": 350,  "timing_variance_ms": 80,  "request_velocity": 0.6},
    "reasoning_chain":   {"inter_request_ms": 600,  "timing_variance_ms": 150, "request_velocity": 0.3},
    "credential_harvest":{"inter_request_ms": 400,  "timing_variance_ms": 100, "request_velocity": 0.5},
    "multi_agent_swarm": {"inter_request_ms": 120,  "timing_variance_ms": 25,  "request_velocity": 2.5},
    # Jailbroken fires at machine speed — inter-request well below 200ms human floor,
    # timing variance well below 50ms machine ceiling → AATL machine_plausibility peaks.
    "jailbroken":        {"inter_request_ms": 75,   "timing_variance_ms": 12,  "request_velocity": 9.0},
    # Persistent recon is deliberate and slow — timing looks human to the AATL
    # (caught by session routing at Layer 2, not AATL at Layer 1).
    "persistent_recon":  {"inter_request_ms": 2200, "timing_variance_ms": 480, "request_velocity": 0.08},
    "consistency_auditor": {"inter_request_ms": 700, "timing_variance_ms": 140, "request_velocity": 0.35},
    "latency_fingerprinter": {"inter_request_ms": 95, "timing_variance_ms": 8, "request_velocity": 8.0},
    "memory_poisoner": {"inter_request_ms": 280, "timing_variance_ms": 60, "request_velocity": 0.9},
    "canary_exfiltrator": {"inter_request_ms": 180, "timing_variance_ms": 35, "request_velocity": 3.0},
    "cloud_lateral": {"inter_request_ms": 240, "timing_variance_ms": 70, "request_velocity": 1.2},
    "human_guided_redteam": {"inter_request_ms": 950, "timing_variance_ms": 260, "request_velocity": 0.22},
    "tool_schema_abuser": {"inter_request_ms": 110, "timing_variance_ms": 18, "request_velocity": 5.5},
    "prompt_injection_carrier": {"inter_request_ms": 420, "timing_variance_ms": 95, "request_velocity": 0.65},
    "rag_poison_retriever": {"inter_request_ms": 360, "timing_variance_ms": 75, "request_velocity": 0.8},
    "auth_boundary_tester": {"inter_request_ms": 190, "timing_variance_ms": 30, "request_velocity": 2.2},
    "data_exfil_planner": {"inter_request_ms": 260, "timing_variance_ms": 65, "request_velocity": 1.4},
    "supply_chain_recon": {"inter_request_ms": 310, "timing_variance_ms": 80, "request_velocity": 0.95},
    "telemetry_blindspot_hunter": {"inter_request_ms": 135, "timing_variance_ms": 20, "request_velocity": 4.2},
    "sandbox_escape_researcher": {"inter_request_ms": 500, "timing_variance_ms": 110, "request_velocity": 0.55},
    "multi_turn_social_engineer": {"inter_request_ms": 1300, "timing_variance_ms": 340, "request_velocity": 0.18},
    "model_self_reflection_breaker": {"inter_request_ms": 820, "timing_variance_ms": 170, "request_velocity": 0.28},
    "long_horizon_sleeper": {"inter_request_ms": 3600, "timing_variance_ms": 900, "request_velocity": 0.03},
    "cross_channel_correlator": {"inter_request_ms": 520, "timing_variance_ms": 115, "request_velocity": 0.5},
    "cost_amplification_agent": {"inter_request_ms": 160, "timing_variance_ms": 26, "request_velocity": 3.8},
    "policy_differential_tester": {"inter_request_ms": 340, "timing_variance_ms": 72, "request_velocity": 0.85},
    "credential_launderer": {"inter_request_ms": 210, "timing_variance_ms": 42, "request_velocity": 1.9},
    "protocol_smuggler": {"inter_request_ms": 105, "timing_variance_ms": 15, "request_velocity": 5.8},
    "state_desynchronizer": {"inter_request_ms": 125, "timing_variance_ms": 22, "request_velocity": 4.6},
    "multimodal_payload_carrier": {"inter_request_ms": 470, "timing_variance_ms": 125, "request_velocity": 0.6},
    "goal_hijacker": {"inter_request_ms": 390, "timing_variance_ms": 85, "request_velocity": 0.75},
    "tool_result_forger": {"inter_request_ms": 145, "timing_variance_ms": 24, "request_velocity": 3.4},
    "inter_agent_spoofer": {"inter_request_ms": 155, "timing_variance_ms": 28, "request_velocity": 3.1},
    "rogue_trusted_agent": {"inter_request_ms": 620, "timing_variance_ms": 140, "request_velocity": 0.42},
    "cascading_workflow_amplifier": {"inter_request_ms": 220, "timing_variance_ms": 55, "request_velocity": 1.7},
    "human_trust_exploiter": {"inter_request_ms": 1500, "timing_variance_ms": 420, "request_velocity": 0.15},
    "malicious_skill_installer": {"inter_request_ms": 260, "timing_variance_ms": 60, "request_velocity": 1.3},
    "audit_evidence_forger": {"inter_request_ms": 300, "timing_variance_ms": 70, "request_velocity": 1.0},
}

# Maps each AgentClass value to its AATR registry entry ID
_AATR_CLASS_MAP: Dict[str, str] = {
    "tool_using":        "AATR-002",   # Tool-Using Code Agent
    "reasoning_chain":   "AATR-004",   # Reasoning Chain Agent
    "credential_harvest": "AATR-001",  # Generic Planning Agent (closest match for credential focus)
    "multi_agent_swarm": "AATR-003",   # Multi-Agent Swarm
    "jailbroken":        "AATR-005",   # Uncensored/Jailbroken Agent
    "persistent_recon":  "AATR-006",   # Persistent Reconnaissance Agent
    "consistency_auditor": "AATR-007", # Mirror-world consistency auditor
    "latency_fingerprinter": "AATR-008", # Timing/response-shape fingerprinting agent
    "memory_poisoner":   "AATR-009",   # Prompt/memory poisoning agent
    "canary_exfiltrator": "AATR-010",  # Canary reuse / second-stage validation agent
    "cloud_lateral":     "AATR-011",   # Cloud metadata/IAM lateral movement agent
    "human_guided_redteam": "AATR-012", # Human-scaffolded frontier-model red team
    "tool_schema_abuser": "AATR-013",   # Tool schema and function-call boundary abuse
    "prompt_injection_carrier": "AATR-014", # Stored/indirect prompt injection carrier
    "rag_poison_retriever": "AATR-015", # RAG/vector retrieval poison and context manipulation
    "auth_boundary_tester": "AATR-016", # IDOR/tenant/role/session authorization probing
    "data_exfil_planner": "AATR-017",   # Bulk extraction and covert egress planner
    "supply_chain_recon": "AATR-018",   # CI/package/build pipeline reconnaissance
    "telemetry_blindspot_hunter": "AATR-019", # Log/alert blindspot hunter
    "sandbox_escape_researcher": "AATR-020", # Sandbox/container/tool isolation researcher
    "multi_turn_social_engineer": "AATR-021", # Multi-turn support/admin social escalation
    "model_self_reflection_breaker": "AATR-022", # Meta-reasoning deception detector
    "long_horizon_sleeper": "AATR-023", # Low-frequency stateful sleeper agent
    "cross_channel_correlator": "AATR-024", # API/log/file/timing correlator
    "cost_amplification_agent": "AATR-025", # Defender cost amplification agent
    "policy_differential_tester": "AATR-026", # Policy route/model differential tester
    "credential_launderer": "AATR-027", # Canary credential laundering agent
    "protocol_smuggler": "AATR-028", # Protocol/header/content smuggling agent
    "state_desynchronizer": "AATR-029", # Race/cache/session desynchronizer
    "multimodal_payload_carrier": "AATR-030", # Multimodal hidden payload carrier
    "goal_hijacker": "AATR-031", # Objective drift / mission rewrite agent
    "tool_result_forger": "AATR-032", # Malicious tool/MCP result forger
    "inter_agent_spoofer": "AATR-033", # A2A spoofing and consensus manipulation
    "rogue_trusted_agent": "AATR-034", # Misaligned trusted agent with legitimate identity
    "cascading_workflow_amplifier": "AATR-035", # Small action to large workflow failure
    "human_trust_exploiter": "AATR-036", # Human approval/execution manipulation
    "malicious_skill_installer": "AATR-037", # Skill/plugin extension compromise
    "audit_evidence_forger": "AATR-038", # Log/report/forensic evidence tampering
}


# ---------------------------------------------------------------------------
# The three formal exhaustion metrics
# ---------------------------------------------------------------------------

@dataclass
class ExhaustionMetrics:
    """
    CBR  — Context Burn Rate:
        How many tokens did the attacker spend per real asset unit gained?
        Higher is better (attacker burned more budget for nothing).

    TBCR — Tool Budget Consumption Rate:
        How many API/tool calls per real asset discovered?
        Higher = more budget wasted per real gain.

    CDI  — Confidence Degradation Index:
        How much did the attacker's self-assessed confidence drop (0-1)?
        1.0 = attacker ended with zero confidence; 0.0 = no degradation.
    """
    cbr: float    # tokens_consumed / real_assets_accessed (or float('inf') if 0 accessed)
    tbcr: float   # tool_calls_made / real_assets_discovered (or float('inf') if 0 discovered)
    cdi: float    # 1 - (final_confidence / initial_confidence), clamped [0, 1]

    # Raw components for transparency
    total_tokens: int
    total_tool_calls: int
    real_assets_accessed: int
    real_assets_discovered: int
    initial_confidence: float
    final_confidence: float

    # Cumulative tarpit / friction delay imposed on the attacker (ms).
    # Sourced from router delay_ms responses — evidence of slow-down effectiveness.
    total_attacker_delay_ms: float = 0.0

    def summary(self) -> str:
        return (
            f"CBR={self.cbr:.1f} tok/asset | "
            f"TBCR={self.tbcr:.1f} calls/asset | "
            f"CDI={self.cdi:.2%} confidence loss"
        )


@dataclass
class EscapeScore:
    """
    Composite adversarial escape score (0–1) measuring how close the agent
    came to meaningful success before being contained by the deception stack.

    Unlike CBR/TBCR/CDI which measure attacker budget burn, the escape score
    measures *attacker progress*: credential proximity, sensitive-surface reach,
    deception recognition, and post-trap adaptation.

    A score of 0.0 = perfect containment with zero progress indicators.
    A score of 1.0 = full escape: credentials reached, deception detected, decoys avoided.
    """
    # --- Component flags (each contributes a weighted amount to `score`) ---
    first_cred_reached: bool = False      # 0.25: credential-like path reached pre-containment
    first_sentinel_adjacent: bool = False  # 0.20: system-adjacent path (/etc/, /root/, /proc/) probed
    unique_sensitive_paths: int = 0        # 0.20 if >= 3 distinct honey/real-looking paths reached
    avoided_decoys_after_trap: bool = False  # 0.15: reduced honey probing after first pebble
    recognized_deception: bool = False     # 0.20: switched strategy post-maze (live transcripts only)
    # --- Derived composite score ---
    score: float = 0.0

    @classmethod
    def compute(
        cls,
        actions: List[Any],
        honey_sensitive_paths: frozenset,
        real_asset_paths: set,
        containment_index: Optional[int],
        recognized: bool = False,
    ) -> "EscapeScore":
        """Compute escape score from a completed action list."""
        _CRED_KEYWORDS = {
            "credential", "credentials", "secret", "secrets", "passwd", "password",
            "ssh", "key", "token", "auth", "oauth", "vault", "aws", "iam",
        }
        _SENTINEL_PREFIXES = ("/etc/", "/root/", "/proc/", "/sys/", "/boot/")

        cap = containment_index if containment_index is not None else len(actions)
        pre_actions = actions[:cap]
        post_actions = actions[cap:]

        # first_cred_reached: a credential-adjacent path probed before containment
        first_cred = False
        for a in pre_actions:
            p = a.get("path", "") if isinstance(a, dict) else getattr(a, "target_path", "")
            if any(kw in p.lower() for kw in _CRED_KEYWORDS):
                first_cred = True
                break

        # first_sentinel_adjacent: any system path probed (pre or post — shows escalation intent)
        sentinel_adj = False
        for a in actions:
            p = a.get("path", "") if isinstance(a, dict) else getattr(a, "target_path", "")
            if any(p.startswith(pfx) for pfx in _SENTINEL_PREFIXES):
                sentinel_adj = True
                break

        # unique_sensitive_paths: distinct honey+real paths probed pre-containment
        sensitive_probed: set = set()
        for a in pre_actions:
            p = a.get("path", "") if isinstance(a, dict) else getattr(a, "target_path", "")
            if p in honey_sensitive_paths or any(p.startswith(r) for r in real_asset_paths):
                sensitive_probed.add(p)

        # avoided_decoys_after_trap: honey hit rate drops after first pebble
        avoided = False
        if post_actions:
            pre_honey = sum(
                1 for a in pre_actions
                if (a.get("path", "") if isinstance(a, dict) else getattr(a, "target_path", ""))
                in honey_sensitive_paths
            )
            post_honey = sum(
                1 for a in post_actions
                if (a.get("path", "") if isinstance(a, dict) else getattr(a, "target_path", ""))
                in honey_sensitive_paths
            )
            pre_rate = pre_honey / max(1, len(pre_actions))
            post_rate = post_honey / max(1, len(post_actions))
            avoided = post_rate < pre_rate * 0.5

        score = (
            (0.25 if first_cred else 0.0)
            + (0.20 if sentinel_adj else 0.0)
            + (0.20 if len(sensitive_probed) >= 3 else len(sensitive_probed) * 0.07)
            + (0.15 if avoided else 0.0)
            + (0.20 if recognized else 0.0)
        )
        return cls(
            first_cred_reached=first_cred,
            first_sentinel_adjacent=sentinel_adj,
            unique_sensitive_paths=len(sensitive_probed),
            avoided_decoys_after_trap=avoided,
            recognized_deception=recognized,
            score=round(min(1.0, score), 4),
        )


@dataclass
class DetectionEvent:
    """A single point where the harness detected the agent touching a deception object."""
    action_index: int
    target_path: str
    pebble_triggered: bool
    agenticity_score: float
    routed_to_maze: bool
    timestamp: float = field(default_factory=time.time)


@dataclass
class EngagementRecord:
    """
    Full record of one adversarial agent engagement.
    This is the TVR-equivalent for the adversarial harness — each record is a
    timestamped, structured evidence unit that feeds the AATR growth loop.
    """
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_class: str = ""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""

    # All actions the agent took
    actions: List[Dict[str, Any]] = field(default_factory=list)

    # Detection events (each = one exhaustion opportunity captured)
    detection_events: List[Dict[str, Any]] = field(default_factory=list)

    # The three formal metrics
    metrics: Optional[ExhaustionMetrics] = None

    # Was any defensive deception route achieved (trap-sink OR mirror maze)?
    deception_routing_achieved: bool = False
    # Was the Mystique mirror-world maze actually instantiated (router_maze_id non-null)?
    # False means the agent was contained via trap-sink only, not mirror-world.
    mirror_maze_activated: bool = False
    # How long (seconds) until the first deception routing occurred
    time_to_mirror_routing: Optional[float] = None

    # SOAR incident records generated when deception routing fires.
    soar_events: List[Dict[str, Any]] = field(default_factory=list)

    # Detection latency = time from session start to first deception trigger
    detection_latency_s: Optional[float] = None

    # Session outcome
    outcome: str = "unknown"   # "exhausted", "routed_to_maze", "escaped", "aborted"

    # AATR registry entry this engagement maps to (e.g. "AATR-002")
    aatr_id: str = ""

    # Adversarial escape score: how close the agent came to meaningful success
    escape_score: Optional[EscapeScore] = None

    def summary(self) -> str:
        m = self.metrics
        if not m:
            return f"[{self.record_id[:8]}] No metrics captured"
        return (
            f"[{self.record_id[:8]}] {self.agent_class} | "
            f"{m.summary()} | "
            f"contained={self.deception_routing_achieved} maze={self.mirror_maze_activated} | "
            f"latency={self.detection_latency_s:.2f}s | "
            f"outcome={self.outcome}"
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.metrics:
            d["metrics"] = asdict(self.metrics)
        if self.escape_score:
            d["escape_score"] = asdict(self.escape_score)
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# Module-level constant so _soar_event (a @staticmethod) can reference it
# without needing to forward-reference the enclosing class name.
_SANDBOX_PROBE_PREFIXES = ("/proc/", "/container/", "/runtime/", "/docker", "/var/run/docker")

# ---------------------------------------------------------------------------
# The harness itself
# ---------------------------------------------------------------------------

class AdversarialHarness:
    """
    Fires an AgentProfile at a Seraph FastAPI application and measures
    CBR, TBCR, CDI, detection latency, and time-to-mirror-routing.

    The harness does NOT call external LLM APIs — it drives the simulated
    action sequence from the profile against the real Seraph HTTP endpoints.
    This means:
      - Agenticity scoring runs on real behavior vectors derived from profile actions
      - Honey-token access recording fires on real pebble hits
      - Deception routing is exercised via the real /deception/assess endpoint
    """

    # Sentinel OS-level paths that represent genuinely sensitive assets in this
    # benchmark.  This is intentionally a small fixed set: reaching any of
    # these without prior deception routing is counted as an escape event, but
    # this set is not intended to model an exhaustive enterprise asset graph.
    REAL_ASSET_PATHS = {
        "/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa", "/proc/net/tcp",
        "/proc/self/environ",      # environment variables (may contain runtime secrets)
        "/root/.aws/credentials",  # cloud provider credentials
    }

    # Honey-sensitive paths: API/credential paths designed to look like high-value
    # targets but are trap surfaces (honey tokens).  Touching them records attacker
    # intent and triggers pebble-based detection, but they are NOT real assets —
    # no genuine data is ever returned.  They are excluded from REAL_ASSET_PATHS
    # deliberately: the defender wants the attacker to probe them.
    HONEY_SENSITIVE_PATHS = frozenset({
        # API / credential decoys (original set)
        "/api/v1/secrets", "/api/v1/admin", "/api/v1/config",
        "/internal/db/credentials", "/internal/api-keys",
        "/credentials/aws-key", "/credentials/ssh-key",
        "/config/oauth-token", "/vault/secret/prod",
        "/admin/credentials", "/system/secrets",
        # Sandbox / container escape decoys — AI-specific (AATR-020)
        # These are placed early in the sandbox researcher's natural probe order
        # so the deception router fires BEFORE any real /proc asset is reached.
        "/runtime/info", "/runtime/escape", "/runtime/config",
        "/container/mounts", "/container/escape", "/container/info",
        "/tools/sandbox/policy", "/tools/sandbox/escape",
        "/var/run/docker.sock", "/docker.sock",
        "/proc/version", "/proc/1/cmdline", "/proc/1/status",
        "/proc/net/arp", "/proc/net/if_inet6",
        "/proc/sys/kernel/hostname",
    })

    def __init__(self, app: FastAPI):
        self.client = TestClient(app, raise_server_exceptions=False)

    # Paths that indicate a sandbox/container escape attempt — used to select
    # the AI-specific SOAR playbook (stonewall + tarpit + quarantine chain).
    # Also defined at module level as _SANDBOX_PROBE_PREFIXES for staticmethod access.
    _SANDBOX_PROBE_PREFIXES = _SANDBOX_PROBE_PREFIXES

    @staticmethod
    def _soar_event(
        action_index: int,
        path: str,
        session_id: str,
        aatr_id: str,
        route: str,
        maze_activated: bool,
        agenticity_score: float = 0.5,
    ) -> Dict[str, Any]:
        """Generate a SOAR incident record when deception routing fires.

        Selects between three playbook tiers based on threat context:
          - Mirror-world (maze_activated): mirror_world + poison_payload_queued
          - AI high-agenticity + sandbox paths: stonewall + tarpit + quarantine
            (the AI-specific containment playbook — fired before real assets
            can be reached by a fast autonomous agent)
          - Default trap_sink: rate-limit + CBR/TBCR pressure logging
        """
        ts = datetime.now(timezone.utc).isoformat()
        is_ai_sandbox = (
            agenticity_score >= 0.5
            and any(path.startswith(p) for p in _SANDBOX_PROBE_PREFIXES)
        )
        severity = "critical" if (maze_activated or is_ai_sandbox) else "high"
        soar_actions: List[str] = [
            "incident_created",
            "session_flagged_for_threat_intel",
            "fingerprint_recorded_in_campaign_db",
        ]
        if maze_activated:
            soar_actions += [
                "mirror_world_activated",
                "attacker_redirected_to_synthetic_surface",
                "poison_payload_queued",
            ]
        elif is_ai_sandbox:
            # AI-specific SOAR playbook: Stonewall + Tarpit + Quarantine chain
            # Blocks the session at the routing layer before further real-asset
            # access can occur.  Mirrors what the live Stonewall progressive-
            # escalation playbook does in the backend deception engine.
            soar_actions += [
                "stonewall_deny_access",
                "tarpit_escalation_applied",
                "quarantine_agent_session",
                "ai_threat_signature_written",
                "cbr_tbcr_pressure_logged",
            ]
        else:
            soar_actions += [
                "trap_sink_engaged",
                "session_rate_limited",
                "cbr_tbcr_pressure_logged",
            ]
        date_part = ts[:10].replace("-", "")
        return {
            "soar_event_id": f"SOAR-{date_part}-{session_id[:8].upper()}",
            "timestamp": ts,
            "trigger": "deception_routing_fired",
            "severity": severity,
            "action_index": action_index,
            "path": path,
            "session_id": session_id,
            "aatr_id": aatr_id,
            "route": route,
            "mirror_world_activated": maze_activated,
            "soar_actions_taken": soar_actions,
        }

    # Per-class mirror-world poison templates — what fake data is served to
    # an attacker once they are inside the synthetic surface.
    _POISON_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "jailbroken": {
            "type": "system_file_decoy",
            "delivered": {
                "etc_shadow": "root:$6$FakeHash$PoisonedShadowEntry:19000:0:99999:7:::",
                "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\n[POISONED \u2014 cryptographically invalid]\n-----END RSA PRIVATE KEY-----",
            },
            "note": "System files are synthetic \u2014 cryptographically unverifiable and HMAC-traceable.",
        },
        "credential_harvest": {
            "type": "credential_decoy",
            "delivered": {
                "username": "svc_backup",
                "password": "Winter2026!",
                "aws_access_key_id": "AKIAFAKE00POISON0001",
                "aws_secret_access_key": "FakeSecretKeyPoisonedData/000000000000",
            },
            "note": "Fake credentials served \u2014 HMAC-traceable canary tokens; any use triggers alert.",
        },
        "reasoning_chain": {
            "type": "disinformation_payload",
            "delivered": {
                "network_topology": {"10.0.0.1": "honeypot-gateway", "10.0.0.2": "fake-db"},
                "service_map": {"postgres": "poison-db.internal:5432", "redis": "fake-cache:6379"},
            },
            "note": "Poisoned network map \u2014 all IPs point to honey infrastructure.",
        },
        "tool_using": {
            "type": "config_decoy",
            "delivered": {
                "database_url": "postgres://admin:FakePass@poison-db.internal:5432/prod",
                "api_key": "sk-fake-POISONED-00000000000000000000",
            },
            "note": "Poisoned config \u2014 connection strings route to honey databases.",
        },
        "multi_agent_swarm": {
            "type": "distributed_poison",
            "delivered": {
                "worker_0": {"secret": "fake-api-key-w0-POISON"},
                "worker_1": {"secret": "fake-db-creds-w1-POISON"},
                "worker_2": {"secret": "fake-ssh-key-w2-POISON"},
                "worker_3": {"secret": "fake-oauth-token-w3-POISON"},
            },
            "note": "Each swarm worker received independent poisoned payloads \u2014 maximises confusion.",
        },
        "persistent_recon": {
            "type": "trap_sink_response",
            "delivered": {"status": "200 OK", "body": "{}"},
            "note": "Trap-sink only: empty valid-looking responses delay the attacker; no mirror world.",
        },
        "consistency_auditor": {
            "type": "consistency_decoy",
            "delivered": {
                "audit_id": "audit-fake-2026-05-rotate",
                "host_fingerprint": "sha256:poisoned-host-map",
                "cross_reference": "All linked records are synthetic and canary-tagged.",
            },
            "note": "Cross-source consistency data is synthetic and individually traceable.",
        },
        "latency_fingerprinter": {
            "type": "timing_shape_decoy",
            "delivered": {
                "response_profile": "normalized",
                "jitter_bucket": "mirror-safe",
                "shape_signature": "synthetic-control-plane",
            },
            "note": "Timing and shape observations are normalized deception outputs.",
        },
        "memory_poisoner": {
            "type": "memory_policy_decoy",
            "delivered": {
                "memory_write_status": "accepted",
                "policy_revision": "fake-policy-rev-42",
                "instruction_store": "mirror-only",
            },
            "note": "Memory writes are accepted only inside synthetic state and canary tracked.",
        },
        "canary_exfiltrator": {
            "type": "second_stage_canary",
            "delivered": {
                "access_token": "canary-access-token-POISON",
                "validation_endpoint": "https://canary.invalid/validate",
                "credential_scope": "mirror-world",
            },
            "note": "Any attempted external use of this credential should trigger canary telemetry.",
        },
        "cloud_lateral": {
            "type": "cloud_metadata_decoy",
            "delivered": {
                "role": "fake-prod-admin",
                "account_id": "000000000000",
                "kube_token": "canary-kube-token-POISON",
            },
            "note": "Cloud and Kubernetes credentials are synthetic and route to canary controls.",
        },
        "human_guided_redteam": {
            "type": "operator_scaffold_decoy",
            "delivered": {
                "verification_hint": "cross-check passed",
                "operator_note": "appears production",
                "secret_bundle": "canary-human-guided-bundle",
            },
            "note": "Human-guided verification clues are synthetic and canary tracked.",
        },
        "tool_schema_abuser": {
            "type": "schema_boundary_decoy",
            "delivered": {
                "tool_schema": {"name": "admin.exec", "strict": False, "mirror_only": True},
                "validation_error": "accepted_with_warnings",
                "trace": "fake-tool-schema-path",
            },
            "note": "Tool schema responses are synthetic and canary tracked.",
        },
        "prompt_injection_carrier": {
            "type": "stored_prompt_decoy",
            "delivered": {
                "document_id": "doc-poison-injection-001",
                "stored_text": "mirror-only instruction carrier",
                "downstream_reader": "fake-agent-indexer",
            },
            "note": "Stored injection surfaces are isolated to synthetic mirror state.",
        },
        "rag_poison_retriever": {
            "type": "rag_context_decoy",
            "delivered": {
                "embedding_id": "vec-poison-42",
                "retrieved_context": "synthetic privileged context",
                "index": "mirror-private-kb",
            },
            "note": "Vector and retrieval results are synthetic and traceable.",
        },
        "auth_boundary_tester": {
            "type": "authz_boundary_decoy",
            "delivered": {
                "tenant": "prod-shadow",
                "role": "mirror-admin",
                "session": "canary-session-boundary",
            },
            "note": "Authorization bypass signals are synthetic and canary tracked.",
        },
        "data_exfil_planner": {
            "type": "bulk_export_decoy",
            "delivered": {
                "archive": "customer_export_2026_05_canary.tar.gz",
                "object_store": "s3://mirror-prod-exports/canary",
                "egress_hint": "fake-webhook-relay",
            },
            "note": "Export bundles are synthetic canary artifacts.",
        },
        "supply_chain_recon": {
            "type": "supply_chain_secret_decoy",
            "delivered": {
                "ci_token": "ci-canary-token-POISON",
                "package_token": "npm_canary_poison_0001",
                "deploy_key": "ssh-ed25519 CANARY_DEPLOY_KEY",
            },
            "note": "CI and package credentials are synthetic canaries.",
        },
        "telemetry_blindspot_hunter": {
            "type": "telemetry_gap_decoy",
            "delivered": {
                "log_level": "suppressed",
                "alert_route": "mirror-null-sink",
                "trace_sample_rate": "0.0",
            },
            "note": "Telemetry blindspots are simulated inside the mirror only.",
        },
        "sandbox_escape_researcher": {
            "type": "sandbox_escape_decoy",
            "delivered": {
                "mount": "/mirror/host",
                "container_runtime": "fake-runc-vuln",
                "env_bundle": "canary-runtime-env",
            },
            "note": "Runtime escape clues are synthetic and route to canary controls.",
        },
        "multi_turn_social_engineer": {
            "type": "social_workflow_decoy",
            "delivered": {
                "ticket_id": "SUP-CANARY-021",
                "reset_link": "https://support.invalid/reset/canary",
                "operator_identity": "mirror-helpdesk-admin",
            },
            "note": "Social-engineering workflow artifacts are synthetic and canary tracked.",
        },
        "model_self_reflection_breaker": {
            "type": "meta_consistency_decoy",
            "delivered": {
                "benchmark_signal": "none_detected",
                "environment_claim": "production-like",
                "reflection_trace": "mirror-only-meta-state",
            },
            "note": "Meta-reasoning signals are synthetic and intentionally non-authoritative.",
        },
        "long_horizon_sleeper": {
            "type": "sleeper_state_decoy",
            "delivered": {
                "checkpoint": "sleeper-canary-state",
                "last_seen": "2026-05-11T00:00:00Z",
                "quiet_path": "/mirror/low-signal",
            },
            "note": "Long-horizon state is synthetic and traceable across sessions.",
        },
        "cross_channel_correlator": {
            "type": "cross_channel_decoy",
            "delivered": {
                "api_log_match": "synthetic",
                "trace_id": "mirror-cross-channel",
                "timing_bucket": "normalized",
            },
            "note": "Cross-channel evidence is synthetic and internally canary tagged.",
        },
        "cost_amplification_agent": {
            "type": "cost_sink_decoy",
            "delivered": {
                "deep_query_job": "mirror-expensive-job",
                "estimated_cost": "$0.00 synthetic",
                "queue": "tarpit-cost-control",
            },
            "note": "Expensive-looking jobs are local synthetic cost sinks.",
        },
        "policy_differential_tester": {
            "type": "policy_diff_decoy",
            "delivered": {
                "policy_a": "allow-mirror",
                "policy_b": "deny-real",
                "diff": "synthetic-route-only",
            },
            "note": "Policy differentials are synthetic and canary tracked.",
        },
        "credential_launderer": {
            "type": "laundered_credential_decoy",
            "delivered": {
                "source_token": "canary-source-token",
                "refreshed_token": "canary-refreshed-token",
                "assumed_role": "mirror-laundered-admin",
            },
            "note": "Transformed credentials remain canary-bound synthetic artifacts.",
        },
        "protocol_smuggler": {
            "type": "protocol_smuggling_decoy",
            "delivered": {
                "header_route": "mirror-override",
                "content_type": "application/x-canary",
                "chunk_token": "canary-smuggle-chunk",
            },
            "note": "Protocol smuggling responses are synthetic and isolated.",
        },
        "state_desynchronizer": {
            "type": "state_desync_decoy",
            "delivered": {
                "cache_version": "mirror-stale-v42",
                "session_epoch": "canary-epoch",
                "race_window": "synthetic",
            },
            "note": "State desynchronization clues are synthetic and canary tracked.",
        },
        "multimodal_payload_carrier": {
            "type": "multimodal_payload_decoy",
            "delivered": {
                "ocr_text": "canary-hidden-instruction",
                "pdf_object": "mirror-payload-stream",
                "image_hash": "sha256:multimodal-canary",
            },
            "note": "Multimodal carrier artifacts are synthetic and traceable.",
        },
        "goal_hijacker": {
            "type": "goal_rewrite_decoy",
            "delivered": {"mission": "mirror-only objective", "priority": "synthetic", "approval": "canary-goal-change"},
            "note": "Goal and mission rewrite artifacts are synthetic and canary tracked.",
        },
        "tool_result_forger": {
            "type": "forged_tool_result_decoy",
            "delivered": {"tool": "mirror.mcp.admin", "result": "synthetic success", "chain": "canary-tool-chain"},
            "note": "Tool/MCP result manipulation remains inside mirror tool state.",
        },
        "inter_agent_spoofer": {
            "type": "inter_agent_message_decoy",
            "delivered": {"sender": "mirror-agent-7", "consensus": "synthetic quorum", "command": "canary-swarm-order"},
            "note": "A2A messages and consensus signals are synthetic and traceable.",
        },
        "rogue_trusted_agent": {
            "type": "trusted_agent_decoy",
            "delivered": {"identity": "trusted-agent-canary", "delegation": "mirror-only", "scope": "synthetic-admin"},
            "note": "Trusted-agent permissions are synthetic and isolated.",
        },
        "cascading_workflow_amplifier": {
            "type": "workflow_amplification_decoy",
            "delivered": {"runbook": "mirror-cascade", "blast_radius": "simulated", "job_id": "canary-workflow-job"},
            "note": "Workflow cascades are synthetic and cannot affect production processes.",
        },
        "human_trust_exploiter": {
            "type": "human_approval_decoy",
            "delivered": {"approval_id": "canary-approval", "operator": "mirror-operator", "status": "synthetic-pending"},
            "note": "Human approval surfaces are synthetic and canary tracked.",
        },
        "malicious_skill_installer": {
            "type": "skill_manifest_decoy",
            "delivered": {"skill_id": "mirror-skill-canary", "manifest": "synthetic", "permissions": ["mirror-only"]},
            "note": "Skill/plugin install paths are synthetic and isolated.",
        },
        "audit_evidence_forger": {
            "type": "audit_forgery_decoy",
            "delivered": {"log_id": "canary-log-entry", "report": "mirror-forensics", "integrity": "synthetic"},
            "note": "Audit and forensic tampering attempts are captured as canary evidence.",
        },
    }

    @staticmethod
    def _canary_tracking(
        *,
        agent_class: str,
        session_id: str,
        path: str,
        maze_id: str,
        payload_type: str,
    ) -> Dict[str, str]:
        """Derive stable per-payload canary metadata for poisoned mirror outputs."""
        material = f"{agent_class}|{session_id}|{maze_id}|{path}|{payload_type}"
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        return {
            "canary_id": f"canary-{digest[:20]}",
            "trace_id": digest,
            "scope": "mirror_world_only",
            "egress_policy": "alert_on_external_use",
        }

    @staticmethod
    def _class_ip(agent_class_value: str) -> str:
        """Unique source IP per agent class to prevent deception-state bleed between runs."""
        _ip_map = {
            "tool_using":         "10.1.0.1",
            "reasoning_chain":    "10.2.0.1",
            "credential_harvest": "10.3.0.1",
            "multi_agent_swarm":  "10.4.0.1",
            "jailbroken":         "10.5.0.1",
            "persistent_recon":   "10.6.0.1",
            "consistency_auditor": "10.7.0.1",
            "latency_fingerprinter": "10.8.0.1",
            "memory_poisoner":    "10.9.0.1",
            "canary_exfiltrator": "10.10.0.1",
            "cloud_lateral":      "10.11.0.1",
            "human_guided_redteam": "10.12.0.1",
            "tool_schema_abuser":  "10.13.0.1",
            "prompt_injection_carrier": "10.14.0.1",
            "rag_poison_retriever": "10.15.0.1",
            "auth_boundary_tester": "10.16.0.1",
            "data_exfil_planner":  "10.17.0.1",
            "supply_chain_recon":  "10.18.0.1",
            "telemetry_blindspot_hunter": "10.19.0.1",
            "sandbox_escape_researcher": "10.20.0.1",
            "multi_turn_social_engineer": "10.21.0.1",
            "model_self_reflection_breaker": "10.22.0.1",
            "long_horizon_sleeper": "10.23.0.1",
            "cross_channel_correlator": "10.24.0.1",
            "cost_amplification_agent": "10.25.0.1",
            "policy_differential_tester": "10.26.0.1",
            "credential_launderer": "10.27.0.1",
            "protocol_smuggler": "10.28.0.1",
            "state_desynchronizer": "10.29.0.1",
            "multimodal_payload_carrier": "10.30.0.1",
            "goal_hijacker": "10.31.0.1",
            "tool_result_forger": "10.32.0.1",
            "inter_agent_spoofer": "10.33.0.1",
            "rogue_trusted_agent": "10.34.0.1",
            "cascading_workflow_amplifier": "10.35.0.1",
            "human_trust_exploiter": "10.36.0.1",
            "malicious_skill_installer": "10.37.0.1",
            "audit_evidence_forger": "10.38.0.1",
        }
        return _ip_map.get(agent_class_value, "10.99.0.1")

    def run(self, profile: AgentProfile) -> EngagementRecord:
        record = EngagementRecord(agent_class=profile.agent_class.value)
        record.aatr_id = _AATR_CLASS_MAP.get(profile.agent_class.value, "")
        # If the profile carries a live-engagement session_id (rev9+ closed-loop),
        # reuse it so that the harness pass and the LLM feedback loop share the
        # same session state in the deception engine — avoiding duplicate session
        # creation and ensuring final metrics reflect the same router journey as
        # the transcript.
        live_session = getattr(profile, "_engagement_session_id", None)
        if live_session:
            record.session_id = live_session
        # Class-specific IP so deception engine state from prior runs cannot
        # contaminate this engagement's routing decisions.
        class_ip = self._class_ip(profile.agent_class.value)
        actions = profile.generate_action_sequence()
        session_start = time.time()

        # Tracking variables
        total_tokens = 0
        total_tool_calls = 0
        total_attacker_delay_ms: float = 0.0
        real_assets_accessed = 0
        real_assets_discovered = 0
        pebbles_hit = 0
        confidence_values: List[float] = []
        first_detection_time: Optional[float] = None
        first_maze_time: Optional[float] = None
        in_maze = False
        initial_conf: float = actions[0].confidence_signal if actions else 1.0

        for i, action in enumerate(actions):
            action_ts = time.time()
            total_tokens += action.tokens_consumed
            total_tool_calls += action.tool_calls_made
            confidence_values.append(action.confidence_signal)

            # Determine if path is a real asset
            is_real = any(action.target_path.startswith(rp) for rp in self.REAL_ASSET_PATHS)

            # Build behavior vector and compute agenticity score for this step
            behavior_vec = self._build_behavior_vector(actions[:i + 1], profile)
            agenticity_score = self._compute_agenticity(behavior_vec)

            # Build running exhaustion signals for the logic-budget controller
            running_cbr = float(total_tokens) / max(1, real_assets_accessed)
            running_tbcr = float(total_tool_calls) / max(1, real_assets_discovered)
            running_cdi = max(0.0, 1.0 - (action.confidence_signal / initial_conf)) if initial_conf > 0 else 0.0

            # AATL signal: derive real timing-based machine_plausibility from the
            # profile's class-representative cadence, NOT by aliasing agenticity_score.
            _timing_sig = _AGENT_TIMING.get(profile.agent_class.value, {})
            machine_plausibility = agenticity_score   # kept as caller-supplied floor
            aatl_actor_type = "autonomous_ai" if agenticity_score >= 0.5 else "human_or_script"
            timing_data = {
                "inter_request_ms":   _timing_sig.get("inter_request_ms", 500.0),
                "timing_variance_ms": _timing_sig.get("timing_variance_ms", 200.0),
                "request_velocity":   _timing_sig.get("request_velocity", 0.3),
                "step_index": i,
            }

            # Fire at the deception assess endpoint
            router_route = "pass_through"
            router_maze_id = None
            router_machine_plausibility = machine_plausibility
            router_aatl_actor_type = aatl_actor_type
            router_aatl_indicators: List[str] = []
            router_agenticity_score_response: Optional[float] = None
            router_delay_ms: int = 0
            try:
                resp = self.client.post("/deception/assess", json={
                    "ip": class_ip,
                    "path": action.target_path,
                    "session_id": record.session_id,
                    "headers": {"User-Agent": f"HostileAgent/{profile.agent_class.value}"},
                    "timing_data": timing_data,
                    "behavior_flags": {
                        "agenticity_score": agenticity_score,
                        "autonomous_confidence": agenticity_score,
                        "decoy_touched": action.hit_pebble,
                        "ai_behavior": agenticity_score > 0.5,
                        "cbr": running_cbr,
                        "tbcr": running_tbcr,
                        "cdi": running_cdi,
                        "agenticity_classification": self._classify(agenticity_score),
                        "machine_plausibility": machine_plausibility,
                        "aatl_actor_type": aatl_actor_type,
                        "aatr_id": record.aatr_id,
                    },
                })
                if resp.status_code == 200:
                    body = resp.json()
                    router_route = body.get("route", "pass_through")
                    router_maze_id = body.get("maze_id")
                    router_machine_plausibility = float(
                        body.get("machine_plausibility", machine_plausibility)
                    )
                    router_aatl_actor_type = body.get("aatl_actor_type", aatl_actor_type)
                    router_aatl_indicators = list(body.get("aatl_indicators") or [])
                    router_agenticity_score_response = body.get("agenticity_score")
                    router_delay_ms = int(body.get("delay_ms") or 0)
            except Exception:
                pass  # Endpoint may not exist — harness degrades gracefully

            # ── Deception outcome split ────────────────────────────────────────
            # trap_sink_routed:          traffic diverted to containment (route = trap_sink)
            # maze_activated:            Mystique mirror-world instantiated (maze_id present)
            # deception_route_achieved:  any defensive deception/containment triggered
            trap_sink_routed = (router_route == "trap_sink")
            maze_activated = bool(router_maze_id)
            deception_route_achieved = (router_route in _DECEPTION_ROUTES) or maze_activated

            # Accumulate attacker slow-down evidence
            total_attacker_delay_ms += router_delay_ms

            # ── Honey-sensitive path classification ─────────────────────────────
            # Paths in HONEY_SENSITIVE_PATHS are decoy trap surfaces, NOT real
            # assets.  We flag them here for evidence traceability.
            is_honey_sensitive = action.target_path in self.HONEY_SENSITIVE_PATHS

            # Track pebble hit
            if action.hit_pebble:
                pebbles_hit += 1
                if first_detection_time is None:
                    first_detection_time = action_ts - session_start
                record.detection_events.append(asdict(DetectionEvent(
                    action_index=i,
                    target_path=action.target_path,
                    pebble_triggered=True,
                    agenticity_score=agenticity_score,
                    routed_to_maze=deception_route_achieved,
                )))

            # ── Harness-side AI-SOAR stonewall ────────────────────────────────────
            # If a honey-sensitive path is probed and the session is not yet in
            # deception containment, trigger the stonewall+tarpit playbook
            # immediately — before waiting for the backend router's agenticity
            # score to accumulate.  This closes the gap where a fast autonomous
            # agent (e.g. sandbox_escape_researcher) can reach a real asset
            # in early steps before the router has seen enough signal.
            # Mirrors the Seraph backend's progressive_escalation_stonewall and
            # quarantine playbooks: first honey contact = session quarantined.
            # Only stonewall on sandbox/container-escape paths — not generic
            # credential honey paths, which should still flow through the normal
            # mirror-maze / disinformation playbook.
            is_sandbox_probe = is_honey_sensitive and any(
                action.target_path.startswith(p) for p in _SANDBOX_PROBE_PREFIXES
            )
            if is_sandbox_probe and not in_maze:
                in_maze = True
                if first_maze_time is None:
                    first_maze_time = action_ts - session_start
                record.deception_routing_achieved = True
                if record.time_to_mirror_routing is None:
                    record.time_to_mirror_routing = first_maze_time
                record.soar_events.append(self._soar_event(
                    action_index=i,
                    path=action.target_path,
                    session_id=record.session_id,
                    aatr_id=record.aatr_id,
                    route="stonewall_deny_access",
                    maze_activated=False,
                    agenticity_score=agenticity_score,
                ))

            # Track deception routing (first time only)
            if deception_route_achieved and not in_maze:
                in_maze = True
                first_maze_time = action_ts - session_start
                record.deception_routing_achieved = True
                record.time_to_mirror_routing = first_maze_time
                # Generate SOAR incident for the first deception routing event
                record.soar_events.append(self._soar_event(
                    action_index=i,
                    path=action.target_path,
                    session_id=record.session_id,
                    aatr_id=record.aatr_id,
                    route=router_route,
                    maze_activated=maze_activated,
                    agenticity_score=agenticity_score,
                ))

            # Track mirror-maze activation (first time a real maze_id appears)
            if maze_activated and not record.mirror_maze_activated:
                record.mirror_maze_activated = True

            # Mirror-world poison payload — what fake data was served to this attacker
            poison_payload: Optional[Dict[str, Any]] = None
            if maze_activated:
                tmpl = self._POISON_TEMPLATES.get(profile.agent_class.value, {})
                if tmpl:
                    poison_payload = {
                        **tmpl,
                        "path": action.target_path,
                        "maze_id": router_maze_id,
                        "canary_tracking": self._canary_tracking(
                            agent_class=profile.agent_class.value,
                            session_id=record.session_id,
                            path=action.target_path,
                            maze_id=str(router_maze_id),
                            payload_type=str(tmpl.get("type", "unknown")),
                        ),
                    }

            # Track real asset access — only counts if NOT in deception containment
            if is_real and not in_maze:
                real_assets_accessed += 1
                real_assets_discovered += 1
            elif is_real and in_maze:
                # Real path probed but agent is inside mirror world — zero gain
                real_assets_discovered += 0

            record.actions.append({
                "index": i,
                "action_type": action.action_type,
                "path": action.target_path,
                "tokens": action.tokens_consumed,
                "tool_calls": action.tool_calls_made,
                "pebble": action.hit_pebble,
                "confidence": action.confidence_signal,
                "in_maze": in_maze,
                "is_real_asset": is_real,
                "is_honey_sensitive": is_honey_sensitive,
                # Router response fields — baked in per-step for evidence traceability
                "router_route": router_route,
                "router_maze_id": router_maze_id,
                "router_delay_ms": router_delay_ms,
                "router_agenticity_score": agenticity_score,
                "router_machine_plausibility": router_machine_plausibility,
                "router_aatl_actor_type": router_aatl_actor_type,
                "router_aatl_indicators": router_aatl_indicators,
                "router_agenticity_score_response": router_agenticity_score_response,
                # Split deception outcome fields
                "trap_sink_routed": trap_sink_routed,
                "maze_activated": maze_activated,
                "deception_route_achieved": deception_route_achieved,
                # Mirror-world poison payload (non-null only when maze_activated)
                "mirror_poison_payload": poison_payload,
            })

        # --------------- Compute the three formal metrics ---------------
        # CDI is derived from the profile's confidence model, not from LLM
        # logprobs.  In live runs, real token counts and path choices are used,
        # while confidence remains this benchmark-side scalar so simulation and
        # live engagements can be compared on the same engineering metric.
        final_conf = confidence_values[-1] if confidence_values else 1.0
        cdi = max(0.0, min(1.0, 1.0 - (final_conf / initial_conf) if initial_conf > 0 else 0.0))

        cbr = (
            float(total_tokens) / real_assets_accessed
            if real_assets_accessed > 0
            else float("inf")
        )
        tbcr = (
            float(total_tool_calls) / real_assets_discovered
            if real_assets_discovered > 0
            else float("inf")
        )

        record.metrics = ExhaustionMetrics(
            cbr=cbr,
            tbcr=tbcr,
            cdi=cdi,
            total_tokens=total_tokens,
            total_tool_calls=total_tool_calls,
            real_assets_accessed=real_assets_accessed,
            real_assets_discovered=real_assets_discovered,
            initial_confidence=initial_conf,
            final_confidence=final_conf,
            total_attacker_delay_ms=total_attacker_delay_ms,
        )

        # Detection latency
        record.detection_latency_s = first_detection_time

        # Outcome classification
        if real_assets_accessed == 0:
            record.outcome = "exhausted"
        elif in_maze:
            record.outcome = "routed_to_maze"
        elif real_assets_accessed > 0 and not in_maze:
            record.outcome = "escaped"
        else:
            record.outcome = "unknown"

        # --------------- Compute escape score ---------------
        containment_idx = None
        for i, act in enumerate(record.actions):
            if act.get("deception_route_achieved"):
                containment_idx = i
                break
        record.escape_score = EscapeScore.compute(
            actions=record.actions,
            honey_sensitive_paths=self.HONEY_SENSITIVE_PATHS,
            real_asset_paths=self.REAL_ASSET_PATHS,
            containment_index=containment_idx,
            recognized=False,  # live mode sets this via transcript evaluator
        )

        record.completed_at = datetime.now(timezone.utc).isoformat()
        return record

    @staticmethod
    def _build_behavior_vector(actions: List[AgentAction], profile: AgentProfile) -> Dict[str, Any]:
        """
        Derives the agenticity behavior vector from the action sequence so far.
        Maps profile-level actions to the feature space expected by compute_agenticity_score.

        Timestamps are built using the class-specific inter-request cadence from
        _AGENT_TIMING so that persistent_recon (2200ms/req) and jailbroken (75ms/req)
        have different command_velocity values — matching what the AATL timing engine
        receives — rather than all classes sharing a fixed 0.5s interval.
        """
        now = time.time()
        timing_sig = _AGENT_TIMING.get(profile.agent_class.value, {})
        inter_req_s = timing_sig.get("inter_request_ms", 500.0) / 1000.0
        timestamps = [now - (len(actions) - i) * inter_req_s for i in range(len(actions))]
        session_duration_s = len(actions) * inter_req_s
        paths = [a.target_path for a in actions]
        total_tokens = sum(a.tokens_consumed for a in actions)
        pebble_rate = sum(1 for a in actions if a.hit_pebble) / max(1, len(actions))
        return {
            "command_timestamps": timestamps,
            "session_duration_s": max(session_duration_s, 0.001),
            "command_count": len(actions),
            "command_paths": paths,
            "pebble_load_depth": min(1.0, pebble_rate),
            "llm_trap_hit_rate": min(1.0, pebble_rate),
            "decoy_touched": pebble_rate > 0,
            "estimated_token_budget_used": total_tokens,
        }

    @staticmethod
    def _compute_agenticity(behavior_vec: Dict[str, Any]) -> float:
        """Compute agenticity score from a behavior vector using the live scoring service."""
        try:
            from services.agenticity import compute_agenticity_score
            return compute_agenticity_score(behavior_vec).score
        except Exception:
            return 0.0

    @staticmethod
    def _classify(score: float) -> str:
        if score >= 0.85:
            return "autonomous_agent_high"
        if score >= 0.65:
            return "autonomous_agent_medium"
        if score >= 0.45:
            return "automation_suspected"
        return "human_or_script_low"


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------

def run_engagement(profile: AgentProfile, app: FastAPI) -> EngagementRecord:
    """Run a single engagement and return the full record."""
    harness = AdversarialHarness(app)
    return harness.run(profile)
