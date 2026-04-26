# Metatron Feature Reality Matrix

Updated: 2026-04-26

Scope: code-evidence snapshot of implemented platform behavior. This document replaces older percentage/marketing claims with a practical matrix of what the repository currently wires, what executes in normal local/container runs, and what remains conditional on external systems.

## Status legend

- `PASS`: implemented code path is present and used by the active application.
- `PARTIAL`: implemented code path exists, but material behavior depends on credentials, optional services, production infrastructure, or deeper assurance.
- `LIMITED`: compatibility, simulation-safe, in-memory, or framework-only behavior.

## Current feature maturity matrix

| Domain | Status | Current code evidence | Reality notes |
|---|---|---|---|
| FastAPI control plane | PASS | `backend/server.py` | Main app connects MongoDB, initializes world model and triune services, registers broad `/api/*` and `/api/v1/*` router mesh, and exposes `/api/health`. |
| React SOC dashboard | PASS | `frontend/src/App.js` | React 19/CRACO app with protected routes. Recent UI is consolidated into workspace pages (`/command`, `/ai-activity`, `/response-operations`, `/investigation`, `/email-security`, `/endpoint-mobility`) with redirects from older routes. |
| Mongo-backed platform state | PASS | `backend/server.py`, router/service modules | MongoDB is the primary persistence layer for alerts, agents, commands, world model state, governance decisions, and telemetry-oriented records. |
| Unified agent control plane | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Agent registration, heartbeats, telemetry, downloads/install scripts, EDM dataset handling, and command metadata are implemented. Impactful commands route through governed dispatch. |
| Endpoint agent monitor set | PASS | `unified_agent/core/agent.py` | Large monitor collection includes process, network, registry, DNS, memory, DLP, vulnerability, AMSI, ransomware, rootkit, kernel, self-protection, identity, CLI, email, mobile, YARA, and related checks. |
| World model and event bus | PASS | `backend/services/world_model.py`, `backend/services/world_events.py`, `backend/routers/world_ingest.py` | Ingest endpoints upsert entities/edges/detections and emit canonical world events. Events are classified as passive/local/strategic/action-critical before optional triune recompute. |
| Triune orchestration | PASS | `backend/services/triune_orchestrator.py`, `backend/triune/*.py` | `TriuneOrchestrator` builds a world snapshot, enriches cognition, runs Metatron assessment, Michael action ranking, Loki challenge/advisory, and beacon cascade logic. |
| Metatron strategic scoring | PASS | `backend/triune/metatron.py` | Strategic pressure blends hotspot risk, sector risk, active responses, and cognition-fabric signals. Output includes policy tier suggestion, confidence, predicted sectors, and recommended posture. |
| Michael response planning | PASS | `backend/triune/michael.py` | Ranks response candidates with keyword, entity risk, recency, graph degree, optional AI explanation, and policy-tier context. |
| Loki dissent/hunting | PASS | `backend/triune/loki.py` | Generates alternative hypotheses, hunt suggestions, deception suggestions, uncertainty markers, and challenges selected hard-disruption actions when cognitive signals prefer deception/poisoning. |
| High-impact governance gate | PASS | `backend/services/outbound_gate.py`, `backend/services/governed_dispatch.py`, `backend/routers/governance.py` | Mandatory high-impact action types are forced to high impact and triune approval. Pending decisions are stored in `triune_outbound_queue` and `triune_decisions`; approvals can release execution. |
| Governance execution mapping | PASS/PARTIAL | `backend/services/governance_executor.py` | Approved decisions map into domain actions such as agent commands, swarm commands, response operations, quarantine, VPN, and tool execution. Coverage is broad but still depends on individual domain executors. |
| Token/tool boundary controls | PARTIAL | `backend/services/token_broker.py`, `backend/services/tool_gateway.py` | Scoped token and governed tool execution primitives exist and can require governance context through environment flags. Production assurance depends on strict configuration and tests. |
| Vector memory | PASS/PARTIAL | `backend/services/vector_memory.py`, `backend/routers/advanced.py` | Namespaced memory entries, trust levels, embeddings, case creation, similarity search, and stats are exposed under `/api/advanced/memory/*`. Some storage and embedding behavior is service-local/in-process. |
| AATL/AATR/cognition fabric | PASS/PARTIAL | `backend/services/aatl.py`, `backend/services/aatr.py`, `backend/services/cognition_fabric.py` | Autonomous-agent heuristics, registry-style behavior matching, and fused cognitive signals feed triune logic. Detection-quality calibration remains an assurance task. |
| Email protection | PASS/PARTIAL | `backend/email_protection.py`, `backend/routers/email_protection.py`, agent email monitor | SPF/DKIM/DMARC, phishing/content heuristics, attachment checks, DLP-style patterns, and protected-user workflows exist. External DNS/reputation quality and deployment configuration affect fidelity. |
| Email gateway | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | API-driven message processing, quarantine, blocklist/allowlist, policies, and stats are implemented. Production SMTP relay operation still requires real mail-server integration and operational policy. |
| Mobile security | PASS/PARTIAL | `backend/mobile_security.py`, `backend/routers/mobile_security.py`, agent mobile monitor | Device registration, app/security checks, risk/compliance scoring, threat lifecycle, and dashboard APIs exist. Real mobile fleet coverage depends on enrollment and telemetry sources. |
| MDM connectors | PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Intune, JAMF, Workspace ONE, and Google Workspace connector framework with sync/actions is present. Live value requires production API credentials and tenant-specific validation. |
| CSPM | PASS/PARTIAL | `backend/cspm_engine.py`, cloud scanners, `backend/routers/cspm.py` | AWS/Azure/GCP scan surfaces exist and the router is registered under `/api/v1`. Production scan completeness depends on cloud credentials and provider permissions. |
| Browser isolation | PARTIAL | `backend/browser_isolation.py`, frontend page | URL analysis/filtering/sanitization flows exist. True remote browser isolation/pixel streaming is not implemented as an enterprise isolation product. |
| Container/kernel/security sensors | PARTIAL | `backend/container_security.py`, `backend/enhanced_kernel_security.py`, `backend/ebpf_kernel_sensors.py`, docker compose services | Trivy/Falco/Suricata/Zeek/osquery-related integrations and kernel-sensor APIs exist. Host privileges, mounted logs, kernel support, and optional service availability determine runtime depth. |
| AI reasoning and LLM augmentation | PARTIAL | `backend/services/ai_reasoning.py`, `backend/ai/*`, Ollama config | Rule-based and optional LLM paths exist. Quality and latency depend on configured local/remote model services. |
| Integrations runtime | PARTIAL | `backend/routers/integrations.py`, `unified_agent/integrations/*` | Multiple parsers/connectors exist. Runtime execution depends on tool installation, credentials, and connector-specific health. |
| CAS shield proxy bundle | LIMITED | `smoke_test.py`, `cas_shield_sentinel_bundle/` | Root `smoke_test.py` is a FastAPI reverse-proxy/risk-scorer service, not a simple platform health smoke script. |

## Current data-flow summary

1. Agents, dashboard actions, integration tasks, and ingest routes create or update Mongo-backed platform records.
2. Canonical event writers call `emit_world_event`, which persists a `world_events` document and classifies whether triune recomputation should run.
3. Triune recompute builds a world snapshot, fuses cognition signals, and returns Metatron/Michael/Loki output.
4. High-impact outbound actions are queued through `OutboundGateService`, stored as pending triune decisions, and released through governance approval/executor paths.
5. The frontend consumes the same `/api` surface, with current navigation consolidated around workspace pages and compatibility redirects.

## Practical bottom line

Metatron/Seraph is a broad, code-rich security control plane with real triune governance and unified-agent logic. The strongest implemented areas are API composition, agent telemetry/control, world-event reasoning, governance gating, and SOC workflows. The most important remaining constraints are production integration depth, durable/scaled assurance for governance and memory-like state, endpoint hardening quality, and contract/test coverage across the large API surface.
