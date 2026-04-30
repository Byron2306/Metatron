# Metatron / Seraph System-Wide Evaluation

**Updated:** 2026-04-30  
**Scope:** Current repository architecture, runtime behavior, frontend wiring, agent control plane, governance flow, and validation posture.  
**Basis:** Code evidence from `backend/server.py`, `backend/routers/`, `backend/services/`, `frontend/src/`, `unified_agent/`, Docker, and CI/test files.

---

## Executive Summary

Metatron / Seraph is currently a broad, modular cybersecurity platform centered on a FastAPI SOC backend, a React command workspace, a cross-platform unified endpoint agent, and a Triune/governance control plane for high-impact automation. The repository has moved beyond the older monolithic-server description: `backend/server.py` now wires a large set of routers and services around MongoDB, startup workers, world-model events, AI-threat analysis, and governed command execution.

The strongest current implementation areas are:

- **Backend breadth and composition:** `backend/server.py` mounts 65 router registrations from the active router set, including SOC operations, unified agents, AI threats, email/mobile/MDM, CSPM, deception, identity, governance, world ingest, and Triune personas.
- **Governed automation:** impactful agent and domain operations are funneled through `backend/services/governed_dispatch.py`, `backend/services/outbound_gate.py`, `backend/routers/governance.py`, and `backend/services/governance_executor.py` so commands can be queued as `gated_pending_approval`, approved/denied, audited, and then released for execution.
- **World-state and Triune reasoning:** `backend/services/triune_orchestrator.py` builds a world snapshot, enriches it with cognition fabric signals, asks Metatron to assess, Michael to plan, and Loki to challenge the plan. World events can trigger this reasoning path.
- **Unified endpoint agent:** `unified_agent/core/agent.py` is a v2.0 cross-platform agent with process, network, DNS, registry, DLP/EDM, YARA, ransomware, rootkit, kernel, identity, firewall, CLI, email, mobile, and WebView2-oriented monitor surfaces. Backend integration lives under `/api/unified/...`.
- **Operator UI:** `frontend/src/App.js` uses React Router and protected routes to present command, world, AI activity, investigation, response, unified-agent, platform, engineering, admin, and tool pages. `frontend/src/components/Layout.jsx` defines the current navigation and points the external Agent UI to port 5000.
- **Runtime services:** startup initializes admin seeding, the CCE worker, network discovery, agent deployment, AATL/AATR, integrations scheduling, and the governance executor where dependencies are available.
- **Validation:** `.github/workflows/contract-assurance.yml`, backend contract/durability tests, unified-agent monitor tests, static governance guardrails, and audit reports provide a growing assurance layer.

## Current Architecture Snapshot

| Layer | Current implementation |
|---|---|
| Main API | FastAPI app in `backend/server.py`, version `3.0.0`, default port `8001`, MongoDB via Motor or optional mock mode. |
| API surface | 62 router files on disk, 65 active `include_router` calls, plus app-level WebSockets `/ws/threats` and `/ws/agent/{agent_id}`. |
| Data plane | MongoDB collections for users, agents, world entities/events, CLI sessions, commands, decisions, response history, audit/telemetry, and domain-specific records. |
| Agent control | `backend/routers/unified_agent.py` plus `unified_agent/core/agent.py` and the separate `unified_agent/server_api.py` portal/proxy. |
| Governance | Outbound gate + triune decisions + governance router + executor service; denial updates pending commands to rejected. |
| AI/cognition | CCE worker analyzes CLI command sessions; AATL/AATR initialize at startup; Triune orchestrator reasons over world state. |
| Frontend | React 19 / Craco / Tailwind dashboard with 69 page components on disk and 66 route declarations. |
| Deployment | Docker Compose starts MongoDB, Redis, backend, Celery worker/beat, frontend, and security tooling/integration services. |
| Test posture | 63 backend test files and 4 unified-agent test files are present, with CI focused on contract assurance and monitor regression. |

## What Is Materially Real

1. **Core SOC API routing** is real and broad. The backend mounts routes for auth, threats, alerts, dashboard, network, hunting, reports, agents, response, audit, timeline, OpenClaw, integrations, ransomware, containers, VPN, correlation, EDR, SOAR, honey tokens, zero trust, ML, sandbox, browser isolation, Kibana, Sigma, Zeek, osquery, atomic validation, MITRE, extension, multi-tenant, enterprise, CSPM, advanced services, Triune personas, unified agent, world ingest, email, mobile, MDM, deception, identity, and governance.
2. **Governed dispatch is now a real control path.** The static guardrail script explicitly checks for mutating endpoints without write/machine auth, shell execution patterns, and direct command queue writes outside the governed dispatch helper.
3. **World-state projection is implemented.** Unified-agent telemetry can project agent trust state into `world_entities` and emit `world_events`; high threat totals can trigger Triune reasoning.
4. **CCE and CLI analysis are active concepts.** The CCE worker polls `cli_commands`, groups by host/session, analyzes sessions with `CognitionEngine`, stores summaries, and can emit world events.
5. **Frontend consolidation is real.** Many legacy routes redirect into newer workspaces (`/command`, `/ai-activity`, `/investigation`, `/response-operations`, `/unified-agent`, `/email-security`, `/endpoint-mobility`) rather than each legacy feature maintaining a fully separate top-level workflow.

## Current Constraints and Risks

| Risk | Current reading | Recommended focus |
|---|---|---|
| Central startup coupling | `backend/server.py` still imports and initializes many domains in one process. | Continue extracting lifecycle registration and dependency health into smaller modules. |
| Optional integration ambiguity | Many features depend on optional external tools, credentials, or services. | Expose clear connected/degraded/unavailable status per feature. |
| Legacy/stale documentation | Older memory docs used outdated percentages, timelines, and claims. | Keep docs tied to active file paths and test evidence. |
| Governance durability | Commands and decisions are DB-backed, but HA/replay semantics still need continued hardening. | Expand restart/scale and denial-path tests. |
| Agent portal drift | `unified_agent/server_api.py` still references `server_old.py` in comments while proxying to the current backend on port 8001. | Normalize portal documentation and runtime labels. |
| Feature verification depth | Breadth is high; validation is strongest around selected contracts. | Broaden regression coverage for high-risk routers and background services. |

## Updated Maturity Assessment

| Domain | Assessment |
|---|---|
| Capability breadth | Very high; the platform covers many SOC, endpoint, cloud, email, mobile, identity, deception, and governance domains. |
| Architecture | Strong modular direction, with a dense but readable central composition root. |
| Security controls | Improving through auth dependencies, strict CORS checks, machine-token WebSockets, governed dispatch, and static guardrails. |
| Operational readiness | Partial-to-strong depending on environment; Docker and startup services exist, but external integrations require configuration. |
| Test/assurance | Moderate and improving; contract and durability tests exist, but broad end-to-end assurance should continue expanding. |
| Documentation accuracy | This update replaces stale percentage-based summaries with code-evidence-based status. |

## Bottom Line

The platform is best described as a **governed adaptive defense fabric**: a broad SOC/XDR-style system with strong endpoint-agent integration, AI/cognition services, world-state reasoning, and explicit governance gates for impactful automation. The main engineering challenge is no longer simply feature presence; it is keeping contracts, runtime health, governance durability, tests, and documentation synchronized with a large and fast-moving codebase.
