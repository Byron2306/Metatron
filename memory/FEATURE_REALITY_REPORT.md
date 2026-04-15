# Feature Reality Report (Code-Evidence Refresh)

Generated: 2026-04-15  
Scope: Qualitative implementation narrative based on current repository code paths

---

## Executive Verdict

Seraph/Metatron is a broad, implementation-heavy security platform with real backend, agent, and UI workflows running today. The core architecture is operational and code-backed:

- `backend/server.py` is the primary FastAPI control plane.
- World-state and Triune reasoning are active through `services/world_events.py` and `services/triune_orchestrator.py`.
- The Unified Agent has a substantial local runtime (`unified_agent/core/agent.py`) plus a canonical local dashboard (`unified_agent/ui/web/app.py`).
- The React frontend is consolidated around workspace routes in `frontend/src/App.js`.

The reality shift since older reports is that the main risks are now less about “missing feature files” and more about **consistency and assurance**:

1. consistency between parallel runtime surfaces (`backend/server.py` vs `unified_agent/server_api.py`),
2. durability and policy guarantees under restart/scale stress,
3. verification depth on fast-moving modules.

---

## What Is Materially Real Today

### 1) Backend Control Plane (Real, active)

**Evidence:** `backend/server.py`, `backend/routers/*`, `backend/services/*`

The backend:

- mounts a large router set under `/api` (plus `/api/v1` routers),
- initializes MongoDB (real Motor or optional mock mode),
- enforces auth/role dependencies from `routers/dependencies.py`,
- starts background workers on startup (CCE, network discovery, deployment, integrations scheduler, governance executor),
- exposes two websocket endpoints (`/ws/threats`, `/ws/agent/{agent_id}`).

This is not a placeholder server; it is the operational control plane.

### 2) World Model + Triune Pipeline (Real, integrated)

**Evidence:** `services/world_model.py`, `services/world_events.py`, `services/triune_orchestrator.py`, `triune/*.py`

World events are emitted through `emit_world_event`, optionally persisted to `world_events`, and can trigger:

1. world snapshot build (`WorldModelService`),
2. cognition enrichment (`CognitionFabricService`),
3. Metatron assessment,
4. Michael planning/ranking,
5. Loki challenge,
6. optional beacon cascade for deception interaction flows.

This gives a concrete Metatron → Michael → Loki execution path.

### 3) Governance + Outbound Control (Real, but mixed durability)

**Evidence:** `services/outbound_gate.py`, `services/governed_dispatch.py`, `services/governance_authority.py`, `services/governance_executor.py`, `services/policy_engine.py`, `routers/governance.py`

High-impact actions can be gated and queued, then approved/denied and executed through queue processing. Core mechanics exist and are wired into runtime paths.  
Residual concern: parts of policy/rate-limit behavior are process-local and need stronger cross-instance durability guarantees for strict enterprise behavior.

### 4) Unified Agent (Real, substantial)

**Evidence:** `unified_agent/core/agent.py`, `backend/routers/unified_agent.py`, `unified_agent/tests/*`

The agent:

- registers and heartbeats,
- polls commands and executes a broad command set,
- runs monitor scans continuously,
- reports telemetry/threats,
- supports EDM/DLP and endpoint fortress controls.

The backend unified router provides enrollment, commanding, rollout, monitor, and EDM endpoints.

### 5) Frontend SOC Surface (Real, consolidated)

**Evidence:** `frontend/src/App.js`, `frontend/src/components/Layout.jsx`, `frontend/src/pages/*.jsx`

The SPA uses a protected route shell and workspace-oriented routing (`/command`, `/investigation`, `/ai-activity`, `/response-operations`, `/detection-engineering`, `/email-security`, `/endpoint-mobility`, `/world`, etc.).  
Many legacy paths are now redirects into these workspaces.

---

## Domain-by-Domain Reality Notes

| Domain | Reality | Notes |
|---|---|---|
| Auth + RBAC | Implemented | JWT + role checks in `routers/dependencies.py`; strict-mode secret enforcement is present. |
| Threat/Alert workflows | Implemented | CRUD and dashboard APIs are active and used by frontend pages. |
| World graph and attack paths | Implemented (partial depth) | World entities/edges/campaigns and graph functions exist; advanced path semantics vary by data quality and ingest depth. |
| Triune cognition/governance | Implemented | Orchestrated pipeline is real; output quality depends on upstream world/event signal quality. |
| Integrations runtime | Implemented (conditional) | Backend integration scheduler/runtime + endpoint runtime command support; requires external tools/containers per integration. |
| Email protection | Implemented | Service and router present with analysis paths. |
| Email gateway | Implemented (ops-conditional) | SMTP-style gateway logic and APIs exist; production value depends on real SMTP/infra credentials and routing. |
| Mobile security | Implemented | Device and threat workflows exist in backend plus agent monitor hooks. |
| MDM connectors | Implemented (ops-conditional) | Multi-provider connector framework exists; production value depends on provider credentials and API connectivity. |
| Kernel/secure boot sensors | Implemented (environment-conditional) | APIs and services exist; runtime fidelity depends on host/kernel/container privileges. |
| Browser isolation | Partial | URL/risk controls exist; full remote isolation depth remains limited. |
| AI augmentation | Partial/conditional | Rule-based baseline works; model-assisted quality depends on configured model services. |

---

## Current Mismatch / Risk Themes

1. **Parallel control surfaces:**  
   `backend/server.py` is the main source of truth, while `unified_agent/server_api.py` remains a separate FastAPI with in-memory persistence and legacy wording.

2. **Best-effort persistence patterns:**  
   Some event paths intentionally swallow persistence failures for resilience (for example world-event insert failure). Good for uptime, weaker for strict audit guarantees unless monitored.

3. **Contract drift potential:**  
   High feature velocity across backend/frontend/agent creates ongoing schema and route drift risk without strong CI contract gates.

4. **Operational dependency variability:**  
   Many advanced capabilities are real but rely on optional integrations (Docker tools, external APIs, local model endpoints, privileged sensor setup).

---

## Updated Interpretation of “Working”

The platform should be considered working when:

1. core services (`backend`, `frontend`, `mongodb`) are healthy,
2. authenticated dashboard workflows load and perform primary reads/writes,
3. unified agent register/heartbeat/command loop is functional,
4. world-event → Triune flow executes without fatal errors,
5. optional integrations fail clearly and gracefully when unavailable.

This is a stronger and more code-faithful definition than earlier binary “feature complete” framing.

---

## Final Reality Statement

The platform is **feature-rich and materially implemented**, not a thin prototype.  
Its next quality frontier is **assurance and consistency**: contract governance, durable policy state, and repeatable verification across rapidly evolving surfaces.
