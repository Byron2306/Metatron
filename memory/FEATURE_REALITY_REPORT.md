# Feature Reality Report (Updated April 2026)

## Executive verdict

The repository contains a broad, actively wired platform rather than a stubbed demo:

- **Backend**: FastAPI app (`backend/server.py`) with **62 router modules** and **694 router endpoints**.
- **Frontend**: React app (`frontend/src/App.js`) with workspace routing and 68 page modules.
- **Unified agent**: endpoint runtime plus optional local API/dashboard under `unified_agent/`.
- **Governance model**: gated command dispatch via decision authority and executor services.

The primary reality shift from older memory docs is that the architecture is now best described as:
**modular API + governed action pipeline + multi-surface UI/workspace model**, not a monolithic release train.

## Evidence used

- `backend/server.py`
- `backend/routers/*.py`
- `backend/services/{governed_dispatch.py, governance_authority.py, governance_executor.py, world_model.py, world_events.py}`
- `backend/integrations_manager.py`
- `frontend/src/App.js`
- `frontend/src/pages/*`
- `unified_agent/server_api.py`
- `unified_agent/core/agent.py`
- `unified_agent/integrations_client.py`

## Current domain-by-domain reality

### 1) Core API and auth

What is true now:

- JWT auth, role checks, and machine-token patterns are centralized in `backend/routers/dependencies.py`.
- Auth/user management routes are in `backend/routers/auth.py`.
- Startup admin seeding and setup-token path exist in the active backend lifecycle.

Implication:

- Platform has a practical security baseline for role-gated operations and internal M2M calls.

### 2) Threat/response pipeline

What is true now:

- Threats, alerts, timeline, response, quarantine, hunting, correlation, and SOAR routes are all mounted in the main server.
- Response/quarantine operations are present both as direct APIs and as governable action types.
- WebSocket channels exist for real-time threat/agent communication (`/ws/threats`, `/ws/agent/{agent_id}`).

Implication:

- Core SOC loop (detect -> assess -> action -> audit) is implemented across multiple modules, not isolated.

### 3) Governance and controlled execution

What is true now:

- `GovernedDispatchService` writes commands as `gated_pending_approval`.
- `GovernanceDecisionAuthority` handles approve/deny transitions in `triune_decisions` and linked queue state.
- `GovernanceExecutorService` translates approved decisions into command delivery and domain operations.
- Governance API is exposed at `/api/governance/*`.

Implication:

- There is explicit control-plane separation between request issuance and high-impact execution.

### 4) Advanced and enterprise surfaces

What is true now:

- `advanced.py` exposes MCP/vector/VNS/quantum/AI reasoning style APIs with security dependencies.
- `enterprise.py`, `identity.py`, and related services support token/policy/identity control surfaces.
- `world_ingest.py` enforces machine token validation for world-model event/entity ingestion.

Implication:

- Advanced features are wired as real routers/services, but operational maturity depends on deployment and policy setup.

### 5) Integrations runtime

What is true now:

- `/api/integrations/*` routes launch runtime jobs and ingest data.
- `integrations_manager.py` tracks jobs, persists status, and supports server/runtime-agent execution modes.
- Supported runtime tool set is explicitly enumerated (`amass`, `bloodhound`, `spiderfoot`, `sigma`, `atomic`, `falco`, `yara`, `suricata`, `trivy`, `cuckoo`, `osquery`, `zeek`, etc).

Implication:

- Integration capability is broad and policy-sensitive; endpoint reliability depends on external tool availability.

### 6) Frontend experience model

What is true now:

- `App.js` routes intentionally consolidate multiple legacy paths into workspace tabs using `Navigate`.
- Security domains have dedicated pages, while workspace wrappers orchestrate cross-domain views.
- Most pages call backend APIs directly; a smaller set are non-fetch wrappers.

Implication:

- UI architecture is now workspace-first with compatibility redirects, not a 1:1 route-to-page legacy model.

### 7) Unified agent surface

What is true now:

- Primary backend unified-agent contract lives in `backend/routers/unified_agent.py`.
- `unified_agent/server_api.py` provides an optional local API/proxy with local JSON persistence.
- `unified_agent/core/agent.py` and integration adapters provide endpoint runtime hooks.

Implication:

- There are two valid agent-adjacent modes: integrated backend mode and local standalone helper mode.

## Reality-based risks (current)

1. **Contract drift risk** between frontend literal paths and backend route evolution (already visible in a few legacy call-sites).
2. **Complexity risk** from breadth of routers/services and mixed `/api` vs `/api/v1` namespaces.
3. **Operational variance risk** for integrations that depend on external binaries/services.
4. **Dual-path behavior risk** between main backend flows and optional unified-agent local API mode.

## What changed from older memory assumptions

1. “Single release version” framing is no longer useful as the main truth source.
2. The platform should be tracked as **component contracts + route topology + governance state transitions**.
3. The most reliable reality indicators are:
   - mounted routers in `backend/server.py`
   - security dependencies in `routers/dependencies.py`
   - governance state transitions in `services/governance_*`
   - frontend route map in `frontend/src/App.js`.

## Recommended maintenance pattern

1. Keep this report short and evidence-based.
2. Pair with:
   - `FEATURE_REALITY_MATRIX.md` for maturity scoring,
   - `full_pages_wiring_audit.md` for route-link health,
   - `RUN_MODE_CONTRACT.md` for operational mode expectations.
3. Update whenever router mounts, governance transitions, or workspace routes change.
