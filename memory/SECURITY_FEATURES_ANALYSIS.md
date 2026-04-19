# Security Features Analysis (As-Built, April 2026)

## Scope

This analysis reflects the currently implemented security surfaces in:

- `backend/server.py`
- `backend/routers/*.py`
- `backend/services/*.py`
- `unified_agent/core/agent.py`
- `frontend/src/App.js` and workspace pages

## Security architecture summary

The platform is implemented as:

1. A FastAPI control plane (`backend/server.py`) with Mongo-backed state.
2. A large modular router set (`backend/routers`, 62 modules) with RBAC and machine-token gates.
3. Security services (`backend/services`, 33 modules) for governance, telemetry integrity, world-state projection, and execution pipelines.
4. A unified endpoint runtime (`unified_agent`) with integration adapters and local deployment UX.

## Core security controls (implemented)

### 1) Authentication and authorization

- JWT-based auth with startup-time secret validation in `routers/dependencies.py`.
- Production/strict mode hard-fails weak or absent JWT secrets.
- RBAC roles (`admin`, `analyst`, `viewer`) enforced through dependency guards.
- Remote admin-only control path supported via:
  - `REMOTE_ADMIN_ONLY`
  - `REMOTE_ADMIN_EMAILS`
- First-admin bootstrap model:
  - `/api/auth/setup`
  - optional `SETUP_TOKEN` header gate.

### 2) Machine-to-machine token boundaries

Machine-token auth dependencies are active in multiple high-impact ingestion and command paths:

- `require_machine_token(...)`
- `optional_machine_token(...)`
- `verify_websocket_machine_token(...)`

Notable protected surfaces include:

- world ingest (`routers/world_ingest.py`)
- integrations ingest/jobs (`routers/integrations.py`)
- advanced ingest endpoints (`routers/advanced.py`)
- websocket agent channel (`/ws/agent/{agent_id}` in `server.py`)

### 3) Governance and outbound action gating

High-impact actions are explicitly queued for approval and execution rather than direct fire-and-forget:

- `services/governed_dispatch.py`
- `services/governance_authority.py`
- `services/governance_executor.py`
- `routers/governance.py`

Execution model:

1. Command enters triune queue in gated state.
2. Decision transitions through `pending -> approved/denied`.
3. Approved items execute through controlled handlers.
4. Audit and world events are emitted for decision and execution transitions.

### 4) Tamper-evident telemetry chain

Multiple router/service domains call tamper-evident telemetry capture via:

- `services/telemetry_chain.py`

Observed usage includes:

- advanced operations
- unified-agent state projection
- governance execution traceability
- CSPM operation logging

This creates a stronger integrity trail than plain application logs alone.

### 5) World model + event pipeline security observability

Security-relevant actions emit world events (`services/world_events.py`) from many domains:

- integrations runtime dispatch
- email gateway and email protection decisions
- MDM connector actions
- governance approvals/denials/executions
- unified-agent telemetry projections

The world event stream is used for state projection and triune trigger conditions.

### 6) Multi-domain detection and response capabilities

Implemented domains include:

- EDR (`routers/edr.py`)
- ransomware (`routers/ransomware.py`)
- threat correlation (`routers/correlation.py`)
- threat response (`routers/response.py`)
- sandbox (`routers/sandbox.py`)
- browser isolation (`routers/browser_isolation.py`)
- honeypots + honey tokens (`routers/honeypots.py`, `routers/honey_tokens.py`)
- zero trust (`routers/zero_trust.py`)
- identity protection (`routers/identity.py`)
- CSPM (`routers/cspm.py`)
- AI threat and triune surfaces (`routers/ai_threats.py`, `routers/metatron.py`, `routers/michael.py`, `routers/loki.py`)

### 7) Endpoint and integration runtime

The unified agent and integration adapters provide additional practical security controls:

- `unified_agent/core/agent.py`
- adapters in `unified_agent/integrations/*` (12 tools)
- backend integration runtime manager in `backend/integrations_manager.py`

Supported runtime tool set includes:

- amass, arkime, bloodhound, spiderfoot
- sigma, atomic
- falco, yara, suricata, trivy
- cuckoo, osquery, zeek

## Security hardening controls present in server startup/runtime

Key hardening features in `backend/server.py` include:

- strict CORS behavior when production/strict mode is active
- mandatory internal integration API key in production
- startup checks + structured initialization of major services
- defensive fail-open import handling for optional enterprise modules

## Current strengths

1. **Broad security domain coverage** across endpoint, network, identity, cloud, email, mobile, and governance.
2. **Explicit command governance model** rather than unrestricted action dispatch.
3. **Machine token perimeter controls** for ingestion and internal channels.
4. **Tamper-evident telemetry integration** across multiple subsystems.
5. **Unified frontend workspace topology** that maps to active backend modules.

## Current weaknesses / residual risk

1. **Large surface area complexity**
   - 62 router modules, 694 endpoint decorators.
   - Increases regression and contract drift risk.
2. **Legacy endpoint traces remain**
   - Frontend still references a small number of stale API patterns (`/api/data`, `/api/login`, `/api/admin/users`).
3. **Mixed prefix model**
   - Combination of `/api/*` and `/api/v1/*` requires careful frontend and client handling.
4. **Multiple runtime modes**
   - Backend, unified-agent API, and local dashboard patterns can create operator confusion if run-mode contract is unclear.

## Security maturity posture (practical)

Relative to the codebase shape (not market claims), this is a:

- **High-feature, medium-to-high maturity control plane**
- with strong governance and telemetry design concepts,
- but still requiring contract simplification and endpoint rationalization to reduce operational risk.

## Immediate recommended actions (code-near)

1. Add CI checks for frontend call-site to backend route parity.
2. Remove/replace known stale frontend endpoint literals.
3. Continue converging `/api` and `/api/v1` contract documentation in one canonical reference.
4. Expand tests around governed dispatch and decision state transitions during mixed-failure scenarios.
