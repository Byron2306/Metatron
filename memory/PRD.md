# Metatron / Seraph Product Requirements Document (Code-Aligned Baseline)

**Last updated:** 2026-04-23  
**Scope:** Product requirements and behavior contracts validated against current repository code and runtime wiring.

---

## 1) Product Definition

Metatron / Seraph is a cybersecurity platform composed of:

- FastAPI control plane (`backend/server.py`)
- React web console (`frontend/`)
- MongoDB data layer, Redis task/broker support
- Optional SIEM/AI/network/sandbox services via Docker Compose
- Cross-platform unified endpoint agent surfaces (`unified_agent/`)

Primary product goal: detect, correlate, and respond to endpoint/network/cloud/email/mobile threats while preserving governed high-impact execution paths.

---

## 2) Core Product Outcomes

### 2.1 SOC control plane

The platform must provide authenticated analysts/admins with:

- Threat and alert visibility
- Agent fleet visibility and commanding
- Timeline and investigation workflows
- Policy and governance operations
- Integration runtime operations (server-side or unified-agent-targeted)

### 2.2 Endpoint integration

The unified agent contract must support:

- Registration and authentication
- Heartbeats and telemetry
- Command polling and command-result reporting
- Runtime tool execution via approved commands

### 2.3 Governed execution

High-impact actions (agent/swarm/response/quarantine/tool execution classes) must flow through outbound gating and triune decision records before execution.

---

## 3) System Architecture Requirements

### 3.1 Backend API layer

Requirements:

1. All primary business routers mount under `/api` in `backend/server.py`.
2. Health contract is `GET /api/health`.
3. Backend startup seeds module DB handles and initializes background workers.
4. Backend must enforce production/strict security constraints at boot.

Current implementation reference:

- `backend/server.py`
- `backend/routers/*`
- `backend/services/*`

### 3.2 Frontend layer

Requirements:

1. Frontend must resolve API root predictably:
   - `${REACT_APP_BACKEND_URL}/api` when env value is valid, otherwise `/api`.
2. Same-origin `/api` support is required for reverse-proxy deployments.
3. UI pages should degrade gracefully when optional integrations are unavailable.

Current implementation reference:

- `frontend/src/lib/api.js`
- `frontend/src/context/AuthContext.jsx`
- `frontend/src/pages/*`

### 3.3 Deployment layer

Requirements:

1. Compose baseline includes MongoDB, Redis, backend, frontend.
2. Optional services are profile-gated or operationally optional.
3. Production override removes direct backend/frontend host exposure and expects Nginx ingress.

Current implementation reference:

- `docker-compose.yml`
- `docker-compose.prod.yml`
- `nginx/conf.d/default.conf`
- `frontend/nginx.conf`

---

## 4) Authentication and Authorization Requirements

### 4.1 Human users (JWT)

Requirements:

1. `/api/auth/register`, `/api/auth/login`, `/api/auth/me`, `/api/auth/setup` must function as primary identity endpoints.
2. JWT secrets must be strong; production/strict mode must fail on missing/weak secrets.
3. Remote access policy (`REMOTE_ADMIN_ONLY`) must restrict non-local clients to admin role or allowlisted admin emails.
4. Role-permission checks must gate write/admin/delete operations.

Implementation reference:

- `backend/routers/auth.py`
- `backend/routers/dependencies.py`

### 4.2 Machine/auth tokens

Requirements:

1. Internal automation and ingest channels must support machine-token validation.
2. World ingest requires machine token headers.
3. Agent websocket and integrations internal paths must validate configured tokens.

Implementation reference:

- `backend/routers/dependencies.py`
- `backend/routers/world_ingest.py`
- `backend/server.py` websocket auth
- `backend/routers/integrations.py`

---

## 5) Unified Agent Requirements

### 5.1 Canonical unified-agent API contract

Required backend endpoints:

- `POST /api/unified/agents/register`
- `POST /api/unified/agents/{agent_id}/heartbeat`
- `GET /api/unified/agents/{agent_id}/commands`
- `POST /api/unified/agents/{agent_id}/command-result`

These endpoints must persist and govern command/telemetry lifecycles.

### 5.2 Agent runtime behavior

Requirements:

1. Agent performs monitor scans and threat handling loops.
2. Agent polls backend commands and posts command execution results.
3. Agent supports side-channel authenticated calls for AI/VNS style routes.
4. Local minimal UI is optional and guarded by `SERAPH_ALLOW_MINIMAL_UI`.

Implementation reference:

- `unified_agent/core/agent.py`
- `backend/routers/unified_agent.py`

### 5.3 Multi-surface clarification requirement

Documentation and operations must distinguish:

- Monolithic unified agent contract (`/api/unified/...`)
- Desktop `UnifiedAgentCore` helper behavior (`unified_agent/ui/desktop/main.py`)
- Flask local dashboard (`unified_agent/ui/web/app.py`)
- Auxiliary FastAPI service (`unified_agent/server_api.py`, in-memory/secondary)

---

## 6) Integration Runtime Requirements

### 6.1 Runtime targets

Integrations API must support:

- `runtime_target=server` (server execution)
- `runtime_target=unified_agent*` (queued for unified agent execution)

### 6.2 Tool control

Only allowlisted tools may run through integration runtime interfaces.

Allowlist source of truth:

- `backend/integrations_manager.py::SUPPORTED_RUNTIME_TOOLS`

Unified-agent local runtime allowlist must remain aligned with backend runtime tool support.

### 6.3 Governance requirement

Unified-agent-targeted runtime commands must be queued through governed dispatch and triune queue/decision records before endpoint execution.

Implementation reference:

- `backend/routers/integrations.py`
- `backend/integrations_manager.py`
- `backend/services/governed_dispatch.py`
- `backend/services/outbound_gate.py`

---

## 7) Threat Cognition and Correlation Requirements

### 7.1 CCE session analysis

Requirements:

1. CCE worker consumes CLI command streams.
2. Session summaries persist when machine-likelihood thresholds are met.
3. High-risk sessions can trigger SOAR evaluation.

Implementation reference:

- `backend/services/cce_worker.py`

### 7.2 Cognitive fusion requirements

Requirements:

1. Fusion service aggregates AATL, CCE, ML predictions, AATR matches, and AI reasoning.
2. Service computes cognitive pressure and policy tier recommendations from weighted signals.
3. Outputs must include recommended actions and supporting signals.

Implementation reference:

- `backend/services/cognition_fabric.py`

### 7.3 Distinct correlation path

Threat-intel campaign/style correlation remains a separate path from cognition fusion and must be documented separately.

Implementation reference:

- `backend/threat_correlation.py`

---

## 8) Domain Feature Requirements

### 8.1 Email protection and gateway

Requirements:

1. Email protection routes must provide authentication/phishing/attachment/DLP workflows.
2. Email gateway routes must support processing, quarantine, blocklist/allowlist, and policy operations.

Implementation reference:

- `backend/email_protection.py`
- `backend/routers/email_protection.py`
- `backend/email_gateway.py`
- `backend/routers/email_gateway.py`

### 8.2 Mobile security and MDM

Requirements:

1. Mobile security routes must support device status/threat/compliance workflows.
2. MDM connectors routes must support connector lifecycle, device sync, and remote actions.

Implementation reference:

- `backend/mobile_security.py`
- `backend/routers/mobile_security.py`
- `backend/mdm_connectors.py`
- `backend/routers/mdm_connectors.py`

### 8.3 CSPM and identity

Requirements:

1. CSPM scan and management paths must be authenticated.
2. Identity threat and incident routes must enforce access controls and durable persistence.

Implementation reference:

- `backend/routers/cspm.py`
- `backend/routers/identity.py`

---

## 9) Production Security Requirements

1. `INTEGRATION_API_KEY` is mandatory for production backend startup.
2. CORS wildcard must not be allowed in production/strict mode.
3. JWT secret must be strong and explicitly set in production/strict mode.
4. High-impact outbound actions must enter triune queue/decision flow.
5. Trusted-network fallback auth for unified agents must remain explicitly opt-in.

---

## 10) Operational Acceptance Criteria

A deployment is acceptable when:

1. Core runtime services are healthy.
2. Auth and dashboard workflows operate under `/api`.
3. Unified-agent register/heartbeat/command/result loop works end-to-end.
4. Integrations runtime executes in configured target mode with governance metadata.
5. Optional services fail gracefully without breaking core SOC routes.

---

## 11) Explicit Non-Goals / Current Limits

These are currently outside strict guaranteed baseline behavior:

- Full remote-browser isolation pixel-streaming model
- Production credential provisioning for all third-party integrations by default
- Auxiliary/legacy agent surfaces as primary control plane (they are secondary)
- Single unified script baseline across all historical helper scripts and defaults

---

## 12) Document Governance

This PRD intentionally avoids historical release scorecards and unverifiable percentages.  
It is maintained as a code-aligned requirements baseline and should be refreshed when API contracts, auth controls, run-mode contracts, or major subsystem behavior changes.

