# Metatron / Seraph AI Defense Platform

Code-accurate platform guide (updated 2026-04-18)

---

## What this repository is

Metatron/Seraph is a large, modular cybersecurity platform that combines:

- FastAPI backend APIs and services for SOC workflows and governed automation
- React frontend workspaces/pages for operations and investigation
- A unified endpoint agent (`unified_agent/core/agent.py`) with broad monitor coverage
- Governance services for gating and executing high-impact actions through triune decision flow

This README focuses on **current code behavior**, not historical marketing snapshots.

---

## Architecture at a glance

### Backend
- Entrypoint: `backend/server.py`
- Framework: FastAPI
- Database: MongoDB (Motor)
- Queue/worker components also exist in compose (`redis`, `celery-worker`, `celery-beat`)

`backend/server.py` wires a large router surface, including:

- `/api/auth/*` authentication
- `/api/unified/*` unified agent lifecycle and EDM control plane
- `/api/email-protection/*`
- `/api/email-gateway/*`
- `/api/mobile-security/*`
- `/api/mdm/*`
- `/api/governance/*`
- `/api/enterprise/*`
- `/api/v1/cspm/*`

### Frontend
- App routes: `frontend/src/App.js`
- Workspaces include command, AI activity, investigation, response, email security, and endpoint mobility.
- Notable route mappings:
  - `/email-security?tab=protection|gateway`
  - `/endpoint-mobility?tab=mobile|mdm`
  - `/unified-agent`
  - `/cspm`

### Unified Agent
- Core implementation: `unified_agent/core/agent.py`
- Includes monitor modules such as:
  - `EmailProtectionMonitor`
  - `MobileSecurityMonitor`
  - CLI telemetry and multiple endpoint/network/process monitors
- Agent talks to backend via unified control-plane endpoints and heartbeat telemetry.

---

## Core capability map (current)

### 1) Governance and high-impact action control

Implemented path:
1. High-impact action is gated by `OutboundGateService` (`backend/services/outbound_gate.py`)
2. Queue + decision records are stored in triune collections
3. Governed command persistence handled by `GovernedDispatchService`
4. Approval/denial APIs exposed by `backend/routers/governance.py`
5. `GovernanceExecutorService` processes approved decisions
6. Executor loop starts at backend startup (`backend/server.py`)

This is an implemented runtime flow, not just a conceptual pattern.

### 2) Unified Agent + EDM lifecycle

In `backend/routers/unified_agent.py` and `unified_agent/core/agent.py`:

- Agent registration/heartbeat/commanding
- Command state transitions with `state_version` and transition logs
- EDM dataset versioning and metadata signing/checksums
- Publish-time quality gates
- Canary rollout (`start -> readiness -> advance`) and rollback paths
- EDM telemetry summaries and rollout status APIs

### 3) CSPM

In `backend/routers/cspm.py`:

- `POST /api/v1/cspm/scan` requires authenticated user context
- Durable scan/finding transition handling
- Provider config persistence with masked/encrypted secret handling
- Demo data seed fallback when no providers are configured

### 4) Email security

Email protection (`backend/email_protection.py`, `backend/routers/email_protection.py`):
- SPF/DKIM/DMARC checks
- URL, attachment, impersonation, and DLP analysis
- Quarantine and protected-user management endpoints

Email gateway (`backend/email_gateway.py`, `backend/routers/email_gateway.py`):
- Gateway decision engine (accept/reject/quarantine etc.)
- Blocklist/allowlist and quarantine operations
- Policy endpoints and process/testing endpoint

### 5) Mobile security and MDM

Mobile security (`backend/mobile_security.py`, router):
- Device lifecycle APIs
- Threat and compliance checks
- App analysis and policy endpoints

MDM connectors (`backend/mdm_connectors.py`, router):
- **Implemented connectors:** Intune, JAMF
- **Declared in metadata but not fully instantiated in manager add flow:** Workspace ONE, Google Workspace

This distinction is important for accurate operational planning.

---

## Quick start

## Prerequisites

- Docker + Docker Compose
- Python 3.11+ (for local backend execution)
- Node 20+ (for local frontend execution)

## Option A: docker-compose baseline

From repo root:

```bash
docker compose up -d mongodb backend frontend
```

Then verify:

```bash
curl -fsS http://127.0.0.1:8001/api/health
```

Frontend (compose mapping) is typically exposed on port 3000.

## Option B: fuller local stack

Use compose services as needed (`redis`, `nginx`, `elasticsearch`, `kibana`, etc.) depending on the flows you are testing.

---

## Authentication bootstrap

Auth router lives at `backend/routers/auth.py`.

Relevant endpoints:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/setup` (one-time admin setup; optional `X-Setup-Token` guard)

Use returned bearer token for protected API routes.

---

## Testing and validation

Repository contains broad test suites under:

- `backend/tests/`
- `unified_agent/tests/`
- additional integration/system report files under `test_reports/`

When validating behavior, prioritize:

1. auth flow
2. unified agent register/heartbeat
3. governance pending/approve/executor flow
4. CSPM scan auth + scan lifecycle
5. email protection and gateway endpoints
6. mobile + MDM endpoints (with corrected connector expectations)

---

## Known implementation caveats (important)

1. **MDM parity caveat**
   - API/platform metadata includes Intune, JAMF, Workspace ONE, Google Workspace.
   - Connector manager runtime support currently instantiates Intune/JAMF in add flow.

2. **Integration-dependent depth**
   - Some domains (CSPM providers, SMTP relay behavior, external integrations) need valid credentials and environment wiring for production-grade operation.

3. **Large contract surface**
   - The backend/frontend route footprint is large; contract drift risk exists without strict CI contract gates.

---

## Repository landmarks

- Backend entrypoint: `backend/server.py`
- Auth/dependencies: `backend/routers/auth.py`, `backend/routers/dependencies.py`
- Governance:
  - `backend/routers/governance.py`
  - `backend/services/outbound_gate.py`
  - `backend/services/governed_dispatch.py`
  - `backend/services/governance_executor.py`
- Unified control plane: `backend/routers/unified_agent.py`
- Email:
  - `backend/email_protection.py`
  - `backend/routers/email_protection.py`
  - `backend/email_gateway.py`
  - `backend/routers/email_gateway.py`
- Mobile/MDM:
  - `backend/mobile_security.py`
  - `backend/routers/mobile_security.py`
  - `backend/mdm_connectors.py`
  - `backend/routers/mdm_connectors.py`
- CSPM:
  - `backend/routers/cspm.py`
  - `backend/cspm_engine.py`
- Frontend routes: `frontend/src/App.js`
- Unified agent core: `unified_agent/core/agent.py`
- Container orchestration: `docker-compose.yml`

---

## Documentation policy

This README is intended to stay code-accurate.  
If behavior changes (especially connectors, route contracts, governance flow, or rollout semantics), update this file and corresponding `memory/*.md` review artifacts in the same change set.
