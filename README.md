# Metatron / Seraph AI Defense Platform

Code-evidence refreshed overview for the current repository state.

---

## What this repository contains

Metatron is a multi-domain security platform with:

- a **FastAPI backend** (`backend/server.py`)
- a **React frontend** (`frontend/src/App.js`)
- a **unified endpoint agent** runtime (`unified_agent/core/agent.py`)
- optional local unified-agent sidecar surfaces (`unified_agent/server_api.py`, `unified_agent/ui/*`)
- Docker Compose orchestration for local and production-style deployments

The platform covers endpoint workflows, threat operations, response/containment, cloud posture, identity controls, email security, and mobile posture APIs.

---

## Current architecture (high level)

### Backend

- Entrypoint: `backend/server.py`
- Data store: MongoDB (with optional mock mode for development/testing)
- API composition model:
  - most routers mounted under `/api/*`
  - selected routers mounted with native `/api/v1/*` prefixes (for example CSPM, identity, secure-boot, attack-paths, kernel)
- WebSocket endpoints:
  - `/ws/threats`
  - `/ws/agent/{agent_id}` (machine-token verified)

### Frontend

- React app with protected routes and auth context
- Workspace-style navigation in `frontend/src/App.js`:
  - `/command`
  - `/investigation`
  - `/response-operations`
  - `/email-security`
  - `/endpoint-mobility`
  - and compatibility redirects from legacy paths

### Unified Agent

- Main endpoint logic: `unified_agent/core/agent.py`
- Backend control-plane APIs: `backend/routers/unified_agent.py` under `/api/unified/*`
- Optional local sidecar API: `unified_agent/server_api.py` (in-memory + proxy oriented)

---

## Major capability surfaces (implemented)

### 1) Auth and access control

Evidence:

- `backend/routers/dependencies.py`
- `backend/routers/auth.py`

Includes:

- JWT bearer auth (`HS256`)
- role model (`admin`, `analyst`, `viewer`)
- production/strict JWT secret enforcement
- optional remote admin gating for non-local requests
- machine-token helpers for service/websocket paths

### 2) Unified agent control plane

Evidence:

- `backend/routers/unified_agent.py`
- `unified_agent/core/agent.py`

Includes:

- agent registration/heartbeat
- command dispatch and result tracking
- monitor and alert surfaces
- installer/bootstrap endpoints
- EDM dataset versioning, publish, rollout, and rollback APIs

### 3) Email security

Evidence:

- `backend/email_protection.py`
- `backend/routers/email_protection.py`
- `backend/email_gateway.py`
- `backend/routers/email_gateway.py`

Includes:

- email analysis (authentication, URL/attachment/DLP style checks)
- quarantine and protection policy operations
- gateway process/quarantine/blocklist/allowlist/policy endpoints

### 4) Mobile and MDM

Evidence:

- `backend/mobile_security.py`
- `backend/routers/mobile_security.py`
- `backend/mdm_connectors.py`
- `backend/routers/mdm_connectors.py`

Includes:

- device registration and posture workflows
- app analysis and threat/compliance paths
- MDM connector management and device action APIs

Important caveat:

- MDM connector framework is real, but provider depth is not uniform in all branches and includes mock fallback behavior in some paths.

### 5) Cloud posture (CSPM)

Evidence:

- `backend/cspm_engine.py`
- `backend/routers/cspm.py`

Includes:

- provider configuration APIs
- scan orchestration
- findings/resources/compliance/dashboard/stats
- authenticated scan start (`POST /api/v1/cspm/scan`)

Important caveat:

- if no providers are configured, CSPM can seed/return demo data to keep UX usable.

---

## Quick start (local)

### Prerequisites

- Docker + Docker Compose
- Linux host recommended

### 1) Run services

```bash
docker-compose up -d
```

### 2) Check health

```bash
python3 smoke_test.py
```

### 3) Open interfaces

- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8001/api/`
- Backend health: `http://localhost:8001/api/health`

---

## Security-critical environment configuration

Minimum important settings:

- `JWT_SECRET` (strong, >= 32 chars; mandatory in production/strict mode)
- `CORS_ORIGINS` (explicit list in production/strict mode)
- `REMOTE_ADMIN_ONLY` and optional `REMOTE_ADMIN_EMAILS`
- `INTEGRATION_API_KEY` (required for production internal integrations)

The backend loads env from `backend/.env` via `load_dotenv(ROOT_DIR / '.env')`.

---

## Deployment notes

- Base compose file: `docker-compose.yml`
- Production overlay: `docker-compose.prod.yml`
- Nginx TLS/proxy config: `nginx/conf.d/default.conf`
- Backend image definition: `backend/Dockerfile`

Additional deployment details are in `DEPLOYMENT.md`.

---

## Testing and validation

Repository includes:

- backend tests under `backend/tests/`
- unified agent tests under `unified_agent/tests/`
- end-to-end and smoke validation scripts in repo root and `backend/scripts/`

Run targeted tests as needed with your Python test tooling.

---

## Repository map

- `backend/` — FastAPI APIs, core engines, services, router mesh
- `frontend/` — React UI and workspace pages
- `unified_agent/` — endpoint agent runtime, local UI and sidecar API
- `memory/` — internal review and architecture documents
- `deployment/`, `nginx/`, `docker-compose*.yml` — deployment infrastructure

---

## Reality statement

Metatron currently provides substantial, code-backed security platform functionality across multiple domains. The strongest guarantees are in internal control-plane logic and API breadth. Production outcomes for external provider integrations (for example CSPM cloud accounts and some MDM paths) remain dependent on environment credentials, dependency availability, and deployment-specific hardening.
