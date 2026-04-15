# Metatron / Seraph AI Defense Platform

This repository contains a large cybersecurity platform composed of:

- A FastAPI backend (`backend/`)
- A React frontend (`frontend/`)
- A unified endpoint-agent stack (`unified_agent/`)
- Optional security/sandbox integrations orchestrated by Docker Compose

This README is intentionally implementation-focused and reflects current code logic.

---

## 1) Architecture at a Glance

### Core services

- **Backend API**: `backend/server.py` (FastAPI, MongoDB, async background startup services)
- **Frontend UI**: `frontend/src/App.js` (route/workspace shell)
- **Data stores**:
  - MongoDB (primary app state)
  - Redis (Celery broker/result backend)
- **Async execution**:
  - In-process background startup services (CCE worker, network discovery, deployment service, governance executor)
  - Celery worker + beat for task execution/scheduling

### Current measured inventory (repo scan)

- Frontend route entries in `App.js`: **67**
- Frontend page files in `frontend/src/pages` (excluding tests): **69**
- `app.include_router(...)` calls in `backend/server.py`: **65**
- Router modules in `backend/routers` (excluding `dependencies.py`): **61**

---

## 2) Major Backend Domains

`backend/server.py` mounts routers under `/api` (with several routers owning `/api/v1/...` prefixes directly). Major domains include:

- Auth/users/session and RBAC
- Threats/alerts/hunting/correlation/timeline/reporting
- Response/quarantine/SOAR/ransomware/deception
- Unified agent, swarm, agent commands, world ingest
- Identity/zero-trust/governance/enterprise controls
- CSPM, container security, VPN, Zeek, osquery, Sigma/Atomic, MITRE
- Email protection, email gateway, mobile security, MDM connectors
- Triune endpoints (`metatron`, `michael`, `loki`)

Important runtime behavior:

- Startup hooks initialize and/or start:
  - CCE worker
  - Network discovery
  - Agent deployment service
  - AATL/AATR initialization
  - Integrations scheduler
  - Governance executor
- Health endpoints:
  - `GET /api/`
  - `GET /api/health`

---

## 3) Security and Governance Controls

### Auth and RBAC

- JWT bearer auth in `backend/routers/dependencies.py`
- Role model: `admin`, `analyst`, `viewer`
- Permission guards via `check_permission(...)`

### Hardening and access controls

- Production/strict JWT secret validation (`JWT_SECRET` required and weak values rejected)
- CORS explicit-origin enforcement in production/strict (`CORS_ORIGINS`)
- Remote access gating (`REMOTE_ADMIN_ONLY`, optional `REMOTE_ADMIN_EMAILS`)
- Machine-token auth for internal/agent endpoints and WebSocket paths

### Governance execution model

- `services/outbound_gate.py` queues high-impact actions for approval
- `services/governance_context.py` enforces governance context in prod/strict (or by explicit flag)
- `services/governance_executor.py` executes approved decisions and emits audit/world events

---

## 4) Frontend Structure

Frontend uses React + Router with a protected layout and workspace-style navigation:

- Entry routing and protected shell: `frontend/src/App.js`
- Auth/session handling: `frontend/src/context/AuthContext.jsx`
- API base helper: `frontend/src/lib/api.js`

Primary workspace routes:

- `/command`
- `/investigation`
- `/response-operations`
- `/ai-activity`
- `/email-security`
- `/endpoint-mobility`

Many legacy direct routes redirect into these workspace tabs for compatibility.

---

## 5) Docker Compose Run Modes

### Baseline stack (default compose file)

`docker-compose.yml` defines:

- MongoDB
- Redis
- Backend
- Frontend
- Celery worker
- Celery beat

Also includes optional services/profiles:

- Security profile: Trivy, Falco, Suricata, Zeek, Volatility
- Sandbox profile: Cuckoo + cuckoo-web (+ dedicated cuckoo mongo)
- Optional local AI runtime (Ollama)
- Nginx ingress service

### Production overlay

Use `docker-compose.prod.yml` with base compose to:

- Run with production/strict backend flags
- Hide direct backend/frontend/data ports
- Route ingress through Nginx

---

## 6) Quick Start (Local)

### 1. Start core services

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat
```

### 2. Check health

```bash
curl -fsS http://127.0.0.1:8001/api/health
```

### 3. Open UI

- Frontend: `http://127.0.0.1:3000`
- Backend API docs (if enabled by environment): `http://127.0.0.1:8001/docs`

### 4. Add optional profiles (example)

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

---

## 7) Environment Variables (High-Impact)

At minimum, review/configure:

- `MONGO_URL`, `DB_NAME`
- `JWT_SECRET`
- `INTEGRATION_API_KEY`
- `CORS_ORIGINS`
- `ENVIRONMENT` and `SERAPH_STRICT_SECURITY`
- `REMOTE_ADMIN_ONLY`, `REMOTE_ADMIN_EMAILS`
- `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`
- `WORLD_INGEST_TOKEN` / `SWARM_AGENT_TOKEN` as needed

For production, set explicit strong secrets and avoid permissive defaults.

---

## 8) Repository Pointers

- Backend entrypoint: `backend/server.py`
- Shared auth/dependency layer: `backend/routers/dependencies.py`
- Governance services: `backend/services/governance_*`, `backend/services/outbound_gate.py`
- Frontend routes: `frontend/src/App.js`
- Frontend auth/API setup: `frontend/src/context/AuthContext.jsx`, `frontend/src/lib/api.js`
- Compose definitions:
  - `docker-compose.yml`
  - `docker-compose.prod.yml`
- Unified agent API portal: `unified_agent/server_api.py`

---

## 9) Current Reality Notes

- The repository includes both core platform services and sidecar/auxiliary components.
- `smoke_test.py` at repository root is a standalone FastAPI sidecar-style app (CAS shield behavior), not a minimal backend health script.
- Documentation should be treated as living and periodically revalidated against code scans to avoid route/count drift.

---

## 10) Contribution and Validation Guidance

When updating docs or behavior:

1. Recalculate route/page/router metrics from code (do not rely on stale static counts).
2. Validate frontend API call-sites against backend router endpoints.
3. Recheck prod/strict security controls after auth/governance changes.
4. Keep workspace-route redirects and backend contract behavior synchronized.

