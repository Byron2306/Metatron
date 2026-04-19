# Seraph AI Defense System

Repository reality-aligned overview (updated April 2026).

## What this repository contains

Seraph is a modular security platform composed of:

- **Backend control plane**: FastAPI app in `backend/server.py`
- **Operator frontend**: React app in `frontend/`
- **Unified endpoint agent**: code and adapters in `unified_agent/`
- **Governed execution pipeline**: decision-gated command dispatch in `backend/services/`
- **Integration runtime**: tool orchestration in `backend/integrations_manager.py` and `backend/routers/integrations.py`

This codebase is feature-rich and broad. The most important operational concept is:
**high-impact actions are intended to flow through governance and auditable queues rather than direct execution**.

---

## Current architecture snapshot

Measured from current code:

- Backend router modules: **62** (`backend/routers/*.py`)
- Backend service modules: **33** (`backend/services/*.py`)
- Router endpoint decorators: **694**
- Frontend page modules: **68** (`frontend/src/pages/*`)
- Route declarations in frontend shell: **66** (`frontend/src/App.js`)
- Unified-agent integration adapters: **12** (`unified_agent/integrations/*`)

### High-level flow

1. Frontend calls backend APIs (mostly under `/api/*`).
2. Backend routers invoke domain services and persist state to MongoDB.
3. World events and telemetry hooks project security-relevant state.
4. Governed dispatch + decision authority + executor manage high-impact command execution.
5. Unified agent and integrations runtime provide endpoint and external tooling execution paths.

---

## Core code entrypoints

### Backend

- Main app: `backend/server.py`
- Router modules: `backend/routers/`
- Core services: `backend/services/`
- Integration orchestration: `backend/integrations_manager.py`
- Runtime path resolver: `backend/runtime_paths.py`

### Frontend

- App shell and route map: `frontend/src/App.js`
- Workspace/feature pages: `frontend/src/pages/`
- Layout/nav shell: `frontend/src/components/Layout.jsx`

### Unified agent

- Endpoint runtime core: `unified_agent/core/agent.py`
- Optional local API/proxy: `unified_agent/server_api.py`
- Tool adapters: `unified_agent/integrations/*`
- Local web UI: `unified_agent/ui/web/app.py`

---

## API surface and route model

Primary API namespace is mounted from `backend/server.py`.

- Most routers mount under: `"/api" + router prefix`
- Some routers define embedded `/api/v1/*` prefixes and are mounted directly:
  - `/api/v1/cspm/*`
  - `/api/v1/identity/*`
  - `/api/v1/attack-paths/*`
  - `/api/v1/secure-boot/*`
  - `/api/v1/kernel/*`
- Deception is intentionally mounted at both:
  - `/api/deception/*`
  - `/api/v1/deception/*` (compatibility path)

WebSocket endpoints:

- `/ws/threats`
- `/ws/agent/{agent_id}` (machine token validated)

Core liveness endpoint:

- `GET /api/health`

---

## Security and governance model (important)

### AuthN/AuthZ

- JWT auth + RBAC in `backend/routers/dependencies.py`
- Roles: `admin`, `analyst`, `viewer`
- Auth/user routes: `backend/routers/auth.py`
- Setup-token bootstrap endpoint: `/api/auth/setup`

### Machine-token protected surfaces

Machine token dependencies are used in ingestion/internal paths such as:

- world ingest (`backend/routers/world_ingest.py`)
- integrations (`backend/routers/integrations.py`)
- advanced/enterprise identity-related internal routes
- agent websocket channel validation in `backend/server.py`

### Governance-gated execution chain

- `backend/services/governed_dispatch.py`
- `backend/services/governance_authority.py`
- `backend/services/governance_executor.py`
- API control endpoints in `backend/routers/governance.py`

Intended model:

1. queue action in gated state,
2. approve/deny decision,
3. execute approved items with audit/event traces.

---

## Run modes

## 1) Minimal backend mode

Requirements:

- Python 3.11+
- MongoDB reachable by `MONGO_URL`

Run:

```bash
python3 backend/server.py
```

or

```bash
uvicorn backend.server:app --host 0.0.0.0 --port 8001
```

Verify:

```bash
curl -sS http://127.0.0.1:8001/api/health
```

## 2) Frontend + backend local mode

Backend:

```bash
python3 backend/server.py
```

Frontend:

```bash
cd frontend
yarn install
yarn start
```

## 3) Docker compose mode

Repository includes a multi-service compose file (`docker-compose.yml`) with 21 services, including:

- `mongodb`, `backend`, `frontend`
- `redis`, `celery-worker`, `celery-beat`
- optional/extended tooling: `elasticsearch`, `kibana`, `trivy`, `falco`, `suricata`, `zeek`, `cuckoo`, `wireguard`, etc.

Start baseline stack:

```bash
docker compose up -d
```

Check backend health:

```bash
docker compose exec backend curl -fsS http://127.0.0.1:8001/api/health
```

---

## Key environment variables

Backend startup behavior depends on environment settings. Important ones include:

- `MONGO_URL`
- `DB_NAME`
- `JWT_SECRET`
- `ENVIRONMENT`
- `SERAPH_STRICT_SECURITY`
- `CORS_ORIGINS`
- `INTEGRATION_API_KEY`
- `WORLD_INGEST_TOKEN` (if used for M2M ingest flows)
- `SWARM_AGENT_TOKEN` / related internal tokens

Security note:

- In production/strict mode, weak or missing secrets are rejected by startup checks.

---

## Repository layout

```text
.
├── backend/
│   ├── server.py
│   ├── routers/
│   ├── services/
│   ├── integrations_manager.py
│   └── tests/
├── frontend/
│   ├── src/App.js
│   ├── src/pages/
│   └── src/components/
├── unified_agent/
│   ├── core/agent.py
│   ├── server_api.py
│   ├── integrations/
│   └── ui/
├── memory/
├── docs/
├── docker-compose.yml
└── DEPLOYMENT.md
```

---

## Testing and validation

Representative test/validation entrypoints in repo:

- Backend tests: `backend/tests/test_*.py`
- Unified-agent tests: `unified_agent/tests/test_*.py`
- Root-level checks:
  - `e2e_system_test.py`
  - `full_feature_test.py`
- Backend script validations in `backend/scripts/`

Run selected backend tests:

```bash
pytest backend/tests -q
```

Run unified-agent tests:

```bash
pytest unified_agent/tests -q
```

---

## Updated memory/review documents

The major review docs were refreshed to match current code logic:

- `memory/full_pages_wiring_audit.md`
- `memory/dashboard_static_audit.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/PRD.md`
- `memory/RUN_MODE_CONTRACT.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/SERAPH_BOARD_BRIEF_2026.md`
- `memory/SERAPH_COMPETITIVE_WHITEPAPER_2026.md`
- `memory/SERAPH_IMPLEMENTATION_ROADMAP_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`

---

## Known current caveats

From static wiring checks, a small number of frontend legacy call-sites still reference non-canonical endpoints:

- `/api/data`
- `/api/login`
- `/api/admin/users`

These are documented in `memory/full_pages_wiring_audit.md` and should be normalized to canonical route contracts.

---

## Practical bottom line

Seraph is currently a large, multi-domain defensive platform with strong governance and integration foundations.  
The primary engineering focus going forward should be contract consistency, operational profile clarity, and reliability hardening across its wide feature surface.

