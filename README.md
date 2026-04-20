# Metatron / Seraph AI Defense Platform

Code-accurate repository guide (updated for current branch state).

## What this repository contains

This repo is a full-stack security platform with:

- A large FastAPI backend (`backend/`)
- A React frontend (`frontend/`)
- A substantial endpoint agent/runtime (`unified_agent/`)
- Docker Compose topology for local and profile-based deployment (`docker-compose.yml`)

The platform covers endpoint, network, cloud posture, threat workflows, response orchestration, identity/governance surfaces, and newer email/mobile/MDM domains.

---

## Canonical runtime architecture

### Primary backend API

- Entry: `backend.server:app`
- Port: `8001`
- Defined in:
  - `backend/server.py`
  - `backend/Dockerfile` (`CMD ["uvicorn", "backend.server:app", ...]`)

### Primary frontend

- React app built via CRACO and served by nginx in container
- Compose host mapping: `127.0.0.1:3000 -> frontend container :80`
- API reverse proxy: `/api -> http://backend:8001` (inside frontend nginx config)
- Defined in:
  - `frontend/package.json`
  - `frontend/Dockerfile`
  - `frontend/nginx.conf`

### Data and async planes

- MongoDB for backend persistence
- Redis for Celery broker/result backend
- Celery worker/beat processes for background tasks
- Defined in:
  - `docker-compose.yml`
  - `backend/celery_app.py`

---

## Repository structure

```text
backend/                 FastAPI app, routers, services, security engines
frontend/                React UI (CRACO), pages, components, auth context
unified_agent/           Endpoint runtime, local dashboards, integrations
memory/                  Internal architecture/reality/roadmap docs
docs/                    Supplementary design and integration docs
test_reports/            Generated validation and evaluation artifacts
docker-compose.yml       Local and profile-based deployment topology
```

---

## Backend overview

### Composition root

- `backend/server.py` mounts routers and initializes services.
- Most routers are mounted under `/api`.
- Some routers include explicit `/api/v1/*` prefixes in their own router definitions and are mounted without an extra `/api` prefix (notably CSPM and identity surfaces).

### High-value route families (examples)

- Auth/users: `/api/auth/*`, `/api/users/*`
- Unified agent control plane: `/api/unified/*`
- Threat/alert/timeline/response/SOAR/hunting/correlation domains
- Email:
  - `/api/email-protection/*`
  - `/api/email-gateway/*`
- Mobile and MDM:
  - `/api/mobile-security/*`
  - `/api/mdm/*`
- CSPM:
  - `/api/v1/cspm/*`
- WebSockets:
  - `/ws/threats`
  - `/ws/agent/{agent_id}`

### Background/runtime hooks

Startup in `backend/server.py` includes:

- Admin bootstrap logic (when configured)
- CCE worker startup
- Network discovery startup
- Deployment service startup
- AATL/AATR initialization
- Integration/governance schedulers

---

## Frontend overview

### Stack

- React 19 + React Router
- CRACO build tooling
- Tailwind/Radix-based component surfaces

### Main entry and route shell

- Entry: `frontend/src/index.js`
- Route topology: `frontend/src/App.js`
- Auth provider and token model: `frontend/src/context/AuthContext.jsx`
- Layout/navigation shell: `frontend/src/components/Layout.jsx`

### API base behavior

- Shared API resolver exists in `frontend/src/lib/api.js`
- Same-origin fallback path is `/api`
- `AuthContext.jsx` includes similar resolver logic (duplication exists and is a known consistency concern)

---

## Unified agent overview

### Primary endpoint runtime

- Heavy implementation lives in `unified_agent/core/agent.py`
- Includes broad monitor/remediation capabilities and local UI support hooks

### Local dashboard contract

- Canonical local dashboard: `unified_agent/ui/web/app.py` on port `5000`
- Contract documented in: `unified_agent/LOCAL_DASHBOARD_CONTRACT.md`
- Helper script: `unified_agent/run_local_dashboard.sh`

### Side server (non-canonical control plane)

- `unified_agent/server_api.py` provides a standalone FastAPI server on port `8002`
- Uses in-memory/file-backed state and backend proxy behavior
- Useful for local/standalone workflows, but not the authoritative Mongo-backed enterprise control-plane surface

---

## Docker Compose run modes

## Full local stack (aligned with current compose dependencies)

```bash
docker compose up -d mongodb redis elasticsearch ollama backend frontend
```

## Security profile extras

```bash
docker compose --profile security up -d
```

## Sandbox profile extras

```bash
docker compose --profile sandbox up -d
```

### Notes on dependency behavior

In current `docker-compose.yml`, backend `depends_on` includes:

- `mongodb`
- `redis`
- `elasticsearch`
- `ollama`

So although some integrations are conceptually optional, compose startup behavior may still require those services unless compose config is changed.

---

## Local development quickstart

### 1) Backend (non-docker)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python backend/server.py
```

Backend health check:

```bash
curl -fsS http://127.0.0.1:8001/api/health
```

### 2) Frontend (non-docker)

```bash
cd frontend
yarn install
yarn start
```

Default dev server is CRA/CRACO local dev runtime (typically port 3000).

---

## Testing and validation entry points

### Backend-focused

- `backend/tests/` (pytest suites)
- `backend/scripts/` includes:
  - `integration_runtime_full_smoke.py`
  - `e2e_endpoint_sweep.py`
  - `e2e_threat_pipeline_test.py`
  - `full_stack_e2e_validate.py`
  - `mitre_coverage_evidence_report.py`

### Unified agent focused

- `unified_agent/tests/test_monitor_scan_regression.py`
- `unified_agent/tests/test_canonical_ui_contract.py`
- `unified_agent/tests/test_endpoint_fortress.py`
- `unified_agent/tests/test_cli_identity_signals.py`

### Root-level integration scripts

- `e2e_system_test.py`
- `full_feature_test.py`
- `test_unified_agent.py`

### Frontend tests

- `frontend/src/setupTests.js` and related page/component tests

---

## Current known consistency risks (important)

1. **Frontend API base duplication**  
   API URL resolution logic appears in multiple frontend modules.

2. **High-density backend composition root**  
   `backend/server.py` centralizes many startup and wiring concerns.

3. **Multiple agent/control surfaces**  
   Core backend unified control plane, agent runtime, and side-server paths must stay aligned.

4. **Docs/scripts drift risk**  
   Historical docs may reference older route/port assumptions.

---

## Documentation map

- `memory/RUN_MODE_CONTRACT.md` — run-mode and contract baseline
- `memory/FEATURE_REALITY_MATRIX.md` — concise implementation status matrix
- `memory/FEATURE_REALITY_REPORT.md` — narrative capability reality assessment
- `memory/SYSTEM_CRITICAL_EVALUATION.md` — critical architecture/risk review
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` — system-wide rebaseline

---

## Final notes

This README intentionally prioritizes **as-implemented behavior** over historical version narratives. For planning and strategic context, use the docs in `memory/` and `docs/` alongside current code paths.
