# Metatron / Seraph Run-Mode Contract

## Current Code-Logic Snapshot (updated 2026-04-28)

- Backend API: `backend/server.py`, FastAPI title `Anti-AI Defense System API`, version `3.0.0`, served on port `8001`.
- Health: `GET /api/health`; older `:8000/health` references are stale.
- Routing: 61 backend router modules plus `backend/routers/__init__.py`; most routers mount under `/api`, with selected native `/api/v1` families.
- Services: 32 backend service modules plus `backend/services/__init__.py`.
- Frontend: `frontend/src/App.js` uses `BrowserRouter`, `AuthProvider`, and `Layout`; authenticated index redirects to `/command`.
- Pages: 68 JSX page files plus `frontend/src/pages/GraphWorld.tsx`; `App.js` contains 68 `<Route` occurrences including redirects.
- Unified agent: `unified_agent/core/agent.py` declares `AGENT_VERSION = "2.0.0"`; backend control plane is under `/api/unified/...`.
- Data/runtime: MongoDB defaults to database `seraph_ai_defense`; Redis/Celery and optional ELK/Ollama/WireGuard/security-tool services are compose-managed.
- Tests: 63 backend `test_*.py` files plus unified-agent tests and GitHub contract/regression workflows.
- Caveat: root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack smoke test.


## Goal

Define the minimum services required for a healthy Seraph deployment and the behavior expected when optional integrations are unavailable.

## Required Core

The dashboard is healthy only when these services are available:

- `mongodb`
- `redis` when using compose/Celery-backed workflows
- `backend`
- `frontend`

The backend listens on `8001` and exposes health at `/api/health`. The frontend listens on `3000` in local development and uses `/api` or `REACT_APP_BACKEND_URL` for API access.

## Optional Integrations

Optional services add capability but must not block baseline SOC operation:

- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`
- `trivy`
- `falco`
- `suricata`
- `cuckoo` / `cuckoo-web`

Expected behavior when optional services are down:

- Core login, command, threat, alert, investigation, and response pages remain usable.
- Integration-specific pages show degraded state, empty data, or actionable configuration errors.
- Backend responses distinguish unavailable dependencies from platform failure.

## Launch Modes

```bash
docker compose up -d mongodb redis backend frontend
docker compose up -d mongodb redis backend frontend wireguard elasticsearch kibana ollama
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

## API Routing Contract

- Backend REST APIs are primarily under `/api/...`.
- Selected router families expose `/api/v1/...` because their routers include the versioned prefix internally.
- App-level WebSockets are `/ws/threats` and `/ws/agent/{agent_id}`.
- Production deployments should prefer same-origin `/api` routing through the reverse proxy.

## Health Validation Sequence

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Then validate at least one page from `/command`, `/investigation`, `/response-operations`, `/unified-agent`, `/email-security`, and `/endpoint-mobility`.

## Definition of Working

A deployment is considered working when required core services are healthy, `GET /api/health` succeeds, the React app reaches `/command`, core SOC read paths function, unified-agent control routes are reachable when agents are configured, and optional integrations degrade explicitly without cascading backend or UI failure.
