# Metatron/Seraph Run-Mode Contract (Updated April 2026)

## Goal

Define the real runtime contract of the current codebase so deployment and validation are grounded in what actually runs today.

## 1) Required core services

These components are required for the primary product API path:

1. `backend/server.py` (FastAPI app, port 8001)
2. MongoDB (`MONGO_URL`, database set via `DB_NAME`)
3. Frontend SPA (`frontend/`) if UI access is required

Behavioral contract:

- Backend starts and mounts routers under `/api` plus selected `/api/v1` routers.
- Authentication and permission checks are enforced by `backend/routers/dependencies.py`.
- Health endpoint must respond on `GET /api/health`.

## 2) Optional-but-supported operational dependencies

These are optional at runtime; feature areas degrade if absent:

- Redis / Celery (`docker-compose.yml`: `redis`, `celery-worker`, `celery-beat`)
- Elasticsearch + Kibana
- Trivy, Falco, Suricata, Zeek, Cuckoo
- WireGuard
- Ollama
- Unified-agent side API (`unified_agent/server_api.py`) and Flask dashboard

Contract:

- Missing optional dependencies must not break core API startup.
- Related feature endpoints may return degraded status or partial data.

## 3) Runtime launch modes

### Mode A: Backend-only API mode

Use when validating server contracts quickly.

- Start: `uvicorn backend.server:app --host 0.0.0.0 --port 8001`
- Requires MongoDB connectivity (or mock mode via env where configured)

### Mode B: Local full-stack dev mode

Use for backend + frontend integration.

- Backend: `backend/server.py` or uvicorn command above
- Frontend: `frontend` (`craco start` or containerized nginx build path)

### Mode C: Compose baseline mode

Use `docker-compose.yml` to run multi-service stack.

- Service definitions: 21
- Core dev path uses: `mongodb`, `backend`, `frontend` (plus optional stack)

### Mode D: Extended security profile

Enable optional sensors/services (Falco, Suricata, Zeek, Trivy, Cuckoo, volatility helper) for deeper telemetry and detection workflows.

## 4) API routing contract

Primary contract:

- Most routers mount under `/api`.
- Selected routers are pre-prefixed with `/api/v1/*` and mounted directly:
  - `/api/v1/cspm`
  - `/api/v1/identity`
  - `/api/v1/attack-paths`
  - `/api/v1/secure-boot`
  - `/api/v1/kernel`

Compatibility contract:

- Deception router mounted at both `/api/deception` and `/api/v1/deception`.

## 5) Auth and machine-token contract

User auth:

- JWT-based auth (`JWT_SECRET`) via bearer token dependencies.
- Role-based permissions (`admin`, `analyst`, `viewer`) with capability checks.

Machine/M2M auth:

- Shared token dependencies (`require_machine_token`, `optional_machine_token`) in:
  - `world_ingest`
  - `integrations`
  - `advanced`
  - `enterprise`
  - `identity`
  - `swarm`
  - `loki`
  - `agent_commands`
  - `cli_events`

WebSocket token enforcement:

- `/ws/agent/{agent_id}` validates machine token via `verify_websocket_machine_token`.

## 6) Governance + command dispatch contract

Operationally impactful commands are designed to pass through governance queueing:

- Queueing and gating: `backend/services/governed_dispatch.py`
- Decision authority transitions: `backend/services/governance_authority.py`
- Approved execution processing: `backend/services/governance_executor.py`
- API surface: `backend/routers/governance.py`

Expected decision states:

- pending -> approved/denied
- approved decisions may move to `pending_executor` then execution outcomes

## 7) Data/storage contract

Primary store:

- MongoDB for users, threats, alerts, triune/governance state, command queues, integrations jobs, and world model collections.

Writable filesystem paths:

- Resolved through `backend/runtime_paths.py::ensure_data_dir()`
- Primary default: `/var/lib/anti-ai-defense`
- Fallback default: `/tmp/anti-ai-defense`

Agent-side/local state:

- `unified_agent/server_api.py` uses local JSON persistence for `agents_db.json`, `alerts_db.json`, `deployments_db.json`.

## 8) Acceptance criteria for “working”

Minimum healthy state:

1. `GET /api/health` returns healthy response.
2. Auth flow can create/login user and resolve `/api/auth/me`.
3. Core pages can fetch their primary backend data sources.
4. Governance queue path can create/read pending decisions.
5. No fatal startup exception from missing optional integrations.

Extended healthy state:

1. Integrations jobs can be queued and queried (`/api/integrations/jobs`).
2. World ingest M2M endpoints accept valid machine token calls.
3. Unified-agent command/heartbeat paths operate end-to-end.

## 9) Known contract caveats (current)

1. A few legacy frontend call-sites still reference non-canonical endpoints (`/api/data`, `/api/login`, `/api/admin/users`).
2. `unified_agent/server_api.py` still describes proxying to `server_old.py` in docstrings/comments even while backend mainline is `backend/server.py`.
3. Compose includes a large optional matrix; not all services are required for base functional runs.

## 10) Contract maintenance triggers

Update this document whenever:

- a router prefix changes,
- a new machine-token surface is added,
- governance states or dispatch behavior change,
- startup dependencies in `server.py` are altered.

