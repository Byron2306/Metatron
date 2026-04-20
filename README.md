# Metatron / Seraph AI Defense Platform

Integrated security platform with a FastAPI control plane, React operator UI, and a deep endpoint runtime (`unified_agent`).

This README is a code-accurate rebaseline for the current repository state (April 2026).

---

## What is in this repository

- **Backend API** (`backend/server.py`)
  - FastAPI app with broad `/api` and `/api/v1` router mesh.
  - MongoDB-backed state via Motor (or mongomock-motor fallback).
  - Startup services: CCE worker, network discovery, deployment service, integrations scheduler, governance executor.
- **Frontend UI** (`frontend/`)
  - React app (CRA + CRACO) with protected pages for SOC, response, governance, unified-agent operations, and platform configuration.
  - API base URL handling in `frontend/src/lib/api.js`.
- **Unified agent runtime** (`unified_agent/core/agent.py`)
  - Large multi-monitor endpoint runtime with telemetry, EDM data controls, and optional triune approval gating for remediation.
- **Async workers** (`backend/celery_app.py`, `backend/tasks/`)
  - Celery worker/beat for async ingestion and scheduled orchestration tasks.

---

## Core runtime flow (current code logic)

### 1) Ingest -> world model risk

Ingestion endpoints under `/api/ingest/*` (`backend/routers/world_ingest.py`) and corresponding async tasks (`backend/tasks/world_ingest_tasks.py`) update world entities/edges and recompute risk via:

- `WorldModelService` in `backend/services/world_model.py`
- `calculate_risk(entity_id)` after upserts/detections

### 2) World events -> Triune orchestration

`emit_world_event()` in `backend/services/world_events.py` persists event records and conditionally triggers triune processing by event class.

Triune execution is orchestrated by `TriuneOrchestrator` (`backend/services/triune_orchestrator.py`):

- Metatron assessment (`assess_world_state`)
- Michael planning (`plan_actions`)
- Loki challenge (`challenge_plan`)
- Beacon cascade reflex handling

### 3) Governed action lifecycle

High-impact actions are queued through:

- `OutboundGateService` (`backend/services/outbound_gate.py`)
- `GovernedDispatchService` (`backend/services/governed_dispatch.py`)

Approval/denial APIs:

- `backend/routers/governance.py` (`/api/governance/*`)

Approved decision release/execution:

- `GovernanceExecutorService` (`backend/services/governance_executor.py`)

### 4) Endpoint command and telemetry plane

Unified-agent API surface:

- `backend/routers/unified_agent.py` (`/api/unified/*`)

Endpoint runtime:

- `unified_agent/core/agent.py` (heartbeat, telemetry, monitor outputs, EDM update/signature validation, remediation controls)

---

## Repository structure

```text
backend/                 FastAPI app, services, routers, celery tasks
frontend/                React operator UI
unified_agent/           Endpoint runtime + local dashboard utilities
memory/                  Architecture/evaluation/roadmap documents
docs/                    Supporting product/technical docs
test_reports/            Generated validation reports
docker-compose.yml       Main local deployment topology
```

---

## Local development and run

## Prerequisites

- Docker Engine + Docker Compose v2
- Python 3.11+ (for local scripts/tests)
- Node.js 20+ (for frontend local dev if not using Docker build)

## Quick start (containerized stack)

```bash
docker compose up -d --build
```

Default notable ports from `docker-compose.yml`:

- Frontend: `http://127.0.0.1:3000`
- Backend API: `http://127.0.0.1:8001`
- MongoDB: `127.0.0.1:27017`
- Redis: `127.0.0.1:6379`
- Nginx (if enabled): `http://localhost` and `https://localhost`

Health endpoint:

```bash
curl -fsS http://127.0.0.1:8001/api/health
```

## Optional one-shot admin bootstrap

`docker-compose.yml` includes an `admin-bootstrap` profile service that calls `/api/auth/setup` after backend health is up.

Run it explicitly:

```bash
docker compose --profile bootstrap up admin-bootstrap
```

Core auth routes:

- `POST /api/auth/setup`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`

---

## Frontend API base behavior

`frontend/src/lib/api.js` currently resolves API root as:

- `REACT_APP_BACKEND_URL + "/api"` if provided and valid
- fallback to same-origin `"/api"` otherwise

This reduces environment misconfiguration drift between local and proxied deployments.

---

## Selected service domains (implemented in this repo)

- Threat, alert, hunting, correlation, timeline
- SOAR, quarantine, response orchestration
- Unified agent lifecycle and command/control
- World model + risk scoring + triune orchestration
- Governance/approval/dispatch executor loop
- Email protection and email gateway APIs
- Mobile security and MDM connectors APIs
- Identity/CSPM/zero-trust/enterprise control-plane services

---

## Testing and validation

Run backend tests (example):

```bash
pytest -q
```

Project-level smoke helper scripts and reports exist in:

- `smoke_test.py`
- `test_reports/`
- various domain-specific test files under repo root and `unified_agent/tests/`

Use targeted test subsets when changing a specific plane (governance, ingest, unified agent, frontend contracts) to keep feedback tight.

---

## Security and operational notes

- Several services support optional integrations and can run in degraded mode depending on credentials/connectivity.
- Security posture is strongest when environment secrets and strict CORS/JWT settings are explicitly configured for your deployment context.
- Governance durability and contract assurance should be treated as continuous engineering priorities as feature velocity continues.

---

## Related documentation

Major evaluation and strategy docs are under `memory/`, including:

- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/architecture_diagrams/architecture-map-2026-03-06.md`

These files were rebaselined to reflect current code logic.
