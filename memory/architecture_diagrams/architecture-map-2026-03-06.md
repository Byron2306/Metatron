# Metatron Full Architecture Map (Rebased 2026-04-15)

> Historical filename retained for continuity.  
> This map reflects current repository architecture and wiring semantics.

## 1) Topology at a Glance

- **Frontend:** React 19 + `react-router-dom` + CRACO build pipeline (`frontend/`).
- **Backend:** FastAPI API server (`backend/server.py`) with modular router registration and startup lifecycle hooks.
- **Data stores:** MongoDB primary state + Redis broker/backend for Celery.
- **Async execution:** Celery worker/beat + in-process asyncio service loops.
- **Optional security stack:** Trivy, Falco, Suricata, Zeek, Volatility, Cuckoo, Ollama.
- **Ingress patterns:** direct local bindings in base compose; Nginx-only ingress in production overlay.

## 2) Frontend Architecture

Core shell:
- Router and protected layout: `frontend/src/App.js`, `frontend/src/components/Layout.jsx`
- Auth/session bootstrap: `frontend/src/context/AuthContext.jsx`
- API base helper: `frontend/src/lib/api.js`

Current route model:
- `67` route entries in `App.js`
- Workspace hubs:
  - `/command`
  - `/investigation`
  - `/response-operations`
  - `/ai-activity`
  - `/email-security`
  - `/endpoint-mobility`
- Legacy paths preserved via redirects (for route stability during migration)

Page inventory:
- `69` page components under `frontend/src/pages` (excluding test files)

## 3) Backend API Architecture

Entrypoint:
- `backend/server.py`

Wiring characteristics:
- `65` `app.include_router(...)` registrations
- `61` router modules (excluding shared dependencies helper)
- Mix of `/api/*` mounts and routers that natively expose `/api/v1/*`

Major API domains:
- Core platform: auth, dashboard, settings, reports, audit, timeline
- Threat operations: threats, alerts, hunting, correlation, intel
- Response plane: response, quarantine, SOAR, deception, ransomware
- Endpoint plane: agents, swarm, unified agent, agent commands
- Security controls: zero trust, identity, governance, enterprise, multi-tenant
- Advanced/ops: CSPM, EDR, sandbox, VPN, containers, Zeek, osquery, Sigma, Atomic
- Intelligence/world model: metatron/michael/loki + world ingest/events
- Emerging domains: email protection/gateway, mobile security, MDM connectors

## 4) Runtime Services and Execution Planes

Startup-triggered services (`backend/server.py`):
- CCE worker
- network discovery
- deployment service
- AATL and AATR initialization
- integrations scheduler
- governance executor

Execution planes:
- Request/response API routes (FastAPI)
- WebSockets (`/ws/threats`, `/ws/agent/{agent_id}`)
- Async background loops (in-process)
- Celery queue workers and scheduled tasks

## 5) Governance and Security Control Paths

Primary controls:
- JWT + RBAC + remote admin gating (`backend/routers/dependencies.py`)
- Machine-token auth for ingest/internal paths and WebSockets
- Governance context requirement (`backend/services/governance_context.py`)
- Outbound gate queue (`backend/services/outbound_gate.py`)
- Governed execution (`backend/services/governance_executor.py`)
- Tamper-evident telemetry hooks in multiple domains

Operational posture:
- Strong controls exist in core paths.
- Principal risk is consistency across all active + legacy surfaces.

## 6) Data and Persistence

- MongoDB collections back core API state, telemetry, governance queue/decisions, and world model entities/events.
- Redis backs Celery broker/result backend.
- Optional SIEM/search stack (Elasticsearch/Kibana) supports analytics and external-facing security workflows.
- Filesystem-backed runtime data is used by selected integrations and tooling.

## 7) Deployment Modes

Local baseline:
- `docker compose up -d mongodb redis backend frontend celery-worker celery-beat`

Security profile:
- `docker compose --profile security up -d`

Sandbox profile:
- `docker compose --profile sandbox up -d`

Production-like:
- `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`
- Backend/frontend become internal-only services; Nginx is the ingress surface.

## 8) Current Architectural Risk Focus

1. API contract drift between frontend call sites and backend route evolution.
2. Complexity concentration in `backend/server.py` startup and router assembly.
3. Assurance/test depth across security-critical denial paths.
4. Operational variability caused by optional integrations and profile-specific behavior.

## 9) Practical Interpretation

The architecture is broad and genuinely implemented, with clear enterprise aspirations and governance-aware design.  
Primary maturity work now is architectural consistency and verification rigor, not basic capability expansion.
