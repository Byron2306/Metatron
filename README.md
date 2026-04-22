# Metatron / Seraph AI Defense Platform

Metatron/Seraph is a modular cybersecurity platform built around a FastAPI backend, React frontend, MongoDB data plane, and a unified endpoint agent. It combines SOC workflows (alerts/threats/timeline), governed response execution, endpoint orchestration, and domain modules such as email security, mobile security, and CSPM.

> This README reflects the current codebase state as of April 2026.

## Table of Contents
- [Current Architecture](#current-architecture)
- [Core Capabilities](#core-capabilities)
- [Implementation Reality Notes](#implementation-reality-notes)
- [Repository Layout](#repository-layout)
- [Quick Start](#quick-start)
- [Runtime Profiles](#runtime-profiles)
- [Configuration](#configuration)
- [API Surface Overview](#api-surface-overview)
- [Unified Agent and EDM](#unified-agent-and-edm)
- [Security Model](#security-model)
- [Testing and Validation](#testing-and-validation)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)

## Current Architecture

### Runtime stack
- **Backend**: FastAPI app in `backend/server.py`
- **Frontend**: React app in `frontend/`
- **Database**: MongoDB (Motor async client)
- **Optional infra**: Redis/Celery, Elasticsearch/Kibana, WireGuard, Ollama, security/sandbox profile services
- **Endpoint plane**: Unified agent in `unified_agent/`

### Entry points
- API root: `/api/`
- Health: `/api/health`
- WebSockets:
  - `/ws/threats`
  - `/ws/agent/{agent_id}` (machine-token protected)

### Router composition
The backend includes 60+ router modules (mounted mostly under `/api`, with some native `/api/v1/*` prefixes such as CSPM).

## Core Capabilities

### SOC and response workflows
- Threat and alert operations
- Threat hunting and timeline reconstruction
- Quarantine and response actions
- SOAR and automation flows
- Audit logging and reports

### Governance and controlled execution
- Decision approval/denial API: `backend/routers/governance.py`
- Decision authority transitions: `backend/services/governance_authority.py`
- Execution release loop: `backend/services/governance_executor.py`
- Outbound gate integration for high-impact actions (for example CSPM provider changes/scans)

### Cloud Security Posture Management (CSPM)
- Router: `backend/routers/cspm.py` (prefix `/api/v1/cspm`)
- Provider config, scans, findings, compliance reports, dashboard/export
- Authenticated scan start path (`Depends(get_current_user)`) and durable state transition records

### Email security
- Email protection service: `backend/email_protection.py`
- Email gateway service/router: `backend/email_gateway.py`, `backend/routers/email_gateway.py`
- Frontend workspace: `frontend/src/pages/EmailSecurityWorkspacePage.jsx`
  - Protection tab
  - Gateway tab

### Mobile and endpoint mobility
- Mobile security service/router: `backend/mobile_security.py`, `backend/routers/mobile_security.py`
- MDM connectors service/router: `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py`
- Frontend workspace: `frontend/src/pages/EndpointMobilityWorkspacePage.jsx`

### Unified agent operations
- Unified control plane API: `backend/routers/unified_agent.py` (prefix `/unified`)
- Swarm operations API: `backend/routers/swarm.py` (prefix `/swarm`)
- Agent install/download endpoints for Linux/Windows/macOS/Android/iOS
- Agent telemetry, commands, monitor and alert streams

## Implementation Reality Notes

These are important for accurate planning and operations:

1. **MDM support breadth is partial**
   - `/api/mdm/platforms` advertises Intune, JAMF, Workspace ONE, and Google Workspace.
   - `MDMConnectorManager.add_connector(...)` currently wires onboarding for **Intune + JAMF**.
   - Treat Workspace ONE / Google Workspace as target-facing metadata paths unless connector manager support is added.

2. **Optional dependencies are non-blocking by design**
   - Several modules degrade gracefully when optional services are unavailable.

3. **Backend startup is broad and orchestrated**
   - Startup hooks initialize multiple services (CCE worker, discovery, deployment service, AATL/AATR, integrations scheduler, governance executor).

4. **Auth and security mode behavior depends on environment flags**
   - `ENVIRONMENT` and `SERAPH_STRICT_SECURITY` influence JWT/CORS startup requirements.

## Repository Layout

```text
backend/                 FastAPI app, routers, services, tests
frontend/                React application and pages
unified_agent/           Endpoint agent runtime and related utilities
memory/                  Strategic and technical review documents
scripts/                 Helper and validation scripts
docker-compose.yml       Main local orchestration file
```

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.11+ (for local script/test work)
- Node.js (for frontend local dev without containers)

### Minimal stack (core)
```bash
docker compose up -d mongodb backend frontend
```

### Recommended local stack
```bash
docker compose up -d mongodb redis backend frontend wireguard elasticsearch kibana ollama
```

### Validate health
```bash
curl -fsS http://localhost:8001/api/health
```

Optional smoke test:
```bash
python3 smoke_test.py
```

## Runtime Profiles

From `docker-compose.yml`:

- **Core services**: `mongodb`, `redis`, `backend`, `frontend`
- **Security profile** (`--profile security`): `trivy`, `falco`, `suricata`, `zeek`, `volatility`
- **Sandbox profile** (`--profile sandbox`): `cuckoo`, `cuckoo-web`, plus dedicated `cuckoo-mongo`
- **Bootstrap profile** (`--profile bootstrap`): helper one-shot services (for example model/admin bootstrap)

## Configuration

Key backend environment variables (non-exhaustive):

- `MONGO_URL`, `DB_NAME`
- `JWT_SECRET`
- `ENVIRONMENT` (`prod`/`production` affects strict behavior)
- `SERAPH_STRICT_SECURITY` (`true` enforces stricter startup checks)
- `CORS_ORIGINS`
- `INTEGRATION_API_KEY`
- `REMOTE_ADMIN_ONLY`, `REMOTE_ADMIN_EMAILS`

Important behavior:
- In production-like mode, weak/missing JWT secrets and wildcard CORS are blocked.
- Websocket machine-token checks require configured token env vars.

## API Surface Overview

Representative prefixes and domains:

- `/api/auth`, `/api/users`
- `/api/threats`, `/api/alerts`, `/api/timeline`, `/api/reports`
- `/api/response`, `/api/quarantine`, `/api/soar`
- `/api/unified/*` (agent lifecycle, EDM, installers)
- `/api/swarm/*` (fleet/scan/deploy/control)
- `/api/governance/*` (decision workflow and executor trigger)
- `/api/email-protection/*`
- `/api/email-gateway/*`
- `/api/mobile-security/*`
- `/api/mdm/*`
- `/api/v1/cspm/*`
- `/api/ingest/*` (world model ingest, machine-token gated)

For exact path contracts, inspect the corresponding router modules under `backend/routers/`.

## Unified Agent and EDM

The unified agent (`unified_agent/core/agent.py`) includes:
- Multi-monitor telemetry collection
- Command handling and response flows
- EDM fingerprinting engine with dataset loading and hot reload
- EDM dataset update/reload command paths

Backend EDM control plane (`backend/routers/unified_agent.py`) provides:
- Dataset version lifecycle
- Publish and rollback operations
- Rollout state tracking and readiness endpoints
- Telemetry summary endpoints

## Security Model

### Authentication and authorization
- JWT bearer auth via shared dependencies in `backend/routers/dependencies.py`
- Role-based permission checks (`admin`, `analyst`, `viewer` plus capability mapping)
- Optional remote-admin restriction for non-local requests

### Machine-to-machine controls
- Header-based machine tokens with constant-time comparison
- Dedicated websocket token verification helper
- World ingest routes gated via required machine token dependency

### Audit and governance trails
- Governance decision and execution updates persisted in DB collections
- World event emission around major control-plane transitions
- Telemetry-chain hooks for tamper-evident action trails in key services

## Testing and Validation

Backend tests live primarily under `backend/tests/`.

Typical test command:
```bash
pytest backend/tests -q
```

Additional repository-level validation scripts include:
- `smoke_test.py`
- `full_feature_test.py`
- `e2e_system_test.py`

Run only the scope you need to keep feedback cycles fast.

## Development Workflow

### Backend
```bash
cd backend
uvicorn server:app --reload --host 0.0.0.0 --port 8001
```

### Frontend
```bash
cd frontend
yarn install
yarn start
```

### API base behavior in frontend
- Shared helper: `frontend/src/lib/api.js`
- Defaults to same-origin `/api` when `REACT_APP_BACKEND_URL` is absent/invalid
- If a localhost backend URL is configured but browser is remote, helper falls back to same-origin to avoid invalid cross-host calls

## Troubleshooting

### Backend fails on startup in production mode
Check:
- `JWT_SECRET` strength/length
- `CORS_ORIGINS` explicit values (no wildcard in strict/prod)
- `INTEGRATION_API_KEY` set when required

### MDM connector add fails for non-Intune/JAMF platform
Current connector manager onboarding path supports Intune and JAMF. Use those for active testing unless additional platform connectors are implemented in manager wiring.

### Frontend cannot reach backend
Verify:
- Backend health at `/api/health`
- `REACT_APP_BACKEND_URL` value
- Reverse-proxy or CORS settings for your deployment mode

---

For strategic and implementation-reality analysis documents, see `memory/`.
