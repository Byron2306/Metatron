# Metatron / Seraph AI Defense Platform

Metatron / Seraph is a governed adaptive defense platform for SOC operations, endpoint telemetry, AI-agent detection, world-state reasoning, and approval-gated response automation.

The active repository is built around:

- a modular FastAPI backend in `backend/server.py`,
- a React/Craco operator console in `frontend/`,
- a cross-platform unified endpoint agent in `unified_agent/`,
- a governance path for high-impact commands,
- world-model, cognition, AATL/AATR, and Triune reasoning services,
- Docker Compose and targeted contract/regression tests.

## Current Architecture

```text
Frontend operator console
  frontend/src/App.js
  frontend/src/components/Layout.jsx
        |
        v
Main SOC API
  backend/server.py  ->  /api/... routers
        |
        +-- MongoDB-backed domain state
        +-- CCE worker, AATL/AATR, network discovery, deployment services
        +-- World model and world events
        +-- Governed dispatch and governance executor
        |
        v
Unified endpoint agent
  unified_agent/core/agent.py
  backend/routers/unified_agent.py

Optional local agent portal
  unified_agent/server_api.py
  default: http://localhost:5000, proxies selected data to backend port 8001
```

## Repository Map

| Path | Purpose |
|---|---|
| `backend/server.py` | Main FastAPI composition root. Loads environment, configures MongoDB/CORS, mounts routers, starts background services. |
| `backend/routers/` | REST and WebSocket API modules for SOC workflows, agents, governance, identity, CSPM, email, mobile, deception, AI threats, and integrations. |
| `backend/services/` | Long-running and shared services: cognition, world model, governance, dispatch, policy, identity, SIEM, telemetry chain, network discovery, and more. |
| `frontend/` | React 19 + Craco operator console with protected routes and consolidated workspaces. |
| `unified_agent/core/agent.py` | Cross-platform endpoint agent v2.0 with broad monitor and response surfaces. |
| `unified_agent/server_api.py` | Separate lightweight agent portal/API and proxy for local operator use. |
| `docker-compose.yml` | Local/integration stack for MongoDB, Redis, backend, Celery, frontend, and security tooling services. |
| `memory/` | Current architecture/review documents and evidence notes. |
| `docs/` | Feature integration notes and supplemental architecture references. |
| `backend/tests/`, `unified_agent/tests/` | Contract, durability, monitor, and regression tests. |

## Backend

The main backend is `backend/server.py`.

Key behavior:

- FastAPI app title: `Anti-AI Defense System API`
- API version: `3.0.0`
- Default runtime port: `8001`
- Database: MongoDB through Motor, with optional mock mode
- Health endpoints:
  - `GET /api/`
  - `GET /api/health`
- App-level WebSockets:
  - `/ws/threats`
  - `/ws/agent/{agent_id}`

The backend currently has 62 router files on disk and 65 active `include_router` registrations in `backend/server.py`. Most routes are mounted under `/api`; some routers own `/api/v1` prefixes internally.

Major API areas include:

- authentication and users,
- threats, alerts, dashboard, reports, audit, timeline,
- network, hunting, honeypots, deception, honey tokens,
- response, SOAR, quarantine, EDR, agent commands,
- unified agent registration, heartbeat, telemetry, EDM/DLP, and command flows,
- AI threats, CCE/CLI events, AATL, AATR,
- governance, enterprise controls, policy, tools, telemetry,
- identity, zero trust, VPN,
- CSPM, containers, secure boot, kernel sensors,
- email protection, email gateway, mobile security, MDM connectors,
- world ingest, Triune persona routers, and advanced services.

## Governance and High-Impact Automation

High-impact agent and domain actions should flow through governed dispatch:

1. A command/action is requested by an API, workflow, or service.
2. `backend/services/governed_dispatch.py` calls `OutboundGateService`.
3. The command is persisted with `gated_pending_approval`, `decision_id`, `queue_id`, transition log, and authority context.
4. `/api/governance/decisions/pending` lists decisions awaiting review.
5. `/api/governance/decisions/{decision_id}/approve` approves and can trigger executor processing.
6. `/api/governance/decisions/{decision_id}/deny` rejects the decision and updates related pending commands to `rejected`.
7. `backend/services/governance_executor.py` releases approved work to command queues or executes supported domain operations.
8. Audit/world-event hooks record execution outcomes where configured.

Static guardrails live in `backend/scripts/governance_guardrails.py` and check for:

- scoped mutating endpoints missing write/admin/machine-token dependencies,
- dangerous shell execution patterns,
- direct command queue writes outside the governed dispatch helper.

## AI, Cognition, and World Model

The platform includes several AI-agent defense and reasoning layers:

- `backend/services/cce_worker.py` polls recent CLI command events, groups them by host/session, invokes `CognitionEngine`, stores session summaries, and can emit world events.
- `backend/services/aatl.py` and `backend/services/aatr.py` initialize the autonomous-agent threat layer and registry.
- `backend/services/world_model.py` and world events maintain graph-like operational state.
- `backend/services/triune_orchestrator.py` runs the current Triune reasoning flow:
  - build world snapshot,
  - add cognition fabric signals,
  - Metatron assesses,
  - Michael plans,
  - Loki challenges.

## Unified Endpoint Agent

The endpoint agent is implemented in `unified_agent/core/agent.py`.

Current facts:

- Agent version constant: `2.0.0`
- Supports cross-platform operation paths for Windows, macOS, Linux, and constrained mobile-style Python environments.
- Contains monitors for process, network, registry, DNS, DLP/EDM, vulnerability, AMSI, firewall, ransomware, rootkit, kernel, self-protection, identity, CLI telemetry, email protection, mobile security, and related surfaces.
- Reports to the backend through `/api/unified/...`.
- Backend telemetry processing can summarize monitors, project agent trust into the world model, emit world events, and trigger Triune reasoning when threat totals justify it.

The separate local portal/API in `unified_agent/server_api.py` can run as an end-user agent dashboard and proxy selected backend data through `BACKEND_URL` (default `http://localhost:8001`).

## Frontend

The operator UI is in `frontend/`.

Current structure:

- React Router entry point: `frontend/src/App.js`
- Auth shell: `frontend/src/context/AuthContext.jsx`
- Protected navigation layout: `frontend/src/components/Layout.jsx`
- Default authenticated route redirects `/` to `/command`
- Legacy routes such as `/agents`, `/agent-commands`, `/swarm`, `/email-protection`, and `/mdm` redirect into consolidated workspaces.

Main workspaces include:

- Command
- World View
- AI Activity
- Investigation
- Response Operations
- Unified Agent
- Email Security
- Endpoint Mobility
- Detection Engineering
- Platform pages for identity, zero trust, VPN, CSPM, containers, browser isolation, and more

The layout resolves the external "Agent UI" link to the current host on port `5000`.

## Integrations and Conditional Features

Many feature modules are implemented as frameworks that need live configuration to provide production value.

Examples:

| Area | Code exists | Production dependency |
|---|---|---|
| Email protection/gateway | `backend/email_protection.py`, `backend/email_gateway.py` | SMTP/DNS/reputation configuration and relay deployment. |
| MDM connectors | `backend/mdm_connectors.py` | Intune, JAMF, Workspace ONE, or Google Workspace credentials. |
| CSPM | `backend/cspm_engine.py` | Cloud provider credentials and account scope. |
| Kernel/security sensors | secure boot and kernel sensor modules | Host OS support, privileges, mounted devices/logs. |
| Sandbox/scanners/SIEM | sandbox, Trivy, Falco, Suricata, Zeek, osquery, SIEM services | External services, binaries, sockets, or log mounts. |
| Model-assisted analysis | AI/cognition services | Configured local or remote model services. |

Documentation should distinguish:

- `REAL`: active code path wired into normal runtime,
- `FRAMEWORK`: substantial implementation requiring external configuration,
- `PARTIAL`: narrower implementation than the product label may imply.

## Local Development

### Backend

Install Python dependencies from the relevant requirements file for your environment, then run the backend from the repository root:

```bash
python3 -m pip install -r requirements.txt
python3 backend/server.py
```

The backend starts on `0.0.0.0:8001` when run directly.

Useful environment variables:

| Variable | Purpose |
|---|---|
| `MONGO_URL` | MongoDB connection string. Defaults to `mongodb://localhost:27017`. |
| `DB_NAME` | Database name. Defaults to `seraph_ai_defense`. |
| `MONGO_USE_MOCK` | Enables mock MongoDB mode when supported. |
| `JWT_SECRET` | JWT signing secret. Set explicitly outside local development. |
| `INTEGRATION_API_KEY` | Required in production for internal ingestion/workers. |
| `CORS_ORIGINS` | Comma-separated allowed origins. Wildcard is rejected in production/strict mode. |
| `SERAPH_STRICT_SECURITY` | Enables stricter security checks when truthy. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME` | Optional startup admin seeding. |

### Frontend

```bash
cd frontend
yarn install
yarn start
```

Scripts from `frontend/package.json`:

- `yarn start` -> `craco start`
- `yarn build` -> `craco build`
- `yarn test` -> `craco test`

### Docker Compose

```bash
cp .env.example .env  # if present in your checkout
docker compose up -d
```

Default exposed services include:

- backend: `127.0.0.1:8001`
- frontend: `3000`
- MongoDB: `127.0.0.1:27017`
- Redis: `127.0.0.1:6379`
- WireGuard UDP: `51820`

Review `docker-compose.yml` before exposing services beyond localhost.

### Local Agent Portal

The lightweight agent portal can be run separately from the main backend:

```bash
cd unified_agent
python3 server_api.py
```

Set `BACKEND_URL` if the main backend is not at `http://localhost:8001`.

## Validation

Targeted checks available in this repository include:

```bash
python3 backend/scripts/governance_guardrails.py
```

```bash
pytest -q backend/tests
```

```bash
python3 -m pytest -q unified_agent/tests/test_monitor_scan_regression.py unified_agent/tests/test_canonical_ui_contract.py
```

```bash
cd frontend
yarn test
```

CI evidence:

- `.github/workflows/contract-assurance.yml` runs governance guardrails and selected backend contract/durability tests.
- Unified-agent monitor regression workflow runs targeted monitor tests when agent code changes.

## Documentation

Major current review documents live in `memory/`:

- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/SERAPH_BOARD_BRIEF_2026.md`
- `memory/SERAPH_IMPLEMENTATION_ROADMAP_2026.md`

These documents have been rebaselined to current code logic and avoid stale implementation percentages. Use them as the current summary layer for architecture, feature reality, security posture, board-level direction, and roadmap focus.

## Engineering Priorities

The codebase already has broad feature coverage. The highest-value work is convergence:

1. Keep frontend, scripts, tests, and backend route contracts synchronized.
2. Keep every high-impact command inside governed dispatch.
3. Expand denial-path and restart/scale tests for governance and executor flows.
4. Add explicit `connected`, `degraded`, `unavailable`, and `not_configured` runtime states for optional integrations.
5. Continue simplifying backend startup lifecycle boundaries.
6. Keep README and `memory/` review docs tied to active file paths and test evidence.

