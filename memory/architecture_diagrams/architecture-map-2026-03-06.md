# Metatron / Seraph Architecture Map

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


## 1) System Topology

Seraph is organized as a central FastAPI control plane, a React SOC console, a MongoDB-backed data layer, and a separate unified endpoint-agent tree.

- **Frontend:** `frontend/`, a Create React App + Craco single-page app served locally on port `3000` or from the production Nginx image.
- **Backend:** `backend/server.py`, a FastAPI application served on port `8001` by `uvicorn backend.server:app`.
- **Database:** MongoDB at `seraph_ai_defense` by default; Redis is available for Celery broker/result workflows.
- **Unified agent:** `unified_agent/core/agent.py` plus local dashboards, mobile/desktop shells, integration runners, and tests.
- **Optional runtime services:** WireGuard, Elasticsearch, Kibana, Ollama, Trivy, Falco, Suricata, and Cuckoo.

## 2) Backend Composition

`backend/server.py` is the composition root. It configures CORS, validates `INTEGRATION_API_KEY` in production, creates the FastAPI app, wires databases into domain modules, registers routers, and exposes health and WebSocket entry points.

Primary router families include core platform, threat operations, response and containment, endpoint/agent plane, enterprise posture, AI/governance/world model, and expansion domains such as email protection, email gateway, mobile security, MDM connectors, secure boot, kernel sensors, and attack paths.

Most routers are mounted with `prefix="/api"`; CSPM, identity, attack-path, secure-boot, and kernel-sensor routers carry `/api/v1` prefixes themselves.

## 3) Frontend Composition

`frontend/src/App.js` defines the current route contract. The authenticated landing page is `/command`, not a standalone `/dashboard` page. Older routes such as `/dashboard`, `/alerts`, `/threats`, `/agents`, `/swarm`, `/soar`, and `/email-gateway` redirect into consolidated workspaces where appropriate.

Important active workspaces: `/command`, `/investigation`, `/response-operations`, `/detection-engineering`, `/email-security`, `/endpoint-mobility`, `/unified-agent`, `/ai-activity`, and `/world`.

## 4) Service Layer

The service layer contains governance/control modules (`governance_*`, `governed_dispatch`, `policy_engine`, `token_broker`, `tool_gateway`), cognitive/AI defense modules (`aatl`, `aatr`, `cognition_*`, `triune_orchestrator`), memory/telemetry modules (`vector_memory`, `telemetry_chain`, `world_*`, `mcp_server`), operations modules (`agent_deployment`, `network_discovery`, `siem`, `cuckoo_sandbox`), and security-domain modules (`identity`, `multi_tenant`, `quantum_security`, `vns`, `threat_hunting`, `boundary_control`).

## 5) Unified Agent and Local Surfaces

The unified agent tree contains the endpoint core, backend control plane under `/api/unified/...`, a secondary helper FastAPI server, a local Flask dashboard on port `5000`, desktop/mobile shells, and local integration runners.

## 6) Runtime Flows

Threat and SOC flow: sensors and integrations feed backend APIs, backend services enrich/correlate/persist, frontend workspaces render state, and analysts or governed automation trigger response actions with telemetry/audit follow-up.

Unified-agent flow: agents register and heartbeat, backend dispatches governed commands/config, agents return telemetry and command results, and WebSocket/REST views update operator state.

Integration flow: backend accepts direct or tool-mediated integration requests, agent-side scripts execute local tools where available, and results are normalized into threat, telemetry, or evidence workflows.

## 7) Current Architecture Risks

- `backend/server.py` remains a large central composition point.
- Docs, scripts, and tests must use port `8001` and `/api/health`.
- Some frontend files are retained as legacy or redirected surfaces; route truth comes from `frontend/src/App.js`.
- Optional integrations need explicit degraded-mode behavior.
