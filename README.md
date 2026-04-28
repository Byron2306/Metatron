# Metatron / Seraph AI Defense Platform

Metatron/Seraph is an AI-native security platform that combines a FastAPI control plane, React SOC console, unified endpoint agent, governed response workflows, deception, identity, cloud posture, email, mobile, MDM, and optional security-tool integrations.

This README reflects the repository logic inspected on 2026-04-28.

## Current Architecture at a Glance

| Layer | Current implementation |
|---|---|
| Backend API | `backend/server.py`, FastAPI title `Anti-AI Defense System API`, version `3.0.0`, served on port `8001`. |
| Frontend | `frontend/`, Create React App + Craco, local port `3000`, routes defined in `frontend/src/App.js`. |
| Primary UI hub | Authenticated users land on `/command`; `/dashboard` redirects to `/command?tab=dashboard`. |
| Database | MongoDB database `seraph_ai_defense` by default; `mongomock` can be enabled for local/mock environments. |
| Queue/cache | Redis is included for Celery broker/result workflows. |
| Unified agent | `unified_agent/core/agent.py`, `AGENT_VERSION = "2.0.0"`; backend control plane under `/api/unified/...`. |
| Realtime | `/ws/threats` and `/ws/agent/{agent_id}`. |
| Optional services | WireGuard, Elasticsearch, Kibana, Ollama, Trivy, Falco, Suricata, Cuckoo, and related tools. |

## Source-Derived Inventory

| Component | Current count / fact |
|---|---:|
| Backend router modules | 61 plus `backend/routers/__init__.py` |
| Backend service modules | 32 plus `backend/services/__init__.py` |
| Frontend page files | 68 JSX files plus `GraphWorld.tsx` |
| Route occurrences in `App.js` | 68 `<Route` occurrences including redirects and protected structure |
| Backend tests | 63 `backend/tests/test_*.py` files |
| Unified-agent test files | 4 under `unified_agent/tests/` plus additional root-level agent tests |

## Repository Layout

```text
backend/                 FastAPI API, routers, services, engines, tests
frontend/                React/Craco SOC console
unified_agent/           Endpoint agent, local UIs, integration runners, tests
docs/                    Product and feature documentation
memory/                  Architecture, evaluation, and review documents
test_reports/            Historical validation reports
deployment/              Deployment variants such as Celery compose
nginx/                   Frontend/reverse-proxy configuration
scripts/                 Utility scripts and browser extension assets
cas_shield_sentinel_bundle/  Standalone CAS Shield sidecar bundle
```

## Backend API

The backend composition root is `backend/server.py`. It creates the FastAPI app, configures CORS from `CORS_ORIGINS`, requires `INTEGRATION_API_KEY` in production-like environments, connects to MongoDB/Motor or mock Mongo when enabled, registers the platform router mesh, exposes `GET /api/health`, and exposes WebSockets at `/ws/threats` and `/ws/agent/{agent_id}`.

Most routers are mounted under `/api`. Some route families carry native `/api/v1` prefixes inside their router definitions, including CSPM, identity, attack paths, secure boot, and kernel sensors.

Major backend domains include auth, users, dashboard, reports, audit, threats, alerts, hunting, timeline, threat intel, correlation, response, quarantine, SOAR, ransomware, deception, agents, swarm, unified agent, EDR, containers, VPN, browser isolation, sandbox, zero trust, CSPM, identity, AI analysis, AI threats, triune Metatron/Michael/Loki, governance, world ingest, email protection, email gateway, mobile security, MDM connectors, kernel sensors, and secure boot.

## Frontend Application

The frontend is a React app using Craco scripts. Routing is defined in `frontend/src/App.js` with `BrowserRouter`, `AuthProvider`, and a protected `Layout`.

Primary workspaces:

| Route | Purpose |
|---|---|
| `/command` | Main command dashboard, alert, threat, and command-center tabs. |
| `/world` | World model and graph views. |
| `/ai-activity` | AI signals, CLI sessions, and intelligence tabs. |
| `/investigation` | Threat intel, correlation, and attack-path investigation. |
| `/response-operations` | Quarantine, response automation, SOAR, and EDR workflows. |
| `/detection-engineering` | Sigma, Atomic validation, and MITRE workflows. |
| `/unified-agent` | Agent fleet and command control. |
| `/email-security` | Email protection and gateway workflows. |
| `/endpoint-mobility` | Mobile security and MDM workflows. |

Many legacy paths intentionally redirect into these workspaces for compatibility.

## Unified Agent

Important entry points:

- `unified_agent/core/agent.py` - endpoint agent core, version `2.0.0`.
- `backend/routers/unified_agent.py` - backend control plane under `/api/unified/...`.
- `unified_agent/server_api.py` - secondary helper API, defaulting to backend `http://localhost:8001`.
- `unified_agent/ui/web/app.py` - local Flask dashboard.
- `unified_agent/run_local_dashboard.sh` - launches the local web dashboard on port `5000`.
- `unified_agent/integrations/` - local runners for Zeek, YARA, Trivy, Suricata, SpiderFoot, PurpleSharp, osquery, Falco, Cuckoo, BloodHound, Arkime, and Amass.

## Run Locally with Docker Compose

```bash
cp .env.example .env
docker compose up -d mongodb redis backend frontend
```

Open:

- Frontend: `http://localhost:3000`
- Backend health: `http://localhost:8001/api/health`

Recommended local full mode:

```bash
docker compose up -d mongodb redis backend frontend wireguard elasticsearch kibana ollama
```

Optional security/sandbox profiles:

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

## Run Backend Locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.server:app --host 0.0.0.0 --port 8001
```

Useful environment variables:

| Variable | Purpose |
|---|---|
| `MONGO_URL` | MongoDB connection string. |
| `DB_NAME` | Database name, default `seraph_ai_defense`. |
| `MONGO_USE_MOCK` | Enables mock MongoDB when supported. |
| `JWT_SECRET` | JWT signing secret; must be changed for production. |
| `CORS_ORIGINS` | Explicit allowed origins. Wildcard is rejected in strict/production mode. |
| `INTEGRATION_API_KEY` | Required in production for internal ingestion/workers. |
| `REDIS_URL` | Redis URL for queue/cache workflows. |

## Run Frontend Locally

```bash
cd frontend
yarn install
yarn start
```

Frontend scripts:

```bash
yarn start
yarn build
yarn test
```

Set `REACT_APP_BACKEND_URL` when the backend is not available through same-origin `/api` routing.

## Validation

Core health checks:

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Backend tests:

```bash
python -m pytest -q backend/tests
```

Unified-agent monitor regression:

```bash
python -m pytest -q unified_agent/tests/test_monitor_scan_regression.py
```

Frontend tests:

```bash
cd frontend
yarn test
```

> Note: root `smoke_test.py` is CAS Shield sidecar code, not the Seraph full-stack smoke test. Use the health checks and targeted pytest suites above for Seraph validation.

## Optional Integration Reality

Seraph includes integration surfaces for many tools and platforms, but production value depends on deployment prerequisites:

- Email gateway needs production SMTP relay/mail-flow configuration.
- MDM connectors need Intune, JAMF, Workspace ONE, or Google Workspace credentials and webhook/sync configuration.
- CSPM needs cloud credentials and scoped permissions.
- AI-augmented analysis needs configured model services such as Ollama or external providers.
- Kernel/eBPF, secure boot, and packet/security-tool integrations depend on host OS privileges and local tooling.
- Cuckoo, ELK, WireGuard, Trivy, Falco, Suricata, Zeek, osquery, BloodHound, Arkime, SpiderFoot, and Amass should be documented as optional or environment-specific.

Core SOC operation should degrade clearly when optional services are unavailable.

## Documentation Map

- `memory/architecture_diagrams/architecture-map-2026-03-06.md` - current architecture map and runtime flows.
- `memory/RUN_MODE_CONTRACT.md` - required versus optional services and validation sequence.
- `memory/FEATURE_REALITY_MATRIX.md` - code-backed maturity matrix.
- `memory/FEATURE_REALITY_REPORT.md` - qualitative feature reality report.
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - risk and critical evaluation.
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - system-wide evaluation rebaselined to current source.
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security feature inventory and conditional gaps.

## Production Notes

Before production deployment:

1. Replace default secrets, especially `JWT_SECRET`.
2. Set explicit `CORS_ORIGINS`.
3. Set `INTEGRATION_API_KEY`.
4. Configure TLS/reverse proxy for frontend and API access.
5. Validate optional integrations and credentials per enabled feature.
6. Run backend, frontend, and unified-agent regression tests relevant to the deployment profile.
7. Confirm high-risk response actions produce audit evidence and verifiable outcomes.

## License

No license file was reviewed as part of this documentation update. Add or update repository licensing information before external distribution.
