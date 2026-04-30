# Metatron / Seraph AI Defense Platform

Metatron / Seraph is a broad cybersecurity operations platform for AI-assisted defense, endpoint telemetry, SOC workflows, response automation, email security, mobile/MDM operations, cloud posture, identity, deception, and governance.

This README reflects the current repository code map as of **2026-04-30**. For deeper review artifacts, see:

- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/RUN_MODE_CONTRACT.md`
- `memory/architecture_diagrams/architecture-map-2026-03-06.md`

---

## Current Code Reality

The platform is best understood as a production-oriented security framework with many implemented domains. Some domains run directly with the local stack; others require live credentials, host privileges, cloud accounts, SMTP/MDM integrations, or optional services.

### Primary Components

| Component | Current implementation |
|---|---|
| Backend | FastAPI app in `backend/server.py`, served on port `8001`. |
| Frontend | React app in `frontend/src`, with protected routing in `frontend/src/App.js`. |
| Endpoint agent | Large Python endpoint runtime in `unified_agent/core/agent.py`. |
| Data store | MongoDB primary state store; mock Mongo support exists for selected modes. |
| Async runtime | Redis plus Celery worker/beat in Docker Compose. |
| Optional stack | Elasticsearch, Kibana, Ollama, WireGuard, Trivy, Falco, Suricata, Zeek, Cuckoo, SIEM, SMTP, MDM, and LLM integrations. |

### Verified Repository Counts

| Area | Current count |
|---|---:|
| Backend router files | 61 |
| Backend service files | 32 |
| Frontend route declarations | 68 |
| Frontend page components | 68 |
| Unified-agent lines | ~17,318 |
| Unified-agent monitor-class families | 28 |

---

## Architecture Overview

```text
Browser / SOC operator
        |
        v
React frontend (frontend/src/App.js)
        |
        v
FastAPI backend (backend/server.py)
        |
        +--> MongoDB platform state
        +--> Redis / Celery jobs
        +--> domain routers and services
        +--> websocket streams
        +--> optional external integrations
        |
        v
Unified endpoint agents (unified_agent/core/agent.py)
```

### Backend Entry Points

- API root: `GET /api/`
- Health check: `GET /api/health`
- WebSockets:
  - `/ws/threats`
  - `/ws/agent/{agent_id}`
- Primary run target: `uvicorn backend.server:app --host 0.0.0.0 --port 8001`

Most routers are included by `backend/server.py` with an outer `/api` prefix. Some routers define native `/api/v1/...` prefixes and are included directly, including CSPM, identity, attack paths, secure boot, and kernel sensors.

### Frontend Routing Model

`frontend/src/App.js` uses a protected `Layout` subtree and redirects `/` to `/command`.

Several old standalone routes now redirect into consolidated workspaces:

| Legacy route | Current workspace |
|---|---|
| `/dashboard` | `/command?tab=dashboard` |
| `/alerts` | `/command?tab=alerts` |
| `/threats` | `/command?tab=threats` |
| `/email-protection` | `/email-security?tab=protection` |
| `/email-gateway` | `/email-security?tab=gateway` |
| `/mobile-security` | `/endpoint-mobility?tab=mobile` |
| `/mdm` | `/endpoint-mobility?tab=mdm` |
| `/agents`, `/swarm`, `/agent-commands` | `/unified-agent` |

---

## Major Security Domains

| Domain | Code location | Current reality |
|---|---|---|
| SOC operations | `backend/routers/threats.py`, `alerts.py`, `dashboard.py`, `timeline.py`, `audit.py`, `reports.py` | Core API and UI surfaces exist. |
| Response and SOAR | `backend/routers/response.py`, `quarantine.py`, `soar.py`, `backend/threat_response.py` | Response surfaces exist; provider-backed actions need configured integrations. |
| Unified agent control | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Registration, heartbeat, commands, telemetry, installer/download concepts. |
| Endpoint monitoring | `unified_agent/core/agent.py` | Broad monitor families; depth depends on OS and privileges. |
| Email protection | `backend/email_protection.py`, `backend/routers/email_protection.py` | SPF/DKIM/DMARC-oriented checks, phishing, URL, attachment, impersonation, DLP, quarantine logic. |
| Email gateway | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | REST/API gateway processing, policies, block/allow lists, queues, quarantine; production SMTP relay requires MTA configuration. |
| Mobile security | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device, threat, app analysis, and compliance model. |
| MDM connectors | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Intune, JAMF, Workspace ONE, and Google Workspace connector classes; live sync/actions require credentials. |
| CSPM | `backend/cspm_engine.py`, `backend/routers/cspm.py` | Authenticated cloud posture API; cloud coverage depends on configured accounts. |
| Identity / zero trust | `backend/routers/identity.py`, `backend/routers/zero_trust.py`, services | Implemented control-plane logic with durability and scale assurance still important. |
| AI / governance | `backend/services/aatl.py`, `aatr.py`, `cce_worker.py`, `governance_executor.py`, triune routers | Framework and startup tasks exist; model-backed quality depends on optional services. |
| Deception | `backend/deception_engine.py`, `backend/routers/deception.py`, honeypot/honey-token routers | Deception surfaces exist; some paths require targeted runtime validation. |
| Browser isolation | `backend/browser_isolation.py`, router/page | URL filtering and sanitization surface exists; full remote browser isolation is not proven by current code alone. |

---

## Quick Start

### 1. Configure environment

```bash
cp .env.example .env
# edit .env for JWT_SECRET, admin setup, CORS, and integration credentials
```

Important environment variables include:

- `JWT_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_NAME`
- `CORS_ORIGINS`
- `MONGO_URL`
- `REDIS_URL`
- `INTEGRATION_API_KEY`

In production or strict mode, CORS origins must be explicit and wildcard origins are rejected.

### 2. Start the compose stack

```bash
docker compose up -d mongodb redis backend frontend
```

Recommended local full mode:

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend elasticsearch kibana ollama wireguard
```

Optional profile examples:

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

### 3. Validate health

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

The `/api/health` endpoint is a shallow application health signal. Validate domain-specific pages and APIs for the integrations you enable.

---

## Development Commands

### Backend

```bash
cd backend
python -m uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

### Frontend

```bash
cd frontend
npm install
npm start
```

### Tests

Available test suites vary by environment and optional dependencies. Common starting points:

```bash
pytest backend/tests
pytest unified_agent/tests
python3 full_feature_test.py
python3 backend/scripts/integration_runtime_full_smoke.py
```

---

## Run-Mode Contract

Required for a useful dashboard:

- `mongodb`
- `redis` when using compose/Celery-backed flows
- `backend`
- `frontend`

Optional/degraded integrations:

- WireGuard
- Elasticsearch and Kibana
- Ollama/local LLM
- Trivy, Falco, Suricata, Zeek
- Cuckoo sandbox
- SMTP/MTA gateway
- MDM platforms
- External SIEM, alerting, and cloud providers

The UI should remain usable when optional integrations are down, but related pages may show partial data, warnings, or disabled actions.

---

## Known Engineering Risks

- `backend/server.py` is a dense composition point with many imports, startup tasks, and fail-soft optional services.
- Some routers use `/api` while others use native `/api/v1` prefixes; clients and docs must be exact.
- Optional routers such as attack paths, secure boot, and kernel sensors may be skipped if imports fail.
- Email gateway, MDM, cloud, sandbox, SIEM, and model-backed workflows require real external configuration for production behavior.
- Some service-local state, queues, and governance flows need durable persistence review before clustered deployment.
- Contract tests should cover workspace redirects and backend response shapes to prevent drift.

---

## Documentation Map

| File | Purpose |
|---|---|
| `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` | Current system-wide evaluation and risk register. |
| `memory/FEATURE_REALITY_REPORT.md` | Narrative reality report by domain. |
| `memory/FEATURE_REALITY_MATRIX.md` | Matrix of PASS/PARTIAL/CONDITIONAL domains. |
| `memory/SYSTEM_CRITICAL_EVALUATION.md` | Critical architecture, security, and operations evaluation. |
| `memory/SECURITY_FEATURES_ANALYSIS.md` | Security-domain feature analysis. |
| `memory/RUN_MODE_CONTRACT.md` | Required vs optional runtime services and validation steps. |
| `memory/architecture_diagrams/architecture-map-2026-03-06.md` | Current architecture map. |
| `DEPLOYMENT.md` | Deployment-specific notes. |
| `frontend/README.md` | Frontend-specific notes. |
| `unified_agent/AGENT README.md` | Agent-specific notes. |

---

## Current Positioning

Metatron / Seraph should be described as a broad, advanced security platform codebase with many implemented frameworks and domain surfaces. The accurate claim is **strong implementation breadth with integration-dependent production depth**, not universal completion across every optional service and environment.
