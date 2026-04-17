# Metatron / Seraph AI Defense Platform

Current-state repository guide (updated from live code paths).

## What this repository is

Metatron/Seraph is a full-stack cybersecurity platform composed of:

- A large FastAPI backend (`/backend`)
- A React frontend SOC workspace (`/frontend`)
- A cross-platform unified endpoint agent (`/unified_agent`)
- Operational documents and audits (`/memory`, `/docs`, root markdowns)

This README intentionally favors **accurate implementation reality** over historical roadmap claims.

---

## Current architecture at a glance

### Backend (`backend/`)

- App entrypoint: `backend/server.py`
- Router modules: `backend/routers/*.py`
- Service modules: `backend/services/*.py`

Current codebase metrics (from repository scan):

- ~65 router modules in `backend/routers`
- ~65 `include_router(...)` registrations in `server.py`
- ~694 route decorators across router files

The backend includes domains for:

- Auth and user management
- Threats/alerts/timeline/audit/reports
- Unified agent lifecycle and command/control
- EDM dataset governance and rollout APIs
- Email protection + email gateway
- Mobile security + MDM connectors
- CSPM and cloud findings lifecycle
- Deception, SOAR, ransomware, zero trust, identity, and more

### Frontend (`frontend/`)

- Route entrypoint: `frontend/src/App.js`
- Main shell/navigation: `frontend/src/components/Layout.jsx`

Current route architecture is **workspace-centric**, not only page-centric:

- `/command`
- `/investigation`
- `/response-operations`
- `/email-security`
- `/endpoint-mobility`

These consolidate multiple older pages into operator workflows.

### Unified Agent (`unified_agent/`)

- Endpoint runtime: `unified_agent/core/agent.py`
- Local UI and desktop/web utilities under `unified_agent/ui`

Current runtime model includes:

- Agent register/heartbeat/control command loop
- Platform-conditional monitor set (27 configured monitor keys)
- 21 `*Monitor` class implementations in code
- EDM loop-back telemetry and runtime dataset update handling

### Deployment/Runtime stack

Primary compose file: `docker-compose.yml`

Core services include:

- `backend` (FastAPI, port 8001)
- `frontend` (served UI, port 3000)
- `mongodb`
- `redis`
- Optional/auxiliary services (e.g., Elasticsearch, Kibana, Ollama, Trivy, Falco, Suricata, Zeek, WireGuard, Cuckoo)

---

## Security and control-plane highlights (current)

- JWT and permission dependencies are in `backend/routers/dependencies.py`
- Production/strict-mode JWT and CORS behavior is explicitly enforced
- CSPM scan endpoint is authenticated (`backend/routers/cspm.py`)
- CSPM provider configure/remove paths are approval-gated
- Unified agent APIs include registration, heartbeat, command, deployment, and EDM lifecycle

---

## Important implementation nuances

These are common sources of misunderstanding in older documents:

1. **MDM platform contract vs manager instantiation**
   - API/UI advertise Intune, JAMF, Workspace ONE, and Google Workspace.
   - Current manager add path in `backend/mdm_connectors.py` instantiates Intune and JAMF connectors.

2. **Email/mobile state durability**
   - Email gateway/protection and mobile services have broad APIs and logic.
   - Some operational state in these modules is still process-memory based.

3. **CSPM no-provider behavior**
   - CSPM is authenticated and has finding/scan lifecycle logic.
   - If no providers are configured, the scan path can return demo-seeded data for UX continuity.

---

## Repository structure

```text
/backend              FastAPI app, routers, services, security engines
/frontend             React app and SOC workspaces
/unified_agent        Endpoint runtime, monitors, local UI helpers
/memory               Internal evaluations, audits, architecture docs
/docs                 Additional product/architecture docs
/deployment           Deployment scripts/assets
/scripts              Utility and validation scripts
```

---

## Local development quick start

Prerequisites:

- Docker + Docker Compose
- Python 3 (for local scripts/tests)
- Node.js/npm (for frontend-local workflows)

### 1) Clone and configure

```bash
git clone <repo-url>
cd <repo-folder>
cp .env.example .env  # if present
```

Set at least:

- `JWT_SECRET`
- database/runtime values needed by your environment

### 2) Start stack

```bash
docker compose up -d
```

### 3) Validate health

```bash
curl http://localhost:8001/api/health
```

Then open frontend:

- http://localhost:3000

---

## Testing and verification

There are multiple test and validation files in repo root and `backend/tests` / `unified_agent/tests`.

Typical patterns:

- Backend/router tests: `backend/tests/...`
- Unified agent tests: `unified_agent/tests/...`
- End-to-end scripts/reports: `test_reports/...`, root-level `*_test.py`

Because this codebase is broad, prefer targeted test runs for changed domains first, then broader smoke/e2e passes.

---

## Operational docs

Start with:

- `DEPLOYMENT.md` (deployment runbook)
- `SYSTEM_FUNCTIONALITY.md` (capability inventory snapshot)
- `memory/FEATURE_REALITY_REPORT.md` (current reality summary)
- `memory/FEATURE_REALITY_MATRIX.md` (status matrix)
- `memory/SYSTEM_CRITICAL_EVALUATION.md` (critical posture)
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` (updated rebaseline document)

---

## Current engineering priorities (recommended)

1. Close MDM connector parity with exposed platform contract.
2. Persist key in-memory operational state in email/mobile domains.
3. Strengthen API/frontend contract tests for workspace-critical paths.
4. Gradually reduce startup coupling concentration in `backend/server.py`.

---

## License and support

Use your organization’s internal policy for licensing and support ownership.
If this repository is internal-only, treat all operational and security docs as confidential.
