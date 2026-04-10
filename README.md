# Metatron / Seraph Security Platform

Repository for a FastAPI + React security operations platform with a unified endpoint agent, multi-domain defensive APIs, and workspace-based SOC UI.

This README is intentionally concise and evidence-oriented.  
For detailed evaluations, see `memory/*.md` and `docs/*.md`.

---

## What Is In This Repo

- **Backend API** (`backend/`): FastAPI application, domain routers, orchestration services, and integrations.
- **Unified Agent** (`unified_agent/`): endpoint runtime, monitors, telemetry, and command execution loop.
- **Frontend** (`frontend/`): React dashboard and workspace routing for SOC operations.
- **Deployment** (`docker-compose*.yml`, `backend/Dockerfile`, `DEPLOYMENT.md`): local/prod container orchestration and operational guides.
- **Memory and design docs** (`memory/`, `docs/`): architecture notes, reality reviews, and roadmap artifacts.

---

## Quick Start (Docker Compose)

### Prerequisites

- Docker 20.10+
- Docker Compose 2.x
- Linux host recommended for full feature depth

### Start stack

```bash
docker-compose up -d --build
```

### Default access

- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8001`
- Health check: `http://localhost:8001/api/health`

For deployment and environment details, see `DEPLOYMENT.md` and `docker-compose.yml`.

---

## Source of Truth for System Wiring

To avoid stale docs, use these files as canonical references:

- **Backend router registration:** `backend/server.py` (`app.include_router(...)`)
- **Frontend route map:** `frontend/src/App.js`
- **Frontend navigation model:** `frontend/src/components/Layout.jsx`
- **Agent monitor/telemetry behavior:** `unified_agent/core/agent.py`

---

## Major Capability Domains (Current Code Reality)

Status legend:
- **PASS**: materially implemented and wired
- **PARTIAL**: implemented with notable prerequisites/gaps
- **LIMITED**: framework-level or incomplete runtime parity

| Domain | Status | Primary Evidence |
|---|---|---|
| Unified agent control plane | PASS | `unified_agent/core/agent.py`, `backend/routers/unified_agent.py` |
| EDM governance and telemetry | PASS/PARTIAL | `backend/routers/unified_agent.py` + heartbeat `edm_hits` in agent |
| Email protection | PASS/PARTIAL | `backend/email_protection.py`, `backend/routers/email_protection.py` |
| Email gateway management | PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` |
| Mobile security | PASS/PARTIAL | `backend/mobile_security.py`, `backend/routers/mobile_security.py` |
| MDM connectors | PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` |
| Identity protection | PASS/PARTIAL | `backend/identity_protection.py`, `backend/routers/identity.py` |
| CSPM | PASS/PARTIAL | `backend/cspm_engine.py`, `backend/routers/cspm.py` |
| Kernel/eBPF security | PARTIAL | `backend/ebpf_kernel_sensors.py`, `backend/routers/kernel_sensors.py` |
| Browser isolation | PARTIAL/LIMITED | `backend/browser_isolation.py`, `backend/routers/browser_isolation.py` |
| Zero trust | PARTIAL | `backend/zero_trust.py`, `backend/routers/zero_trust.py` |

### Important caveats

- Email gateway includes strong processing/policy APIs, but SMTP runtime completeness is integration-dependent.
- MDM manager wiring currently instantiates Intune and JAMF connectors; other platform enum values are not full parity in manager instantiation.
- Browser isolation service generates proxy URLs that are not fully mirrored by current router endpoints.
- Kernel/eBPF depth depends on host kernel, privileges, and optional dependencies.

---

## Frontend Workspaces

The UI is workspace-first, with many legacy routes redirecting into workspace tabs.

Primary workspace routes in `frontend/src/App.js` include:

- `/command` (dashboard/alerts/threats/command center)
- `/investigation` (intel/correlation/attack paths)
- `/response-operations` (EDR/SOAR/quarantine/automation)
- `/detection-engineering` (sigma/atomic/MITRE)
- `/email-security` (protection/gateway)
- `/endpoint-mobility` (mobile/mdm)
- `/unified-agent`, `/identity`, `/cspm`, `/browser-isolation`, etc.

---

## Development Notes

### Backend

Run locally from repo root:

```bash
python -m uvicorn backend.server:app --host 0.0.0.0 --port 8001
```

### Frontend

From `frontend/`:

```bash
yarn install
yarn start
```

### Python dependencies

Backend requirements are maintained in:

- `backend/requirements.txt`
- root `requirements.txt` (contains CAS shield bundle requirements and related tooling)

---

## Testing

Test and report artifacts exist in:

- `tests/`
- `test_reports/`
- root-level smoke/e2e scripts (for example `smoke_test.py`, `e2e_system_test.py`)

Recommended approach:
1. run focused tests for changed domain modules,
2. run smoke/e2e checks for integration-sensitive changes,
3. verify frontend route/API behavior for impacted workspaces.

---

## Documentation Map

- Deployment: `DEPLOYMENT.md`
- System functionality overview: `SYSTEM_FUNCTIONALITY.md`
- Architecture and feature reviews: `memory/*.md`
- Domain-specific docs and analyses: `docs/*.md`

---

## Documentation Governance

When updating capability claims, always pair the claim with:
1. file-level evidence,
2. runtime prerequisites,
3. known limitations.

This keeps README and memory artifacts aligned with implementation reality.
