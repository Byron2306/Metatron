# Metatron / Seraph AI Defense Platform

Code-verified documentation rebaseline (updated: 2026-04-24).

This repository contains a multi-domain security platform spanning:
- SOC workflows (threats, alerts, hunting, response, SOAR, timeline)
- endpoint telemetry and control (unified agent)
- email and mobile security
- cloud posture and advanced governance/AI services

---

## Current Implementation Snapshot (Code-Verified)

The values below come from direct source inspection in this repository:

- Backend router files (`backend/routers/*.py`): **62**
- FastAPI router definitions (`APIRouter(...)`): **65**
- Endpoint decorators (`@router.get/post/put/delete/patch`): **694**
- Frontend pages (`frontend/src/pages/*.jsx`): **68**
- Docker services in root `docker-compose.yml`: **21**

---

## What Is Implemented Today

### 1) Core SOC Platform
- Threat, alert, hunting, correlation, timeline, response, and SOAR APIs are implemented.
- Frontend workspaces route users into command, investigation, detection engineering, email security, and endpoint/mobility flows.

Primary files:
- `backend/server.py`
- `backend/routers/threats.py`
- `backend/routers/alerts.py`
- `backend/routers/hunting.py`
- `backend/routers/response.py`
- `backend/routers/soar.py`
- `frontend/src/App.js`

### 2) Unified Agent + Endpoint Monitoring
- Unified agent lifecycle and telemetry surfaces are implemented in backend routes.
- Agent core contains 27 unique monitor assignments in the runtime monitor map (plus conditional WebView2 on Windows).
- EDM governance and rollout APIs are present.

Primary files:
- `backend/routers/unified_agent.py`
- `unified_agent/core/agent.py`

### 3) Security Hardening Baseline
- Strict JWT secret handling is enforced in production/strict mode.
- CORS wildcard origins are rejected in strict/prod mode.
- Remote admin-only gate exists for non-local requests.
- CSPM scan route requires authenticated user.

Primary files:
- `backend/routers/dependencies.py`
- `backend/server.py`
- `backend/routers/cspm.py`

### 4) Email Security
#### Email Protection
- SPF/DKIM/DMARC checks
- phishing/url heuristics
- attachment and DLP analysis
- quarantine and protected-user management

Primary files:
- `backend/email_protection.py`
- `backend/routers/email_protection.py`

#### Email Gateway
- inline message parsing and threat scoring
- sender/domain/IP allow/block logic
- quarantine release/delete and policy update routes

Primary files:
- `backend/email_gateway.py`
- `backend/routers/email_gateway.py`

### 5) Mobile Security + MDM
#### Mobile Security
- device registration/status/compliance/threat/app-analysis flows are implemented.

Primary files:
- `backend/mobile_security.py`
- `backend/routers/mobile_security.py`

#### MDM Connectors (important reality note)
- Runtime connector manager currently provisions:
  - **Intune**
  - **JAMF**
- Workspace ONE and Google Workspace are referenced in enums/platform metadata but are **not currently provisioned by `MDMConnectorManager.add_connector(...)`**.

Primary files:
- `backend/mdm_connectors.py`
- `backend/routers/mdm_connectors.py`

### 6) Advanced/Governed Security Plane
- `/api/advanced/*`: MCP, vector memory, VNS, quantum, AI reasoning routes
- `/api/governance/*`: pending decisions, approve/deny, executor run-once

Primary files:
- `backend/routers/advanced.py`
- `backend/routers/governance.py`
- `backend/services/governed_dispatch.py`
- `backend/services/governance_executor.py`

---

## Known Capability Gaps (Current)

1. Email gateway allowlist is not full CRUD yet:
   - add/list exist
   - delete endpoint is not present in current router

2. MDM runtime provisioning is currently two-platform (Intune/JAMF), not four-platform.

3. Given the API surface size, contract drift remains a practical risk without strict CI contract checks.

---

## Repository Layout (High-Level)

```text
backend/
  server.py
  routers/
  services/
  scripts/

frontend/
  src/
    App.js
    pages/

unified_agent/
  core/agent.py
  ui/
  tests/

memory/
  SYSTEM_WIDE_EVALUATION_MARCH_2026.md
  SYSTEM_CRITICAL_EVALUATION.md
  FEATURE_REALITY_REPORT.md
  FEATURE_REALITY_MATRIX.md
  SECURITY_FEATURES_ANALYSIS.md
```

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3 (for local scripts/tests)

### 1) Configure environment
```bash
cp .env.example .env
```

Minimum recommended settings for safe startup:
- `JWT_SECRET` (strong value, especially for strict/prod mode)
- `CORS_ORIGINS`
- `INTEGRATION_API_KEY` (required in production)
- `REMOTE_ADMIN_ONLY` / `REMOTE_ADMIN_EMAILS` as needed

### 2) Launch core services
```bash
docker compose up -d mongodb redis backend frontend
```

### 3) Check health
```bash
curl -fsS http://localhost:8001/api/health
```

### 4) Optional full stack
```bash
docker compose up -d
```

---

## API and UI Notes

- Backend routers are mounted in `backend/server.py`.
- Most app routes are under `/api/...`; some routers are versioned at `/api/v1/...`.
- Frontend route composition and workspace redirects are in `frontend/src/App.js`.

---

## Rebaseline Documentation

The major memory-review docs were rewritten to match current code:

- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`

If you need a current-state architecture/feature summary, start with those files.
