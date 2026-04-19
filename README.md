# Metatron / Seraph AI Defense Platform

Code-verified platform overview (updated 2026-04-19).

---

## What this repository contains

Metatron/Seraph is a full-stack security platform with:

- a FastAPI backend (`backend/`)
- a React frontend (`frontend/`)
- a large cross-platform endpoint agent (`unified_agent/`)
- operational docs, memory/evaluation artifacts, and test suites.

The platform spans SOC workflows, endpoint telemetry, response orchestration, email/mobile security, CSPM, identity, and governance controls.

---

## Current architecture at a glance

### Backend

Main entrypoint: `backend/server.py`

The backend composes a large router mesh including:

- `/api/unified/*` (unified agent lifecycle, commands, EDM lifecycle, deploy flows)
- `/api/swarm/*` (swarm/orchestration controls)
- `/api/email-protection/*`
- `/api/email-gateway/*`
- `/api/mobile-security/*`
- `/api/mdm/*`
- `/api/v1/cspm/*`
- `/api/v1/identity/*`
- plus alerts, threats, timeline, SOAR, response, zero-trust, etc.

### Frontend

Main app: `frontend/src/App.js`

The UI uses an authenticated workspace model with consolidated pages and route redirects (command, investigation, response-operations, endpoint-mobility, detection-engineering, etc.) mapped to backend APIs.

### Unified Agent

Main implementation: `unified_agent/core/agent.py`

The endpoint agent includes a broad monitor fleet and sends monitor telemetry/state through heartbeat paths consumed by backend unified router surfaces.

---

## Security and control-plane highlights

- JWT auth with strict secret checks in production-like mode (`backend/routers/dependencies.py`)
- role/permission checks across write/admin routes
- CORS strict-mode enforcement in backend startup
- governance/outbound gate patterns for higher-impact actions
- websocket machine-token verification for agent channels

---

## Domain capability status (code-verified)

| Domain | Status | Notes |
|---|---|---|
| Unified agent control plane | Strong | Extensive register/heartbeat/command/deployment/EDM APIs |
| EDM + DLP governance | Strong | Dataset versioning, publish/rollback, rollout endpoints |
| Email protection | Strong | SPF/DKIM/DMARC + phishing/URL/attachment/impersonation/DLP |
| Email gateway | Strong | SMTP-style decision flow, quarantine, list/policy controls |
| Mobile security | Strong | Device, threat, compliance, app analysis APIs |
| MDM connectors | Partial | Intune + JAMF implemented; Workspace ONE + Google Workspace currently declared but not runtime connector classes |
| CSPM | Strong/Partial | Auth + DB-backed scan/finding durability, mixed with some in-memory state |
| Identity + governance | Strong/Partial | Rich controls present, continued assurance hardening ongoing |
| Zero trust / browser isolation / kernel | Partial/Strong | Wired and active, depth varies by environment and feature |

---

## Important reality note: MDM breadth

Current code behavior:

- Implemented connector classes: **Intune**, **JAMF**
- Declared (UI/metadata/enum) but not implemented as manager connector classes yet: **Workspace ONE**, **Google Workspace**

This is documented in updated files under `memory/` and should be reflected in any external positioning or release notes.

---

## Repository layout

```text
backend/                 FastAPI services, routers, domain logic, tests
frontend/                React UI, pages, workspace routing
unified_agent/           Endpoint agent runtime and integrations
memory/                  Evaluation and architecture/reality documentation
docs/                    Supporting technical docs
tests/                   Root-level and integration tests
docker-compose.yml       Main multi-service runtime stack
DEPLOYMENT.md            Deployment guide
```

---

## Running locally

### Minimal core

```bash
docker compose up -d mongodb backend frontend
```

### Recommended operational local stack

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat
```

### Optional profiles

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

---

## Basic validation checklist

1. `docker compose ps`
2. `curl -fsS http://localhost:8001/api/health`
3. Open frontend and authenticate.
4. Validate representative pages:
   - command workspace
   - unified agent
   - investigation/timeline
   - response operations
   - settings

---

## Key updated documentation

Code-verified memory docs:

- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/RUN_MODE_CONTRACT.md`
- `memory/SERAPH_COMPETITIVE_WHITEPAPER_2026.md`
- `memory/SERAPH_BOARD_BRIEF_2026.md`
- `memory/SERAPH_IMPLEMENTATION_ROADMAP_2026.md`

These are now aligned to current code behavior and should be treated as the primary internal narrative baseline.

---

## License and support

Refer to your organization policy and repository-level governance for licensing, release, and support ownership.
