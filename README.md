# Metatron / Seraph Security Platform

Code-first security platform combining endpoint telemetry, threat operations, governance-controlled response, and multi-domain security services.

---

## Table of Contents

- [Repository Overview](#repository-overview)
- [Current Architecture](#current-architecture)
- [Core Security Domains](#core-security-domains)
- [Unified Agent](#unified-agent)
- [Security Controls and Hardening](#security-controls-and-hardening)
- [Runtime and Deployment](#runtime-and-deployment)
- [Frontend Workspaces](#frontend-workspaces)
- [Testing and Validation](#testing-and-validation)
- [Developer Quick Start](#developer-quick-start)
- [Documentation Map](#documentation-map)
- [Known Constraints](#known-constraints)

---

## Repository Overview

This repository contains:

- A **FastAPI backend** (`backend/`) with broad router and service coverage.
- A **React frontend** (`frontend/`) using protected workspace-style routes.
- A **cross-platform unified endpoint agent** (`unified_agent/`) with many monitor modules.
- **Compose-based runtime** (`docker-compose.yml`) with datastore, backend, frontend, analytics, and security tool services.
- Extensive **tests and validation scripts** (`backend/tests`, `backend/scripts`, root test scripts).

Primary backend entrypoint:

- `backend/server.py`

Primary frontend entrypoint:

- `frontend/src/App.js`

Primary agent core:

- `unified_agent/core/agent.py`

---

## Current Architecture

## Backend composition

- `backend/server.py` wires routers through `app.include_router(...)`.
- The code currently contains **65 router registrations** in `server.py` (including compatibility and multi-prefix registrations).
- Major route groups include:
  - `/api/*` (main application surface)
  - `/api/v1/cspm/*`
  - `/api/v1/identity/*`
  - websocket channels at `/ws/threats` and `/ws/agent/{agent_id}`

## Frontend composition

- Uses `react-router-dom` with `ProtectedRoute` gating.
- Currently has **65 route entries** in `frontend/src/App.js`.
- Routing is workspace-oriented with redirect aliases (for command, investigation, response operations, email security, endpoint mobility, and more).

## Runtime topology

Defined in `docker-compose.yml`, including:

- MongoDB
- Redis
- Backend API
- Frontend UI
- Celery worker
- Celery beat
- Elasticsearch
- Kibana
- Ollama
- Trivy
- Falco
- Suricata
- WireGuard
- Additional helper/observability containers

---

## Core Security Domains

This section describes **implemented code domains** and where they live.

## 1) Unified agent control plane

- Router: `backend/routers/unified_agent.py`
- Service patterns: telemetry ingestion, registration/heartbeat, command pathways, dataset/rollout endpoints, event/audit hooks.

## 2) Endpoint telemetry and detection

- Agent core: `unified_agent/core/agent.py`
- Includes monitors for endpoint process/network/registry, threat behavior, DLP/EDM, kernel, identity-related signals, and email/mobile local telemetry.

## 3) Email security

- Email protection:
  - `backend/email_protection.py`
  - `backend/routers/email_protection.py`
- Email gateway:
  - `backend/email_gateway.py`
  - `backend/routers/email_gateway.py`

## 4) Mobile and MDM

- Mobile security:
  - `backend/mobile_security.py`
  - `backend/routers/mobile_security.py`
- MDM connectors:
  - `backend/mdm_connectors.py`
  - `backend/routers/mdm_connectors.py`

## 5) CSPM and identity

- CSPM:
  - `backend/cspm_engine.py`
  - `backend/routers/cspm.py`
- Identity:
  - `backend/identity_protection.py`
  - `backend/routers/identity.py`

## 6) Response, SOAR, and governance execution

- Response and quarantine:
  - `backend/threat_response.py`
  - `backend/quarantine.py`
- SOAR and related operations:
  - `backend/soar_engine.py`
  - `backend/routers/soar.py`
- Governance approval-to-execution:
  - `backend/services/governance_executor.py`

---

## Unified Agent

Agent core file:

- `unified_agent/core/agent.py`

The monitor map initialization currently includes keys such as:

- `process`, `network`, `registry`, `process_tree`, `lolbin`, `code_signing`, `dns`
- `memory`, `whitelist`, `dlp`, `vulnerability`, `yara`, optional `amsi`
- `ransomware`, `rootkit`, `kernel_security`, `self_protection`, `identity`
- `auto_throttle`, `firewall`, optional `webview2`
- `cli_telemetry`, `hidden_file`, `alias_rename`, `priv_escalation`
- `email_protection`, `mobile_security`

Current monitor key count in initialization map: **30** (with some platform/feature conditional entries).

---

## Security Controls and Hardening

Core security dependencies and guards are implemented in:

- `backend/routers/dependencies.py`
- `backend/server.py`

Key behaviors:

- JWT secret validation with strict behavior in production/strict mode.
- Role-based permission checks (`check_permission`).
- Remote-admin restriction for non-local requests (configurable via env).
- Machine-token support for service/ingest channels.
- Websocket machine-token check on `/ws/agent/{agent_id}`.
- CORS wildcard rejection in production/strict mode.

Environment-specific enforcement inputs include:

- `ENVIRONMENT`
- `SERAPH_STRICT_SECURITY`
- `JWT_SECRET`
- `CORS_ORIGINS`
- `REMOTE_ADMIN_ONLY`
- `REMOTE_ADMIN_EMAILS`
- `INTEGRATION_API_KEY`

---

## Runtime and Deployment

## Docker setup

Main deployment file:

- `docker-compose.yml`

Backend image:

- `backend/Dockerfile`

Deployment guide:

- `DEPLOYMENT.md`

## Backend startup behavior

From `backend/server.py`, startup currently attempts to initialize:

- admin bootstrap (env-driven)
- CCE worker
- network discovery
- deployment service
- AATL and AATR initialization
- Falco alert persistence hook
- integrations scheduler
- governance executor

## Health endpoint

- `GET /api/health`

---

## Frontend Workspaces

Frontend routing is centralized in `frontend/src/App.js` and uses both direct pages and workspace redirects.

Major workspace-oriented paths include:

- `/command`
- `/ai-activity`
- `/investigation`
- `/response-operations`
- `/detection-engineering`
- `/email-security`
- `/endpoint-mobility`
- `/unified-agent`
- `/world`

This allows legacy/feature routes to map into consolidated operations views.

---

## Testing and Validation

## Backend tests

- Location: `backend/tests/`
- Current test file count: **63** `test_*.py` files.

## Backend script validations

- Location: `backend/scripts/`
- Includes:
  - `integration_runtime_full_smoke.py`
  - `full_stack_e2e_validate.py`
  - `e2e_threat_pipeline_test.py`
  - `e2e_endpoint_sweep.py`
  - `governance_guardrails.py`
  - `mitre_coverage_evidence_report.py`

## Root-level tests/utilities

- `smoke_test.py`
- `full_feature_test.py`

---

## Developer Quick Start

## 1) Start stack

```bash
docker compose up -d --build
```

## 2) Verify backend health

```bash
curl http://localhost:8001/api/health
```

## 3) Run smoke test

```bash
python3 smoke_test.py
```

## 4) Run full feature test (optional deeper pass)

```bash
python3 full_feature_test.py
```

## 5) Run backend test suite (example)

```bash
pytest backend/tests -q
```

---

## Documentation Map

Key docs:

- `SYSTEM_FUNCTIONALITY.md`
- `DEPLOYMENT.md`
- `ATTACK_COVERAGE_BACKLOG.md`
- `docs/` (feature and integration docs)
- `memory/` (engineering review and architecture memory artifacts)
- `test_reports/` (validation/evidence summaries)

Updated current-state memory review docs:

- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`

---

## Known Constraints

1. **Environment-dependent integrations**  
   Some implemented domains (SMTP relay behavior, MDM vendor connectivity, cloud scan depth) depend on external credentials and integration setup.

2. **Large API and compatibility surface**  
   High route volume and compatibility aliases increase maintenance and contract-consistency pressure.

3. **Mixed in-memory and persistent state patterns**  
   Several workflows combine DB persistence with in-memory coordination, requiring careful restart/scale validation.

4. **Operational hardening requires disciplined config**  
   Production safety depends on strict env configuration (JWT/CORS/tokens/admin controls).

---

## License / Usage

Refer to repository governance and organizational policy for deployment and usage constraints in production environments.

