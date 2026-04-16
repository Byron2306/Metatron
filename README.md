# Seraph / Metatron Security Platform

Code-accurate repository overview for the current implementation state.

---

## What this repository is

Seraph/Metatron is a modular cybersecurity platform with:

- FastAPI backend APIs (`backend/`)
- React frontend SOC workspaces (`frontend/`)
- Unified cross-platform endpoint agent (`unified_agent/`)
- Docker Compose runtime topology with optional security/sandbox profiles

The codebase focuses on integrated detection, investigation, response, and governance workflows.

---

## Current Architecture Snapshot

### Backend

- Entry point: `backend/server.py`
- Router includes: **65** (`app.include_router(...)` registrations)
- Mix of `/api` and explicit `/api/v1/...` route prefixes

High-signal domain routers include:

- `backend/routers/unified_agent.py` (51 handlers)
- `backend/routers/cspm.py` (18 handlers)
- `backend/routers/mobile_security.py` (17 handlers)
- `backend/routers/email_protection.py` (17 handlers)
- `backend/routers/mdm_connectors.py` (18 handlers)
- `backend/routers/email_gateway.py` (12 handlers)

### Frontend

- Main router: `frontend/src/App.js`
- Navigation layout: `frontend/src/components/Layout.jsx`
- Workspace-centric IA:
  - Command
  - AI Activity
  - Investigation
  - Response Operations
  - Detection Engineering
  - Email Security
  - Endpoint Mobility

Legacy path redirects are normalized to workspace tabs:

- `/email-protection` -> `/email-security?tab=protection`
- `/email-gateway` -> `/email-security?tab=gateway`
- `/mobile-security` -> `/endpoint-mobility?tab=mobile`
- `/mdm` -> `/endpoint-mobility?tab=mdm`

### Unified Endpoint Agent

Core: `unified_agent/core/agent.py`

The agent initializes a broad monitor set including:

- process/network/registry/process tree/LOLBin/code signing/DNS
- memory/DLP/vulnerability/YARA
- ransomware/rootkit/kernel/self-protection/identity/firewall
- CLI telemetry, hidden file, alias/rename, privilege escalation
- email protection + mobile security monitors

---

## Security Domain Coverage (Current Code Reality)

### Unified Agent + EDM

- Agent registration/heartbeat/command and telemetry APIs
- EDM dataset versioning, publish, rollback, rollout lifecycle
- Files:
  - `backend/routers/unified_agent.py`
  - `unified_agent/core/agent.py`

### Email Security

- Email Protection:
  - SPF/DKIM/DMARC checks
  - URL/attachment analysis
  - impersonation and DLP checks
  - quarantine workflows
  - `backend/email_protection.py`
  - `backend/routers/email_protection.py`

- Email Gateway:
  - message processing path
  - quarantine release/delete
  - blocklist/allowlist management
  - policy + stats APIs
  - `backend/email_gateway.py`
  - `backend/routers/email_gateway.py`

### Endpoint Mobility

- Mobile Security:
  - device lifecycle, threat/compliance, app analysis
  - `backend/mobile_security.py`
  - `backend/routers/mobile_security.py`

- MDM Connectors:
  - connector management/sync/device actions APIs
  - `backend/mdm_connectors.py`
  - `backend/routers/mdm_connectors.py`

Important implementation note:

- Concrete connector classes currently implemented:
  - `IntuneConnector`
  - `JAMFConnector`
- Platform enum also includes `workspace_one` and `google_workspace`, but concrete connector classes for those are not present in current code.

### CSPM

- Prefix: `/api/v1/cspm`
- Provider config/list/remove, scan workflows, findings/compliance/dashboard
- High-impact actions are governance-gated (`OutboundGateService`, `requires_triune=True`)
- Scan start uses authenticated dependency (`get_current_user`)
- No-provider demo fallback behavior exists
- File: `backend/routers/cspm.py`

---

## Security Controls and Hardening

Primary auth/hardening logic:

- `backend/routers/dependencies.py`
- `backend/server.py`
- `backend/routers/auth.py`

Implemented controls include:

- JWT auth and token issuance
- strict/production JWT secret quality checks
- role-based permission checks
- remote admin-only policy for non-local requests
- CORS strict-mode origin validation
- optional machine-token dependencies for internal service calls
- one-time admin setup flow (`/api/auth/setup`) with optional setup token

---

## Runtime Topology (Docker Compose)

Main file: `docker-compose.yml`

Core services:

- `mongodb`, `redis`, `backend`, `frontend`
- `celery-worker`, `celery-beat`

Additional services:

- `elasticsearch`, `kibana`, `ollama`, `ollama-pull`
- `wireguard`, `nginx`, `admin-bootstrap`

Security profile:

- `trivy`, `falco`, `suricata`, `zeek`, `volatility`

Sandbox profile:

- `cuckoo-mongo`, `cuckoo`, `cuckoo-web`

---

## Quick Start

### 1) Configure environment

Create a `.env` file (or copy from your template) with at least:

- `JWT_SECRET` (strong, 32+ chars)
- `MONGO_URL` / DB defaults if overriding
- `CORS_ORIGINS`
- optional integration credentials as needed

### 2) Start baseline stack

```bash
docker compose up -d mongodb redis backend frontend
```

### 3) Verify health

```bash
docker compose ps
curl -fsS http://127.0.0.1:8001/api/health
curl -fsS http://127.0.0.1:3000
```

### 4) Optional profiles

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
docker compose --profile bootstrap up -d
```

---

## API and Workspace Smoke Checks

After authentication, useful checks include:

- `/api/unified/agents`
- `/api/email-protection/stats`
- `/api/email-gateway/stats`
- `/api/mobile-security/stats`
- `/api/mdm/status`
- `/api/v1/cspm/dashboard`

Frontend workspaces to validate:

- `/command`
- `/email-security`
- `/endpoint-mobility`
- `/cspm`
- `/unified-agent`

---

## Repository Guide

- `backend/` - API server, routers, services
- `frontend/` - React app and pages
- `unified_agent/` - endpoint agent runtime
- `memory/` - internal review/evaluation docs
- `docker-compose.yml` - runtime topology

---

## Documentation Integrity

This README is intentionally based on current code evidence.

If you update capability docs, keep statuses explicit:

- implemented now
- implemented but integration-dependent
- planned/not yet concrete

This avoids feature inflation and keeps operators aligned with actual runtime behavior.
