# Metatron / Seraph AI Defense Platform

This repository contains a modular cybersecurity platform with:

- A FastAPI backend (`backend/`)
- A React frontend (`frontend/`)
- A large cross-platform endpoint agent (`unified_agent/`)
- Operational and architecture review artifacts (`memory/`, `docs/`)

This README is an **Apr 2026 code-accurate baseline** focused on real repository behavior.

## Current Code Snapshot (Apr 2026)

- Backend router modules: **61** (`backend/routers/*.py`, excluding `__init__.py`)
- Routers registered in app: **65** (`app.include_router(...)` in `backend/server.py`)
- Backend service modules: **32** (`backend/services/*.py`, excluding `__init__.py`)
- Frontend page components: **68** (`frontend/src/pages/*.jsx`)
- Unified agent core: **17,317 LOC** (`unified_agent/core/agent.py`)
- Unified agent monitor keys initialized: **27** (OS-conditional for some monitors)
- Docker Compose services: **21** (`docker-compose.yml`)

## Architecture Overview

### Backend

- Entrypoint: `backend/server.py`
- Framework: FastAPI + MongoDB (Motor)
- Auth/permissions: `backend/routers/dependencies.py`
- Router style:
  - Most routes mount under `/api/<prefix>`
  - Some routers carry explicit versioned prefixes (for example `/api/v1/cspm`, `/api/v1/identity`)

Examples of major backend domains:

- Threats/alerts/timeline/response
- Unified agent control and telemetry
- Zero trust and governance
- Identity protection
- CSPM
- Email protection and email gateway
- Mobile security and MDM connectors
- Sandbox, containers, SIEM/Kibana/Loki-style integrations

### Unified Agent

- Core file: `unified_agent/core/agent.py`
- Responsibilities:
  - Endpoint monitoring
  - Telemetry collection and heartbeat
  - Local response/remediation hooks
  - Local UI/API helpers for endpoint-side control
- Monitor registration is mostly centralized in `UnifiedAgent.__init__`.

### Frontend

- Location: `frontend/`
- Build/runtime: React app with CRACO
- High surface area SOC UI under `frontend/src/pages/`

## Runtime Profiles and Services

Primary compose file: `docker-compose.yml`

### Core runtime (minimum practical stack)

```bash
docker compose up -d mongodb backend frontend
```

### Recommended local full stack

```bash
docker compose up -d mongodb backend frontend wireguard elasticsearch kibana ollama
```

### Optional profiles

- `--profile security`: trivy/falco/suricata/zeek/volatility and related tooling
- `--profile sandbox`: cuckoo stack
- `--profile bootstrap`: one-shot bootstrap helpers

## Health and Quick Validation

Backend direct health:

```bash
curl -fsS http://localhost:8001/api/health
```

Frontend direct health:

```bash
curl -fsS http://localhost:3000
```

If nginx reverse proxy is enabled:

```bash
curl -kfsS https://localhost/api/health
```

## Security and Control Notes

- `backend/server.py` enforces stricter CORS behavior in prod/strict mode.
- Production environments are expected to provide integration/auth secrets through environment variables.
- CSPM scan start is authenticated, and some high-impact CSPM/provider mutations are triune-gated in current code.
- Many integrations are operationally real but become fully effective only with production credentials (SMTP, MDM tenants, cloud providers, SIEM endpoints, etc.).

## Key Repository Paths

- `backend/server.py` - app composition and startup orchestration
- `backend/routers/` - API surface
- `backend/services/` - service-layer logic
- `unified_agent/core/agent.py` - endpoint agent core
- `frontend/src/pages/` - UI pages
- `docker-compose.yml` - local orchestration
- `memory/` - architecture/reality review documents

## Memory / Review Documents (Updated)

Major documents refreshed with Apr 2026 code-aligned summaries:

- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/RUN_MODE_CONTRACT.md`

These documents now include a revalidation layer with current counts, corrected health/run-mode guidance, and endpoint-level contract updates.
