# Metatron / Seraph AI Defense Platform

A modular cybersecurity platform that combines endpoint telemetry, governed response workflows, cloud posture scanning, and SOC operations APIs.

## Current Repository Snapshot (2026-04-16)

- **FastAPI router files:** 62 (`backend/routers`)
- **Service modules:** 33 (`backend/services`)
- **Router registrations in server startup:** 65 (`backend/server.py`)
- **Frontend pages:** 69 (`frontend/src/pages`)
- **Backend test files:** 63 (`backend/tests/test_*.py`)
- **Unified agent core size:** 17,317 lines (`unified_agent/core/agent.py`)

## What the platform does

### Core control plane

- Unified agent registration, heartbeat, command delivery, and command-result ingestion.
- Governed dispatch for high-impact actions (triune approval queueing).
- Deployment orchestration with real SSH/WinRM execution paths and retry/state tracking.
- EDM dataset governance with versioning, signatures, rollout stages, readiness checks, and rollback.

### Security domains

- Threat, alerts, timeline, hunting, response, SOAR, deception, and quarantine APIs.
- Identity protection incident handling with state-transition durability.
- CSPM scanning and findings workflows for AWS/Azure/GCP.
- Email protection analysis (SPF/DKIM/DMARC, phishing, URL/attachment, DLP).
- Email gateway processing API (policy, quarantine, block/allow lists).
- Mobile device security analysis and compliance workflows.
- MDM connector management APIs (Intune and JAMF connector implementations currently active).

## Security model highlights

- JWT-based auth with strict production safeguards (`JWT_SECRET` requirements).
- Role-based permissions (`admin`, `analyst`, `viewer`) on protected routes.
- Remote admin gate (`REMOTE_ADMIN_ONLY`) to restrict non-local access.
- Machine-token authentication dependencies for internal/agent ingestion surfaces.
- CORS strictness enforcement in production/strict mode.

## Runtime architecture

Primary runtime is Docker Compose with backend + frontend + data/security dependencies.

Key services in `docker-compose.yml` include:

- backend (FastAPI)
- frontend (React)
- mongodb
- redis
- celery worker/beat
- elasticsearch + kibana
- ollama
- nginx
- wireguard
- trivy, falco, suricata, zeek, osquery (as configured)

## Quick start

### 1) Configure environment

```bash
cp .env.example .env
```

Set at minimum:

- `JWT_SECRET` (strong, >= 32 chars)
- `INTEGRATION_API_KEY` (required in production)
- `CORS_ORIGINS` (explicit origins for strict/production)
- optional admin seed values: `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME`

### 2) Start services

```bash
docker-compose up -d
```

### 3) Verify health

```bash
python3 smoke_test.py
```

Or directly:

- `GET /api/health`
- `GET /api/`

## API shape overview

Most routes are mounted under `/api/*`, with selected namespaces under `/api/v1/*`.

High-use namespaces:

- `/api/auth/*`
- `/api/unified/*`
- `/api/email-protection/*`
- `/api/email-gateway/*`
- `/api/mobile-security/*`
- `/api/mdm/*`
- `/api/v1/cspm/*`
- `/api/v1/identity/*`

## Known maturity constraints (important)

- Some security domain services use in-memory runtime state (email/mobile paths), so persistence parity is still evolving.
- MDM route metadata lists more platforms than currently instantiated connector implementations.
- Auth hardening is strong overall, but route-by-route normalization remains ongoing in some areas.

## Key docs

- `DEPLOYMENT.md` - deployment paths and environment setup
- `SYSTEM_FUNCTIONALITY.md` - broad capability map (historical + current)
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - code-evidence critical evaluation
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - rebaselined system-wide summary
- `memory/FEATURE_REALITY_REPORT.md` - practical reality narrative
- `memory/FEATURE_REALITY_MATRIX.md` - PASS/PARTIAL matrix
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security-focused capability analysis

## Development notes

- Backend entrypoint: `backend/server.py`
- Unified agent API: `backend/routers/unified_agent.py`
- Agent runtime: `unified_agent/core/agent.py`
- Tests: `backend/tests/`

Use `python3` and project tests/scripts in this repo for validation flows.
