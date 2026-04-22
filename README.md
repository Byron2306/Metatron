# Metatron / Seraph AI Defense System

Enterprise-oriented cybersecurity platform with:

- FastAPI backend control planes
- Unified endpoint agent runtime
- Security orchestration and governance workflows
- Optional security sensor and sandbox integrations

This README is a **current-state, code-aligned** overview.

---

## Table of Contents

1. [What This Repository Contains](#what-this-repository-contains)
2. [Architecture Overview](#architecture-overview)
3. [Core Runtime and Service Topology](#core-runtime-and-service-topology)
4. [Backend API Surface](#backend-api-surface)
5. [Unified Agent](#unified-agent)
6. [Security and Hardening Model](#security-and-hardening-model)
7. [Quick Start (Local)](#quick-start-local)
8. [Production-Style Deployment](#production-style-deployment)
9. [Configuration Essentials](#configuration-essentials)
10. [Validation and Health Checks](#validation-and-health-checks)
11. [Testing](#testing)
12. [Repository Map](#repository-map)
13. [Known Integration Dependencies](#known-integration-dependencies)

---

## What This Repository Contains

This project combines:

- A large modular backend (`backend/`) with dozens of routers and domain services
- A cross-platform unified endpoint agent (`unified_agent/`)
- A React frontend dashboard (`frontend/`)
- Docker Compose topologies for local and production-style runs
- Security feature domains including:
  - threat/alert/timeline workflows
  - unified endpoint telemetry and control
  - CSPM
  - identity protection
  - SOAR/orchestration
  - governance decision routing
  - email protection and email gateway
  - mobile security and MDM connectors

---

## Architecture Overview

### High-level components

- **Backend API**: FastAPI app (`backend/server.py`)
- **Frontend**: React app served by Nginx container (`frontend/`)
- **Datastores**:
  - MongoDB (primary persistence)
  - Redis (Celery broker/result backend)
- **Background workers**:
  - Celery worker and beat
  - startup-triggered background services in backend
- **Optional integrations**:
  - Elasticsearch/Kibana
  - Ollama
  - WireGuard
  - Trivy/Falco/Suricata/Zeek/Volatility
  - Cuckoo sandbox profile

### Runtime composition notes

- API routing is modular by domain but assembled centrally in `backend/server.py`.
- Some router paths are `/api/*`; others are versioned (`/api/v1/*`) by router design.
- Governance and event-emission patterns are integrated in high-impact flows.

---

## Core Runtime and Service Topology

Defined primarily in:

- `docker-compose.yml`
- `docker-compose.prod.yml`

### Core required services

- `mongodb`
- `redis`
- `backend`
- `frontend`

### Common optional services

- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`
- `nginx` (used for ingress in production-style topology)

### Profile-gated services

- `security` profile: `trivy`, `falco`, `suricata`, `zeek`, `volatility`
- `sandbox` profile: `cuckoo`, `cuckoo-web`, `cuckoo-mongo`

---

## Backend API Surface

The backend is broad and modular:

- Router modules: `backend/routers/*.py`
- Main app and includes: `backend/server.py`

Current codebase indicators:

- 60+ router modules
- 65 router include mounts in `server.py`
- Large endpoint surface (hundreds of route handlers)

### Representative domain routers

- Auth/users: `routers/auth.py`
- Threats/alerts/timeline: `routers/threats.py`, `routers/alerts.py`, `routers/timeline.py`
- Unified agent: `routers/unified_agent.py`
- Swarm operations: `routers/swarm.py`
- CSPM: `routers/cspm.py`
- Identity: `routers/identity.py`
- Governance: `routers/governance.py`
- Enterprise controls: `routers/enterprise.py`
- Advanced controls: `routers/advanced.py`
- Email/mobile/MDM:
  - `routers/email_protection.py`
  - `routers/email_gateway.py`
  - `routers/mobile_security.py`
  - `routers/mdm_connectors.py`

---

## Unified Agent

Primary files:

- `unified_agent/core/agent.py`
- Backend integration: `backend/routers/unified_agent.py`

### Key behaviors

- Agent registration and authenticated heartbeat
- Telemetry and monitor summaries in heartbeat payloads
- Command lifecycle (queue, dispatch, result ingestion)
- EDM-related dataset and rollout integration with backend
- Optional WebSocket control channels

### Monitor breadth

Agent runtime initializes a large monitor set including process/network/registry/DLP/YARA/ransomware/rootkit/kernel/self-protection/firewall/CLI telemetry/email/mobile and others, with platform-conditional monitors for Windows-specific paths.

---

## Security and Hardening Model

Primary references:

- `backend/routers/dependencies.py`
- `backend/server.py`

### Built-in controls

- JWT secret resolution with strict/prod enforcement
- Role/permission checks via reusable dependencies
- CORS strict validation in strict/prod mode
- Remote admin-only gate behavior for non-local requests
- Machine-token helper dependencies for internal/API ingest paths

### Important operational reality

Hardening quality depends on correct environment configuration (secrets, tokens, origins, production flags). Configure these explicitly before production use.

---

## Quick Start (Local)

### Prerequisites

- Docker + Docker Compose v2

### Start core stack

```bash
docker compose up -d mongodb redis backend frontend
```

### Start recommended local full stack

```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana ollama wireguard
```

### Access

- Frontend: `http://localhost:3000`
- Backend health: `http://localhost:8001/api/health`
- API root: `http://localhost:8001/api/`

---

## Production-Style Deployment

Use production override:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Notes:

- Production override reduces direct host exposure for internal services.
- Backend strict mode flags are enabled by default in prod override.
- Nginx is expected as ingress path in production-style layout.

---

## Configuration Essentials

Set these in your environment (compose `.env` or deployment secrets):

- `JWT_SECRET` (strong secret; required in strict/prod)
- `ENVIRONMENT` (`production` for prod behavior)
- `SERAPH_STRICT_SECURITY` (`true` recommended for prod)
- `CORS_ORIGINS` (explicit origins in prod)
- `REMOTE_ADMIN_ONLY` (defaults to true)

Common integration settings:

- `INTEGRATION_API_KEY`
- `SWARM_AGENT_TOKEN`
- `IDENTITY_INGEST_TOKEN`
- `ADVANCED_INGEST_TOKEN`
- `ENTERPRISE_MACHINE_TOKEN`

Optional domain settings (as needed):

- CSPM provider credentials
- MDM provider credentials
- SMTP/mail infrastructure variables
- Ollama URL/model variables

---

## Validation and Health Checks

### Service status

```bash
docker compose ps
```

### Backend health

```bash
curl -fsS http://localhost:8001/api/health
```

### Frontend reachability

```bash
curl -fsS http://localhost:3000
```

### Core workflow smoke checks

Validate:

1. Auth login/setup flow
2. Threats and alerts list loads
3. Unified agents endpoint responds
4. At least one optional domain endpoint behaves as expected for enabled integrations

---

## Testing

Repository includes multiple test suites and scripts, including backend tests and top-level integration-style scripts.

Examples at repo root:

- `backend_test.py`
- `full_feature_test.py`
- `smoke_test.py`
- `e2e_system_test.py`

Backend tests are also under `backend/tests/`.

Run tests according to your active runtime and dependencies (core-only vs full integration profiles).

---

## Repository Map

- `backend/` - FastAPI app, routers, services, domain engines
- `frontend/` - React frontend
- `unified_agent/` - endpoint agent runtime and integrations
- `memory/` - internal review/evaluation docs
- `docs/` - architecture/feature and design docs
- `test_reports/` - generated report artifacts
- `docker-compose.yml` - primary compose topology
- `docker-compose.prod.yml` - production override

---

## Known Integration Dependencies

Some domains are fully implemented in code but depend on live external systems for full operational depth:

- CSPM cloud providers
- MDM providers
- SMTP/mail-routing topology
- Optional SIEM and model backends

Interpret status accordingly:

- Code-complete does not always mean externally integrated in every environment.

---

## License / Usage

Follow your organization or repository licensing/policy guidance for deployment and operation.

