# Metatron / Seraph Security Platform

Enterprise security platform combining endpoint telemetry, threat operations, governance, and advanced security services.

---

## Repository Reality (April 2026)

This README is aligned to current code in this repository (not legacy release notes).

- Backend API server: FastAPI (`backend/server.py`)
- API composition: **62 router modules**, **65 router registrations**, **~694 route decorators**
- Unified endpoint agent: `unified_agent/core/agent.py`
- Agent monitor modules instantiated: **27**
- Frontend pages: React app under `frontend/src/pages`
- Deployment stack: `docker-compose.yml` with core + optional profile services

---

## Architecture at a Glance

### 1) Backend API and control planes

The backend composes a large set of routers under `/api` and `/api/v1` roots. Key planes include:

- Core SOC: threats, alerts, timelines, reports, hunting, response, quarantine
- Unified agent control: registration, heartbeats, commands, installers, EDM governance
- Enterprise governance: identity, policy decisions, token broker, tool gateway, telemetry chain
- Advanced services: MCP, vector memory, VNS, quantum, AI, sandbox bridge
- Domain security modules: CSPM, email protection, email gateway, mobile security, MDM connectors

`backend/server.py` is the router composition source of truth.

### 2) Unified endpoint agent

The unified agent in `unified_agent/core/agent.py` includes broad host telemetry and controls:

- Process/network/registry, DNS, DLP, vulnerability, YARA, ransomware, rootkit
- Kernel security, self-protection, firewall, CLI telemetry
- Email protection and mobile security monitor modules
- Monitor snapshots and telemetry pushed back into backend unified APIs

### 3) Data and persistence

- Primary database: MongoDB
- Async driver: Motor
- Durable state machine patterns implemented in multiple critical routers (for example CSPM and identity incident transitions)

### 4) Runtime orchestration

`docker-compose.yml` supports:

- Core services: `mongodb`, `redis`, `backend`, `frontend`
- Optional and profile-gated services: security sensors/tooling, sandbox stack, bootstrap helpers
- Default bind posture is localhost for several core ports via `BIND_*` env vars

---

## Core Capability Map (Code-Accurate)

### Unified Agent + EDM Governance

Primary router: `backend/routers/unified_agent.py` (`/api/unified/*`)

Notable implemented areas:

- Agent register/heartbeat/list/detail/delete
- Command dispatch and command result loops
- Deployment queue/list/detail
- Agent download + install scripts (Linux/Windows/macOS/Android/iOS)
- EDM dataset versioning and publish
- EDM staged rollout/readiness/advance/rollback flow
- Monitor telemetry aggregation endpoints

### Email Security

- Email Protection router/service:
  - `backend/routers/email_protection.py`
  - `backend/email_protection.py`
- Email Gateway router/service:
  - `backend/routers/email_gateway.py`
  - `backend/email_gateway.py`

Implemented behavior includes authentication checks (SPF/DKIM/DMARC), URL and attachment analysis, quarantine flows, blocklist/allowlist, and policy update endpoints.

### Mobile + MDM

- Mobile Security:
  - `backend/routers/mobile_security.py`
  - `backend/mobile_security.py`
- MDM Connectors:
  - `backend/routers/mdm_connectors.py`
  - `backend/mdm_connectors.py`

Important nuance:

- MDM router and platform metadata expose Intune, JAMF, Workspace ONE, and Google Workspace entries.
- Current concrete connector classes in service implementation are Intune and JAMF; other listed platforms are not yet backed by equivalent connector classes.

### CSPM

Router: `backend/routers/cspm.py` (`/api/v1/cspm/*`)

Current behavior highlights:

- Authenticated scan start (`POST /api/v1/cspm/scan` uses `Depends(get_current_user)`)
- Durable scan and finding transition logic with state metadata
- Provider configuration/removal operations are triune-gated via outbound governance paths
- Demo-seed path exists for non-configured environments

### Identity + Governance + Enterprise control plane

- Identity router: `backend/routers/identity.py` (`/api/v1/identity/*`)
- Governance router: `backend/routers/governance.py`
- Enterprise router: `backend/routers/enterprise.py` (`/api/enterprise/*`)

Implements identity event ingestion and analytics, governance decision approval/deny flows, outbound-gated high-impact actions, and tamper-evident telemetry endpoints.

### Browser isolation

Router/service:

- `backend/routers/browser_isolation.py`
- `backend/browser_isolation.py`

Includes session management, URL analysis, sanitization, and domain blocklist flows. Full enterprise-grade remote isolation depth remains an area for further maturation.

---

## Run Modes

### Minimal core mode

Use this when you want API/UI + persistence baseline:

```bash
docker compose up -d mongodb redis backend frontend
```

### Extended local mode

Adds common local observability and AI dependencies:

```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana ollama
```

### Profile-based security tooling

```bash
docker compose --profile security up -d
```

### Profile-based sandbox tooling

```bash
docker compose --profile sandbox up -d
```

---

## Quick Start

```bash
cp .env.example .env
docker compose up -d mongodb redis backend frontend
```

Then verify:

```bash
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Optional smoke checks:

```bash
python3 smoke_test.py
```

---

## Authentication and access model

Shared auth/permissions live in `backend/routers/dependencies.py`.

Key points:

- JWT auth with strong-secret requirements in production/strict mode
- Role-based permissions (`admin`, `analyst`, `viewer`)
- Remote admin gating behavior controlled by env flags
- Machine-token dependencies available for service-to-service and ingest endpoints

---

## Deployment semantics note

Agent deployment (`backend/services/agent_deployment.py`) supports real SSH/WinRM execution paths and durable status transitions.

Simulation behavior exists but is controlled:

- Triggered when credentials are absent
- Only allowed when `ALLOW_SIMULATED_DEPLOYMENTS=true`
- Default behavior is non-simulated unless explicitly enabled

Treat simulated mode as demo/testing only.

---

## Where to read deeper

- `DEPLOYMENT.md` - deployment and operations details
- `SYSTEM_FUNCTIONALITY.md` - broad capability inventory (legacy/large; validate against code for critical claims)
- `memory/FEATURE_REALITY_REPORT.md` - updated feature reality narrative
- `memory/FEATURE_REALITY_MATRIX.md` - updated implementation matrix

---

## Documentation policy for this repo

When updating docs:

1. Prefer router/service code as source of truth over historical release notes.
2. Distinguish API surface coverage from full provider-depth implementation.
3. Mark simulation/conditional behavior explicitly.
4. Keep maturity claims tied to specific code evidence.
