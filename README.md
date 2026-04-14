# Metatron / Seraph AI Defense Platform

Code-revalidated overview of the current platform architecture, runtime contracts, and operational workflows.

---

## 1) What this repository contains

Metatron/Seraph is a modular security platform composed of:

- a primary FastAPI backend (`backend/`) on port `8001`,
- a React frontend (`frontend/`) on port `3000`,
- an optional Unified Agent portal/proxy API (`unified_agent/server_api.py`) on port `8002`,
- background workers (Celery + scheduler),
- optional security and sandbox integrations (profiles in compose).

The primary control-plane contract is the backend API served by `backend/server.py`.

---

## 2) Current architecture at a glance

### Core runtime planes

1. **API Plane (Backend)**
   - Entry: `backend/server.py`
   - Router mesh in `backend/routers/*`
   - Mongo-backed service state
   - Startup workers for discovery/correlation/governance/deployment

2. **UI Plane (Frontend)**
   - Entry: `frontend/src/App.js`
   - Workspace-centric routes (`/command`, `/investigation`, `/response-operations`, `/detection-engineering`, etc.)
   - API base resolved by `frontend/src/lib/api.js` and `frontend/src/context/AuthContext.jsx`

3. **Agent Plane**
   - Unified agent lifecycle/control APIs under `/api/unified/*`
   - Local monitors and telemetry in `unified_agent/core/agent.py`
   - Deployment service in `backend/services/agent_deployment.py`

4. **Async Plane**
   - `celery-worker`, `celery-beat`
   - broker/result backend via Redis

---

## 3) Backend API model

### Primary API base

- Canonical user-facing base: `/api/*`
- Additional routers with internal full prefix contracts:
  - `/api/v1/cspm/*`
  - `/api/v1/identity/*`
  - `/api/v1/attack-paths/*`
  - `/api/v1/secure-boot/*`
  - `/api/v1/kernel/*`

### Notable domain routers

- Auth and users: `/api/auth/*`, `/api/users/*`
- Unified agent: `/api/unified/*`
- Email protection: `/api/email-protection/*`
- Email gateway: `/api/email-gateway/*`
- Mobile security: `/api/mobile-security/*`
- MDM connectors: `/api/mdm/*`
- CSPM: `/api/v1/cspm/*`
- Identity: `/api/v1/identity/*`
- Governance: `/api/governance/*`
- Response/SOAR/Quarantine: `/api/threat-response/*`, `/api/soar/*`, `/api/quarantine/*`

---

## 4) Authentication and authorization

### Auth

- JWT bearer tokens
- Login/register/setup endpoints in `backend/routers/auth.py`
- Password hashing via `bcrypt` with PBKDF2 fallback

### Runtime hardening

- Weak/missing JWT secret handling is stricter in production/strict mode.
- Remote requests can be restricted with `REMOTE_ADMIN_ONLY` and `REMOTE_ADMIN_EMAILS`.
- Machine-token gates exist for selected ingest and websocket flows.

### Important current limitation

Several routes currently use `check_permission("admin")`, but the permission map in `backend/routers/dependencies.py` defines permissions (for example `write`, `manage_users`), not an `"admin"` permission literal.

Implication: those endpoints are effectively unauthorized for all roles until the permission semantic mismatch is corrected.

---

## 5) Security domains currently implemented

### Endpoint + agent operations

- agent register/heartbeat/command/control APIs
- monitor status and telemetry flows
- deployment queueing/retry/state transitions

### Email security

- SPF/DKIM/DMARC checks
- phishing/URL/attachment analysis
- quarantine and release workflows
- gateway processing, block/allow lists, and policies

### Mobile + MDM

- device lifecycle and compliance APIs
- app analysis and threat tracking
- MDM connector framework (Intune/JAMF/Workspace ONE/Google Workspace model)

### Cloud + identity

- CSPM scans/findings/providers/dashboard/export
- identity threat incidents, provider event ingest, token-abuse analytics
- identity response action queue/dispatch workflow

---

## 6) Data durability model (selected domains)

Multiple subsystems now use explicit state versioning and transition logs:

- CSPM findings/scans
- Identity incidents
- Deployment tasks/device deployment status

This enables:

- guarded transitions,
- conflict detection,
- explicit terminal-state handling,
- improved auditability.

---

## 7) Docker Compose topology

`docker-compose.yml` provides:

### Core services

- `mongodb`
- `redis`
- `backend`
- `frontend`
- `celery-worker`
- `celery-beat`

### Optional integrations/services

- `wireguard`
- `elasticsearch` + `kibana`
- `ollama` (+ optional bootstrap pull)
- security profile: `trivy`, `falco`, `suricata`, `zeek`, `volatility`
- sandbox profile: `cuckoo-mongo`, `cuckoo`, `cuckoo-web`
- edge/reverse proxy: `nginx`

---

## 8) Run modes

### Minimal reliable mode

```bash
docker compose up -d mongodb redis backend frontend
```

### Standard local mode (recommended for full app behavior)

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend wireguard elasticsearch kibana ollama
```

### Security profile

```bash
docker compose --profile security up -d
```

### Sandbox profile

```bash
docker compose --profile sandbox up -d
```

---

## 9) Quick verification checklist

1. Confirm services:
   ```bash
   docker compose ps
   ```
2. Backend health:
   ```bash
   curl -fsS http://127.0.0.1:8001/api/health
   ```
3. Frontend:
   - open `http://127.0.0.1:3000`
4. Auth sanity:
   - register/login in UI or via `/api/auth/*`
5. Core workspace sanity:
   - command workspace,
   - investigation workspace,
   - response operations,
   - detection engineering,
   - unified agent page.

If optional services are down, dependent features should degrade without crashing core flows.

---

## 10) Frontend route model (current)

Current route strategy in `frontend/src/App.js`:

- Default entry redirects to `/command`.
- Legacy paths often redirect into workspace tabs (for example:
  - `/alerts` -> `/command?tab=alerts`
  - `/threat-intel` -> `/investigation?tab=intel`
  - `/soar` -> `/response-operations?tab=soar`)
- This keeps old deep links usable while consolidating UX into workspace pages.

---

## 11) Unified Agent portal API (adjunct surface)

`unified_agent/server_api.py` is a separate FastAPI service (port `8002`) that:

- tracks local in-memory agent/alert/deployment data,
- exposes a lightweight `/portal` UI,
- proxies to backend (`/proxy/api/{path}`),
- is useful for local management patterns but not the canonical backend contract.

Treat it as adjunct/compatibility surface, not replacement for `backend/server.py`.

---

## 12) Known high-priority gaps

1. **Authorization semantic mismatch**
   - `check_permission("admin")` endpoints need correction.

2. **Integration-complete vs framework-complete distinction**
   - Some domains require live provider credentials/infrastructure to be fully operational (SMTP/MDM/cloud providers).

3. **Contract discipline**
   - Continue strengthening route/schema regression tests for high-change routers.

---

## 13) Development notes

- Backend dependencies: `backend/requirements.txt`
- Frontend dependencies: `frontend/package.json`
- Main backend startup:
  ```bash
  uvicorn backend.server:app --host 0.0.0.0 --port 8001 --reload
  ```
- Frontend dev startup:
  ```bash
  cd frontend
  yarn start
  ```

---

## 14) Summary

Metatron/Seraph is currently a broad, real, modular security platform with strong implementation depth across core SOC, endpoint, cloud, identity, email, and mobile planes.

The top corrective priority is authorization semantics consistency for admin-gated routes; after that, focus remains on integration completion and contract hardening.
