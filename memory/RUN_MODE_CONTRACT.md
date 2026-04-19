# Metatron Run-Mode Contract (Code-Verified)

Generated: 2026-04-19  
Scope: Runtime expectations derived from `docker-compose.yml`, `backend/server.py`, and frontend API patterns.

---

## Goal

Define required vs optional runtime components so operators can run the platform predictably and understand degraded behavior.

---

## 1) Required Core (must be up)

- `mongodb`
- `backend`
- `frontend`

Without these, the primary platform UX and API contract are not healthy.

---

## 2) Core-Operational Additions (recommended for production-like operation)

- `redis`
- `celery-worker`
- `celery-beat`

These improve async execution and scheduled/background operations.  
Platform can start without all of them, but behavior may degrade for queued/background workflows.

---

## 3) Optional Integrations (graceful degradation expected)

- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`
- `trivy` (security profile)
- `falco` (security profile)
- `suricata` (security profile)
- `zeek` (security profile)
- `cuckoo` + `cuckoo-web` + `cuckoo-mongo` (sandbox profile)

Behavior contract:

1. Core SOC workflows should remain available when optional integrations are down.
2. Integration-specific pages/features may show warnings, partial data, or explicit unavailable states.
3. Optional failures must not cascade into auth failure or total API outage.

---

## 4) Runtime Launch Modes

### Minimal reliable mode

```bash
docker compose up -d mongodb backend frontend
```

### Recommended local full mode

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat wireguard elasticsearch kibana ollama
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

## 5) API Routing Contract

1. Main backend routes are mounted under `/api` in `backend/server.py`.
2. Selected routers are native `/api/v1/*` (e.g., CSPM, identity, secure boot, kernel sensors).
3. Frontend commonly resolves backend via `REACT_APP_BACKEND_URL` and requests `.../api/...`.
4. In reverse-proxy deployments, same-origin `/api` routing should be preferred.

---

## 6) Auth and Access Contract

From `backend/routers/dependencies.py`:

- JWT auth is mandatory for protected APIs.
- In production/strict mode, weak JWT secrets are rejected.
- Remote admin-only gating can be enforced (`REMOTE_ADMIN_ONLY=true` default).
- Role-based permission checks (`read`, `write`, `admin`, etc.) gate many mutation endpoints.

---

## 7) Health Validation Sequence

1. `docker compose ps`
2. `curl -fsS http://localhost:8001/api/health`
3. Verify frontend root (container serves on port 3000 by default compose mapping)
4. Authenticate and validate representative pages:
   - command workspace
   - unified agent
   - investigation/timeline
   - response operations
   - settings

---

## 8) Acceptance Criteria for “Working”

System is considered working when:

1. Core services are healthy.
2. Login/auth works and protected frontend routes load.
3. Critical API planes respond:
   - `/api/unified/*`
   - `/api/swarm/*`
   - `/api/threats`, `/api/alerts`, `/api/timeline*`
   - `/api/v1/cspm/*` and `/api/v1/identity/*` (with auth)
4. Optional integrations degrade gracefully if unavailable.

---

## 9) Code-Verified Reality Conditions

### 9.1 Confirmed strong contracts

- Extensive modular router composition in `backend/server.py`.
- Unified agent register/heartbeat/command/deployment surfaces.
- Email protection + email gateway + mobile security + MDM route surfaces.
- CSPM auth guard on scan entrypoint.

### 9.2 Known conditional/partial contracts

- MDM manager currently implements Intune/JAMF runtime connectors; other advertised platforms are not yet wired as connector classes.
- Some services use mixed in-memory + DB state patterns.
- Optional integrations require explicit environment/dependency setup for full behavior.

### 9.3 Risk areas to monitor

- Frontend/backend drift on high-churn routes.
- Legacy vs current endpoint overlap (`/api` vs `/api/v1` domains).
- Long-running/background job consistency across restarts.

---

## 10) Updated “Working” Interpretation

“Working” means operationally reliable core SOC and control-plane behavior with explicit degraded states, **not** full parity across every advertised integration path.
