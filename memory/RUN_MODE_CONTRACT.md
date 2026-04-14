# Metatron Run-Mode Contract (Source of Truth, Revalidated)

Generated: 2026-04-14  
Scope: Operational run-mode contract aligned to current `docker-compose.yml`, `backend/server.py`, and frontend API-base logic.

## Goal

Define what must be online for a healthy baseline, what can degrade safely, and how to interpret runtime status against the current implementation.

---

## 1) Required Core Services (must be up)

- `mongodb`
- `redis`
- `backend` (FastAPI on `:8001`)
- `frontend` (React/nginx on `:3000`)

If any of these are down, core UX and/or worker-backed platform behavior is not considered healthy.

---

## 2) Important Worker Plane

- `celery-worker`
- `celery-beat`

These are required for full async task execution and scheduled operations.  
The UI can load without them, but orchestration and deferred processing are degraded.

---

## 3) Optional Integrations (degraded mode if down)

Default optional services:
- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`
- `trivy` (security profile)
- `falco` (security profile)
- `suricata` (security profile)
- `zeek` (security profile)
- `volatility` (security profile)
- `cuckoo` + `cuckoo-web` + `cuckoo-mongo` (sandbox profile)

Behavior contract:
- Core SOC flows should remain functional when these are disabled/unhealthy.
- Dependent pages may show partial data, explicit warnings, or degraded status.

---

## 4) API Routing Contract

- Frontend resolves API base as:
  - `${REACT_APP_BACKEND_URL}/api` when valid/non-localhost misuse is not detected,
  - otherwise same-origin `/api`.
- Primary backend routes are mounted under `/api` plus selected routers with embedded `/api/v1/*` prefixes.
- Identity and CSPM canonical bases:
  - `/api/v1/identity/*`
  - `/api/v1/cspm/*`

---

## 5) Security Contract Baseline

- JWT authentication is required for protected user routes.
- Remote non-local requests are gated by `REMOTE_ADMIN_ONLY` logic in dependency middleware.
- Machine-token protected flows (ingest/websocket) require configured shared tokens.
- In production/strict mode:
  - missing/weak JWT secret is rejected,
  - wildcard/empty CORS origin config is rejected.

**Known accuracy constraint:**  
Some endpoints use `check_permission("admin")` even though `"admin"` is not defined as a permission token in the role map. Those endpoints are currently inaccessible until permission semantics are corrected.

---

## 6) Runtime Launch Modes

### Minimal reliable mode
```bash
docker compose up -d mongodb redis backend frontend
```

### Standard full local mode
```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend wireguard elasticsearch kibana ollama
```

### Security profile mode
```bash
docker compose --profile security up -d
```

### Sandbox profile mode
```bash
docker compose --profile sandbox up -d
```

---

## 7) Health Validation Sequence

1. `docker compose ps`
2. `curl -fsS http://127.0.0.1:8001/api/health`
3. Open frontend at `http://127.0.0.1:3000`
4. Validate login and one data-backed page from each core workspace area:
   - command/investigation,
   - response operations,
   - detection engineering,
   - unified agent.
5. If optional profiles are enabled, validate corresponding pages and expect explicit degraded behavior when dependencies are missing.

---

## 8) Acceptance Criteria for "Working"

System is considered working when:
1. Required core services are healthy.
2. Authentication works (`/api/auth/login`, `/api/auth/me`).
3. Core read/write workflows complete without fatal contract errors.
4. Optional integrations fail gracefully (no cascade failure into core routes).
5. Deployment and response status transitions represent real or explicitly simulated outcomes.

System is not fully healthy when:
- critical admin-only operations are blocked by permission-token mismatch,
- required provider credentials are absent in environments that expect live cloud/email/MDM integrations.

---

## 9) Current Risk Notes to Monitor

1. Access-control semantics consistency (`check_permission("admin")` usage).
2. Contract drift across primary backend vs adjunct legacy/compat endpoints.
3. Optional integration enablement without explicit degraded-mode operator messaging.
4. Environment/config drift across local/dev/prod profiles.

---

## 10) Changelog (2026-04-14)

- Revalidated core-service set to include Redis and Celery worker plane.
- Aligned API-base routing contract to current frontend resolver logic.
- Added strict-mode security runtime expectations from dependency/server logic.
- Documented current permission-token mismatch as a known operational constraint.
