# Metatron / Seraph Run-Mode Contract (Code-Validated)

**Last updated:** 2026-04-23  
**Validation basis:** `backend/server.py`, `docker-compose.yml`, `docker-compose.prod.yml`, `frontend/src/lib/api.js`, `nginx/conf.d/default.conf`

---

## 1) Purpose

This document defines what is required to call the platform "working", what can degrade safely, and which runtime contracts are enforced by code today.

---

## 2) Core Runtime Requirements

### 2.1 Minimum practical stack (local Compose)

For normal local operation through Docker Compose, the minimum practical set is:

- `mongodb`
- `redis`
- `backend`
- `frontend`

Why Redis is included: the backend container is configured with Redis/Celery settings in Compose, and background/async paths rely on that runtime.

### 2.2 Primary API/UI contracts

- Backend API listens on **port 8001** by default (`backend/server.py`).
- Health endpoint is **`GET /api/health`**.
- Frontend resolves API base to:
  - `REACT_APP_BACKEND_URL/api` if configured, or
  - same-origin `/api` fallback (`frontend/src/lib/api.js`).

### 2.3 Optional but common services

- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`

These are not required for core login/dashboard CRUD flows, but related pages and features will degrade or show reduced data when unavailable.

---

## 3) Profile-Gated Services

### Security profile

- `trivy`
- `falco`
- `suricata`
- `zeek`
- `volatility`

### Sandbox profile

- `cuckoo-mongo`
- `cuckoo`
- `cuckoo-web`

Notes:
- Cuckoo is intentionally isolated on Mongo 5 in this repo's Compose model.
- Security services can be profile-gated locally but promoted in production override.

---

## 4) Canonical Launch Modes

### 4.1 Minimal local reliability mode

```bash
docker compose up -d mongodb redis backend frontend
```

### 4.2 Recommended local full mode

```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana ollama wireguard
```

### 4.3 Security mode

```bash
docker compose --profile security up -d
```

### 4.4 Sandbox mode

```bash
docker compose --profile sandbox up -d
```

### 4.5 Production mode

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Production override expectations:
- Frontend/backend direct host ports are hidden.
- Nginx becomes ingress.
- `ENVIRONMENT=production` and strict security defaults apply.

---

## 5) Runtime Health Contract

A deployment is considered healthy when all checks below pass:

1. `docker compose ps` shows core services running.
2. Backend health returns 200:
   - local direct: `curl -fsS http://localhost:8001/api/health`
   - via ingress: `curl -fsS https://<host>/api/health`
3. Frontend root loads (port 3000 local container mapping, or ingress domain in prod).
4. Auth flow works (`/api/auth/register` or `/api/auth/login` then `/api/auth/me`).
5. At least one read workflow each for threats, alerts, agents, and settings succeeds.

---

## 6) Security Contracts Enforced by Code

### 6.1 Production boot guards

- Backend startup fails in production if `INTEGRATION_API_KEY` is missing.
- CORS wildcard is rejected in production/strict mode.
- In production/strict mode, weak/missing JWT secret fails startup (`routers/dependencies.py`).

### 6.2 Machine-token channels

- World ingest endpoints require machine tokens (`/api/ingest/*`).
- Integrations internal paths can authorize via machine token headers.
- Agent websocket in backend validates configured machine tokens.

### 6.3 Remote admin gate

- `REMOTE_ADMIN_ONLY` defaults to true in Compose.
- Non-local requests must satisfy admin role/email restrictions.

---

## 7) Degraded-Mode Expectations

The platform is still "working" in degraded mode when:

- Core stack is healthy.
- Optional integrations are unavailable but:
  - core SOC read paths still function,
  - failure is explicit (status/warning/error), and
  - there is no cascading crash in core pages.

Common degraded examples:

- No Ollama: AI-augmented analysis falls back or returns limited output.
- No Elasticsearch/Kibana: SIEM dashboards and related routes are reduced.
- No WireGuard: VPN-specific management/status paths are reduced.
- No Cuckoo/security sensors: sandbox/security profile pages show unavailable state.

---

## 8) Known Contract Drift Risks (Current)

1. **API base inconsistencies in frontend pages:** some pages build paths differently, so environment misconfiguration can still create path drift.
2. **Multiple agent surfaces:** monolithic unified agent API contract (`/api/unified/...`) differs from desktop/core helper assumptions (`/agents/...` style paths).
3. **Legacy auxiliary API/UI components:** `unified_agent/server_api.py` is a secondary in-memory service and should not be treated as the primary backend contract.
4. **Script defaults:** some scripts default to hardcoded cloud IP/URLs; they should be overridden per environment.

---

## 9) "Working" Definition (Final)

The system is considered **working** when:

1. Core runtime (`mongodb`, `redis`, `backend`, `frontend`) is healthy.
2. Backend auth and dashboard API paths operate under `/api`.
3. Unified-agent registration/heartbeat/command polling works on `/api/unified/agents/*`.
4. Optional service failures degrade gracefully and do not break core SOC workflows.
5. Security boot constraints (JWT/CORS/internal token requirements) are respected in strict/production runs.
