# Metatron Run-Mode Contract (Rebaselined)

Generated: 2026-04-20  
Purpose: define reliable launch modes and runtime expectations based on current code wiring

## 1) Canonical Runtime Surfaces

- **Primary backend API**: `backend.server:app` (FastAPI) on port `8001`
- **Primary frontend UI**: built React app served by nginx (container port `80`, mapped to host `3000` in compose)
- **Primary data store**: MongoDB (`mongodb` service)
- **Primary async broker/backend**: Redis (used by Celery worker/beat)

Authoritative files:
- `backend/server.py`
- `backend/Dockerfile`
- `frontend/Dockerfile`
- `docker-compose.yml`

---

## 2) Compose Core vs Optional (as currently wired)

### Core operational baseline

At minimum for practical full-stack operation in this repo's compose model:
- `mongodb`
- `redis`
- `backend`
- `frontend`

### Compose-coupled dependencies currently referenced by backend `depends_on`

In `docker-compose.yml`, backend currently depends on:
- `mongodb`
- `redis`
- `elasticsearch`
- `ollama`

Even when some integrations are conceptually optional, compose startup behavior may still require these services unless compose config is adjusted.

### Optional/profile-based integrations

Profile or environment dependent services include:
- Security profile: `trivy`, `falco`, `suricata`, `zeek`, `volatility`
- Sandbox profile: `cuckoo`, `cuckoo-web`, `cuckoo-mongo`
- Edge/proxy extras: `wireguard`, root `nginx`, `admin-bootstrap`, `ollama-pull`

---

## 3) Launch Modes

### A) Full local stack (closest to current compose default wiring)

```bash
docker compose up -d mongodb redis elasticsearch ollama backend frontend
```

### B) Extended security profile

```bash
docker compose --profile security up -d
```

### C) Sandbox profile

```bash
docker compose --profile sandbox up -d
```

---

## 4) API Routing Contract

### Backend

- Most routers mount under `/api` in `backend/server.py`.
- Some routers include their own `/api/v1/*` prefix and are mounted without an additional `/api` prefix (e.g., CSPM, identity).
- WebSocket endpoints `/ws/threats` and `/ws/agent/{agent_id}` are top-level (not under `/api`).

### Frontend

- Frontend resolves API root as either:
  - `${REACT_APP_BACKEND_URL}/api` when env var is valid, or
  - same-origin `/api` fallback.
- In containerized deployment, `frontend/nginx.conf` proxies `/api` to `http://backend:8001`.

Contract references:
- `frontend/src/lib/api.js`
- `frontend/src/context/AuthContext.jsx`
- `frontend/nginx.conf`

---

## 5) Local Dashboard Contract (Unified Agent)

- Canonical local dashboard ownership:
  - Port `5000`: `unified_agent/ui/web/app.py` (Flask)
  - Alternate local UI path in core agent can be shifted via `--ui-port` (default in code is 5000; docs reserve 5050 to avoid collision)

Reference:
- `unified_agent/LOCAL_DASHBOARD_CONTRACT.md`
- `unified_agent/run_local_dashboard.sh`
- `unified_agent/core/agent.py`

---

## 6) Health Validation Sequence

1. `docker compose ps`
2. `curl -fsS http://127.0.0.1:8001/api/health`
3. `curl -fsS http://127.0.0.1:3000` (compose mapped frontend)
4. Verify login path (`/login`) and at least one workspace page under authenticated flow.
5. If security/sandbox profiles are enabled, validate related pages and endpoints degrade gracefully when external tools are unavailable.

---

## 7) Known Runtime Consistency Risks

1. **Compose dependency strictness vs conceptual optionality**  
   Backend `depends_on` currently includes Elasticsearch and Ollama.

2. **Frontend API-base drift risk**  
   URL resolution logic exists in multiple places (`frontend/src/lib/api.js` and `frontend/src/context/AuthContext.jsx`, plus page-local patterns).

3. **Multiple agent/server surfaces**  
   Main authoritative control plane lives in backend `/api/unified/*`; `unified_agent/server_api.py` is a separate side-server path.

4. **Port and contract drift across scripts/docs**  
   Some historical docs/scripts reference legacy defaults or alternate URLs.

---

## 8) Acceptance Criteria for "Working"

System is considered working when all are true:
1. Backend health endpoint returns healthy.
2. Frontend loads and authentication path functions.
3. Core SOC reads/writes (alerts, threats, timeline, unified agent views) complete without fatal contract errors.
4. Optional integrations fail gracefully with explicit status or partial data behavior rather than system-wide failures.

---

## 9) Bottom Line

The current runtime contract is viable and feature-rich, but operational predictability depends on keeping compose dependencies, frontend API-base behavior, and multi-surface agent contracts explicitly aligned in docs and tests.
