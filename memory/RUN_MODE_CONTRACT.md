# Metatron Run-Mode Contract (Updated Source of Truth)

**Last Updated:** 2026-04-15  
**Purpose:** Define required services, optional integrations, and expected behavior for predictable operations.

---

## 1) Required Core Services

The platform is not considered healthy unless these are up and reachable:

- `mongodb`
- `redis`
- `backend`
- `frontend`

For async/task-enabled operation, include:

- `celery-worker`
- `celery-beat`

---

## 2) Optional Integrations (Graceful Degradation Expected)

Optional in baseline operation:

- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`

Profile-gated optionals:

- `security` profile:
  - `trivy`
  - `falco`
  - `suricata`
  - `zeek`
  - `volatility`
- `sandbox` profile:
  - `cuckoo`
  - `cuckoo-web`

Contract:

- Core SOC workflows must remain usable when optional services are unavailable.
- Optional-dependent pages may return warnings, partial data, or unavailable status, but should not cascade core failures.

---

## 3) Launch Modes

### Minimal core mode

```bash
docker compose up -d mongodb redis backend frontend
```

### Core + async worker mode

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat
```

### Recommended local expanded mode

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat wireguard elasticsearch kibana ollama
```

### Security profile mode

```bash
docker compose --profile security up -d
```

### Sandbox profile mode

```bash
docker compose --profile sandbox up -d
```

### Production overlay mode

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Production overlay behavior:

- Backend/frontend/data ports are internalized.
- Nginx is intended ingress for HTTP(S).
- `ENVIRONMENT=production` and strict security posture flags are enabled for backend.

---

## 4) API Routing Contract

- Backend routers are primarily mounted under `/api` in `backend/server.py`.
- Some routers expose native `/api/v1/*` prefixes (for compatibility and specific domains).
- Frontend should prefer same-origin `/api` when reverse-proxied.
- `REACT_APP_BACKEND_URL` may be used in direct dev/topology scenarios.

---

## 5) Identity and Access Contract

- User auth: Bearer JWT (`/api/auth/*`) with role checks.
- Remote access gate defaults to admin-only behavior when `REMOTE_ADMIN_ONLY=true`.
- Machine/internal calls use header token checks (constant-time compare).
- World ingest endpoints require valid machine token headers and configured tokens.

---

## 6) Governance Contract

- In production/strict mode, governance context is required by default (`governance_context_required()` behavior).
- High-impact actions are queued via outbound gate (`triune_outbound_queue`, `triune_decisions`).
- Governance executor processes approved decisions into operational dispatch.
- Audit/world-event hooks should remain active for governance transitions.

---

## 7) Health Validation Sequence

1. `docker compose ps`
2. `curl -fsS http://localhost:8001/api/health`
3. Verify frontend responds (`http://localhost:3000` or ingress URL)
4. Verify auth flow (`/api/auth/*`)
5. Validate one endpoint each for threats, alerts, unified/swarm, settings/timeline
6. If optional integrations are enabled, validate dependent pages and API endpoints

---

## 8) Updated "Working" Definition

System is considered **working** when:

1. Required core services are healthy.
2. Login and core SOC workflows execute (threats, alerts, timeline, settings, unified operations).
3. Async task path is functional if Celery services are part of the run mode.
4. Optional integrations fail gracefully when unavailable.
5. High-impact action paths honor governance queueing/execution semantics.

---

## 9) Known Ongoing Integrity Risks

- Frontend API base/path construction is still mixed across pages.
- Large router surface can drift without automated contract checks.
- Legacy/alternate surfaces require continuous hardening parity validation.
- Optional integration diversity increases degraded-mode test burden.

