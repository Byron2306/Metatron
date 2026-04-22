# Metatron Run-Mode Contract (Updated Source of Truth)

**Date:** 2026-04-22  
**Scope:** Runtime expectations backed by current compose/app code.

---

## 1) Required Core for a Healthy Platform

At minimum, these services must be healthy for baseline operation:

- `mongodb`
- `redis`
- `backend`
- `frontend`

If any are down, the platform should be treated as degraded or unavailable.

---

## 2) Optional and Profile-Gated Services

### Default optional (non-core but commonly enabled)

- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`
- `nginx` (required for TLS/reverse-proxy ingress topology)

### Security profile services

- `trivy`
- `falco`
- `suricata`
- `zeek`
- `volatility`

### Sandbox profile services

- `cuckoo`
- `cuckoo-web`
- `cuckoo-mongo`

Contract:

- Core SOC/API workflows must remain usable without profile-gated services.
- Optional domain pages should degrade gracefully with clear status messaging.

---

## 3) Launch Modes

### Minimal core mode

```bash
docker compose up -d mongodb redis backend frontend
```

### Recommended local full mode

```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana ollama wireguard
```

### Security mode

```bash
docker compose --profile security up -d
```

### Sandbox mode

```bash
docker compose --profile sandbox up -d
```

### Production override mode

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

---

## 4) API and Routing Contract

- Backend serves API routes primarily under `/api/*`.
- Some routers expose versioned paths directly (for example `/api/v1/*` domains like CSPM/identity).
- Frontend is expected to call backend through:
  - same-origin `/api` behind nginx/reverse proxy, or
  - configured external backend URL (`REACT_APP_BACKEND_URL`) in direct-mode deployments.

---

## 5) Security Mode Contract

### Production/strict expectations

- `ENVIRONMENT=production` and/or `SERAPH_STRICT_SECURITY=true` enforce stricter behavior.
- `JWT_SECRET` must be strong; weak/default secrets are invalid in strict/prod mode.
- `CORS_ORIGINS` must be explicit (wildcard not allowed in strict/prod mode).
- `REMOTE_ADMIN_ONLY` defaults to true and gates non-local admin access behavior.

### Machine-token protected paths

- Multiple internal ingest/control surfaces require machine tokens (for example swarm/unified/enterprise/advanced identity paths and websocket machine auth where configured).

---

## 6) Health Validation Sequence

1. `docker compose ps`
2. `curl -fsS http://localhost:8001/api/health`
3. `curl -fsS http://localhost:3000` (or ingress URL)
4. Validate login and critical pages:
   - Threats
   - Alerts
   - Agents/Unified
   - Settings
5. Validate optional domains only when corresponding services are enabled.

---

## 7) Acceptance Criteria for "Working"

System is considered working when all are true:

1. Core services are healthy (`mongodb`, `redis`, `backend`, `frontend`).
2. Auth works (`/api/auth/login` and/or initial setup flow).
3. Core read workflows function (threats/alerts/dashboard/agents).
4. Unified agent registration + heartbeat function for at least one agent.
5. Optional integrations fail gracefully without cascading failure.

---

## 8) Known Contract Risks to Monitor

1. **Prefix drift risk** (`/api/*` vs `/api/v1/*` expectations in clients/scripts).
2. **Environment drift risk** (security behavior differs significantly with weak/missing prod env config).
3. **Integration realism variance** (credential-dependent domains may appear healthy but provide demo/no-op data paths when not fully configured).
4. **Surface-area regression risk** due to high endpoint and router count.

---

## 9) Operational Guidance

- Treat memory/evaluation docs as secondary references; this file is the runtime contract baseline.
- Before claiming production readiness for a domain, validate:
  - live credentials,
  - end-to-end external connectivity,
  - durable persistence path,
  - auth/permission checks under non-admin and remote contexts.

