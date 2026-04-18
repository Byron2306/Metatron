# Metatron Run-Mode Contract (Current Source of Truth)

Generated: 2026-04-18  
Scope: Runtime expectations aligned with current `docker-compose.yml`, backend auth/dependency behavior, and API routing.

---

## 1) Required Core Services (baseline healthy system)

- `mongodb`
- `redis`
- `backend`
- `frontend`

System should be considered unhealthy when these are unavailable.

### Notes
- Backend is configured to depend on Redis and MongoDB in compose.
- Frontend depends on backend health.

---

## 2) Optional / Profile-Gated Services

### Default optional (can be down without hard platform failure)
- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`
- `nginx`

### Security profile (`--profile security`)
- `trivy`
- `falco`
- `suricata`
- `zeek`
- `volatility`

### Sandbox profile (`--profile sandbox`)
- `cuckoo-mongo`
- `cuckoo`
- `cuckoo-web`

### Bootstrap profile (`--profile bootstrap`)
- `ollama-pull`
- `admin-bootstrap`

---

## 3) Runtime Behavior Contract

### Core behavior
- UI and API must remain usable with only core services up.
- Optional integrations must degrade explicitly (status and feature-level messaging), not fail silently.

### Deployment behavior
- Real deployment paths exist (`SSH`, `WINRM`) in `backend/services/agent_deployment.py`.
- Simulated deployment only occurs when:
  - credentials are absent, **and**
  - `ALLOW_SIMULATED_DEPLOYMENTS=true`.
- Default behavior (without that flag) is to fail deployment attempts lacking credentials.

### CSPM behavior
- `POST /api/v1/cspm/scan` is authenticated (`Depends(get_current_user)`).
- Provider configure/remove operations are triune-gated outbound actions.
- When providers are not configured, demo data path can be used by scan flow (explicitly handled in router).

---

## 4) API Routing Contract

- Canonical API base: `/api` for most routers.
- Additional versioned paths:
  - `/api/v1/cspm/*`
  - `/api/v1/identity/*`
  - `/api/v1/deception/*` compatibility mount alongside `/api/deception/*`
- Backend router registration count in current code: 65 `app.include_router(...)` calls in `backend/server.py`.

---

## 5) Auth and Access Contract

### JWT
- `JWT_SECRET` is required in production/strict mode; weak or missing secrets are rejected in strict production context.

### Remote admin gating
- `REMOTE_ADMIN_ONLY` (default true) restricts remote access paths in auth dependency logic.

### Machine-token paths
- Multiple machine-ingest endpoints enforce shared token dependencies (enterprise/identity/websocket/internal integrations).

---

## 6) Minimal Launch Modes

### Minimal reliable local mode
```bash
docker compose up -d mongodb redis backend frontend
```

### Recommended broader local mode
```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana ollama wireguard
```

### Security tooling mode
```bash
docker compose --profile security up -d
```

### Sandbox mode
```bash
docker compose --profile sandbox up -d
```

---

## 7) Health Validation Sequence

1. `docker compose ps`
2. `curl -fsS http://localhost:8001/api/health`
3. `curl -fsS http://localhost:3000` (or deployed frontend origin)
4. Validate authenticated endpoint access (token/session)
5. Validate optional integration pages only for enabled services/profile

---

## 8) Acceptance Criteria for “Working”

System is considered working when:

1. Core required services are healthy.
2. Authentication succeeds and dashboard loads.
3. At least one read path each from:
   - Threats/Alerts
   - Unified Agent
   - Settings/Status
   - One domain module (e.g., CSPM, Email, Mobile).
4. Optional services fail/degrade gracefully when disabled.
5. Deployment success states correspond to verified execution (or explicit simulation mode labeling in non-production demo mode).

---

## 9) Known High-Value Contract Risks to Track

1. API contract drift across high-velocity routes and frontend consumers.
2. Optional integration state handling consistency (especially across profile-gated services).
3. Environment-specific auth and CORS misconfiguration during production rollout.
4. Residual assumptions in legacy scripts/docs about older route aliases or port defaults.

---

## 10) Practical Interpretation

The system is not “all-or-nothing.” It is a core platform with optional security planes. Operational correctness depends on:

- strict core health,
- explicit degraded-mode semantics for optional services,
- and truthful execution state reporting (especially deployment and triune-gated actions).
