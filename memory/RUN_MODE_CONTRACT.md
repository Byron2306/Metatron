# Metatron Run-Mode Contract (Source of Truth)

**Reviewed:** 2026-04-25  
**Goal:** Define required vs optional runtime surfaces so operators can tell core platform health apart from degraded integration features.

## 1) Required Core Services

The dashboard is not considered healthy unless these services are up:

- `mongodb`
- `backend`
- `frontend`

The backend listens on port `8001` in the root Compose file and exposes health at:

```bash
curl -fsS http://localhost:8001/api/health
```

The frontend listens on port `3000` in local Compose mode.

## 2) Core Adjacent Services

These services are strongly recommended for normal local operation, but should not make the core dashboard unusable if down:

- `redis`
- `celery-worker`
- `celery-beat`

They support async/background work, scheduled jobs, and broker/result behavior.

## 3) Default Optional Integrations

The UI and APIs should degrade gracefully if these services are unavailable:

- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`
- `nginx`

Expected behavior:

- core auth and dashboard shell remain usable;
- integration-specific pages show unavailable/degraded state;
- backend health does not claim those integrations are healthy unless checked separately.

## 4) Security Tooling Integrations

Root `docker-compose.yml` currently defines these security-tool services:

- `trivy`
- `falco`
- `suricata`
- `zeek`
- `volatility`

These require tool availability, host permissions, mounted logs, and/or network capture support. They should be treated as conditional integrations, not required core services.

## 5) Sandbox Integrations

Sandbox mode depends on the Cuckoo stack:

- `cuckoo-mongo`
- `cuckoo`
- `cuckoo-web`

Sandbox APIs can exist without full detonation capability. Operators should validate the sandbox service itself before treating sandbox verdicts as production evidence.

## 6) AI / Model Integrations

`ollama` and model-backed services are optional. Rule-based or fallback paths may still run, but model quality and latency depend on configured model availability.

## 7) API Routing Contract

- Frontend API calls should resolve to backend `/api/...` routes through `REACT_APP_BACKEND_URL` or same-origin proxying.
- Backend health is `GET /api/health`, not root `/health`.
- Most routers are mounted under `/api` in `backend/server.py`.
- Some routers carry native or duplicated `/api/v1` surfaces: CSPM, identity, attack paths, secure boot, kernel sensors, and deception compatibility mounts.
- Raw WebSockets are exposed at `/ws/threats` and `/ws/agent/{agent_id}`.

## 8) Launch Modes

### Minimal reliable mode

```bash
docker compose up -d mongodb backend frontend
```

### Core async mode

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend
```

### Local integration mode

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend elasticsearch kibana ollama wireguard
```

### Full Compose mode

```bash
docker compose up -d
```

Full Compose mode starts all 21 services and is environment-sensitive. It requires more host resources and may need privileges for VPN, network inspection, and sandbox functions.

## 9) Health Validation Sequence

1. Validate containers:
   ```bash
   docker compose ps
   ```
2. Validate backend core health:
   ```bash
   curl -fsS http://localhost:8001/api/health
   ```
3. Validate frontend:
   ```bash
   curl -fsS http://localhost:3000
   ```
4. Log in and verify the workspace shell loads.
5. Validate optional services from their own pages or API status endpoints.
6. Treat optional-service failures as degraded integration state, not automatic platform-wide failure.

## 10) Known Conditional Contracts

- Unified deployment success must be tied to verified execution evidence, not only queue acceptance.
- WinRM/SSH deployment requires valid credentials, reachable endpoints, and required Python packages.
- Email gateway production behavior requires SMTP relay/server configuration.
- MDM connector production behavior requires tenant credentials and API permissions.
- CSPM requires cloud credentials for meaningful scan data.
- Kernel sensors and secure boot routes may be disabled if optional imports fail.
- Browser isolation currently has limited depth compared with full remote browser isolation.
- Scripts and tests must avoid legacy endpoint drift such as `/health` or obsolete `/api/agent/*` paths unless compatibility is explicitly maintained.

## 11) Acceptance Criteria for "Working"

A deployment is considered working when:

1. Required core services are healthy.
2. Authentication and the protected React layout work.
3. Core SOC workflows load data or show empty states without fatal errors.
4. Unified-agent routes can register/heartbeat in the configured mode.
5. Optional integrations report explicit connected/degraded/unavailable state.
6. High-risk action paths route through governance/authorization controls.
7. Documentation and validation scripts point at active endpoints.

## 12) Documentation Rule

Do not promote an optional integration from conditional to production-ready in docs until there is credentialed or service-backed runtime evidence for the target environment.
