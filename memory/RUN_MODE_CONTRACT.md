# Metatron Run-Mode Contract (Source of Truth)

## Goal
Define what is **required** vs **optional** so operators can run the platform predictably and understand why some dashboard features may be unavailable.

## 1) Required Core (must be up)
- `mongodb`
- `redis`
- `backend`
- `frontend`

The Compose backend depends on MongoDB and Redis. If any of these are down, the dashboard/API stack is not considered healthy. Celery worker/beat are strongly recommended for async jobs and scheduled integration/world/triune work, but the API process can still start separately.

## 2) Default Optional Integrations (degraded mode if down)
- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`

Behavior contract:
- UI should remain usable when optional services are down.
- Related pages/features may show degraded status, warnings, or partial data.

## 3) Profile-Based Optional Integrations
These are intentionally profile-gated and not required for baseline operation.

### bootstrap profile
- `ollama-pull`
- `admin-bootstrap`

### security profile
- `volatility`
- `trivy`
- `falco`
- `suricata`
- `zeek`

### sandbox profile
- `cuckoo`
- `cuckoo-web`

Note: `cuckoo-mongo` is defined as a support service for sandbox components in Compose, while the Cuckoo API/UI services themselves are profile-gated.

## 4) Runtime Launch Modes
### Minimal reliable mode
`docker compose up -d mongodb redis backend frontend`

### Recommended local full mode
`docker compose up -d mongodb redis backend celery-worker celery-beat elasticsearch kibana ollama frontend wireguard nginx`

### Bootstrap helpers
`docker compose --profile bootstrap up ollama-pull admin-bootstrap`

### Extended security mode
`docker compose --profile security up -d`

### Sandbox mode
`docker compose --profile sandbox up -d`

## 5) API Routing Contract
- Frontend calls backend via `${REACT_APP_BACKEND_URL}/api/...`.
- In production behind reverse proxy, same-origin `/api` routing should be preferred.
- Backend routers are mounted under `/api` in `backend/server.py`.

## 6) Health Validation Sequence
1. `docker compose ps`
2. `curl -fsS http://localhost:8001/api/health`
3. `curl -fsS http://localhost:3000` (or deployed frontend URL)
4. Validate optional services only when their profile or credentials are enabled.
5. Treat `/api/health` as API process health; it currently returns a static database field and should not be considered a live dependency probe by itself.

## 7) Known Wiring Risks (current static audit)
- Backend route surface is large and centrally wired in `backend/server.py`; generated route inventories should be kept in CI.
- Some Tier-1 routers are imported with fail-open warnings, so absence can be masked unless startup logs/readiness checks are reviewed.
- Frontend routes intentionally redirect many legacy pages into workspace hubs; docs should describe current paths rather than old standalone pages.
- Unified-agent monitor counts are platform/config dependent; do not document a universal 29-monitor invariant.
- Optional integration behavior must distinguish unconfigured, unavailable, degraded, and healthy states.

## 8) Acceptance Criteria for "Working"
- Core services up and healthy.
- Login works and main dashboard loads without fatal errors.
- At least one page each from: Threats, Alerts, Agents, Settings can load data successfully.
- Optional integration pages degrade gracefully if their service is not enabled.

## 9) Consolidated Reality Conditions (2026-03-04)

These conditions align run-mode expectations with the critical evaluation and feature reality artifacts.

### 9.1 Must-pass operational contracts
- Swarm group/tag/device assignment flows should be available end-to-end.
- Threats/Alerts/Timeline/Zero-Trust pages should load and execute their core read paths.
- Threat response routes should remain functional even when optional providers (Twilio/OpenClaw) are unavailable.

### 9.2 Known degraded/conditional contracts
- Unified deployment endpoint currently represents a queued/simulated flow unless backed by real deployment execution plumbing.
- WinRM auto-deployment is conditional on:
  - valid credentials (password-based auth),
  - `pywinrm` installed,
  - remote endpoint availability (port/protocol/security policy).
- OpenClaw integration is optional and should never block core SOC operation.

### 9.3 Contract integrity risks to monitor
- Unified command schema mismatch risk between frontend and backend payload models.
- Threat-response OpenClaw analyze payload mapping mismatch risk.
- Mixed frontend API base strategy (`REACT_APP_BACKEND_URL` hard dependency in some pages vs `/api` fallback in others).
- Script ecosystem endpoint drift (`/api/agent/*` legacy paths vs active `/api/swarm` and `/api/unified` contracts).
- Script/default URL drift across `localhost:8001`, `localhost:8002`, and legacy cloud defaults.
- Validation script mismatch risk (`/api/zero-trust/overview` probe not aligned to active router paths).

### 9.4 Updated "Working" interpretation
System is considered **working** when:
1. Core required services are healthy.
2. Core SOC workflows (threats, alerts, timeline, zero-trust read/evaluate) execute successfully.
3. Optional integrations fail gracefully with explicit status and no cascading core failure.
4. Deployment success states correspond to verified execution, not simulation-only completion.

## 10) Acceptance Changelog (2026-03-04)

- Added writable runtime data-path fallback behavior for backend services to prevent startup failure in restricted environments.
- Aligned backend integration tests to current API contracts (response shapes, permissions, and agent-download artifact behavior).
- Removed test warning sources from VPN/browser integration tests (no non-`None` test returns).
- Final targeted acceptance subset result:
  - `backend/tests/test_audit_timeline_openclaw.py`
  - `backend/tests/test_unified_agent_hunting.py`
  - `backend/tests/test_vpn_zerotrust_browser.py`
  - `backend/tests/test_agent_download.py`
  - outcome: **94 passed, 5 skipped, 0 failed**
