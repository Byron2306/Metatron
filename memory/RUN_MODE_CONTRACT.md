# Run-Mode Contract (Current Source of Truth)

Date: 2026-04-15

## Purpose

Define required versus optional runtime components and clarify which service owns each major API/dashboard surface so operators can run the platform predictably.

---

## 1) Canonical Runtime Ownership

### Primary enterprise control plane

- Service: `backend/server.py`
- Default port: `8001`
- Responsibilities:
  - main `/api` backend routers,
  - websocket endpoints (`/ws/threats`, `/ws/agent/{agent_id}`),
  - startup workers/schedulers,
  - world-event and governance connected workflows.

### Primary frontend SOC UI

- Service: `frontend` (React SPA)
- Default port: `3000`
- Uses `/api/...` calls to backend.

### Primary data store

- Service: MongoDB
- Default port: `27017`

### Local unified agent dashboard (canonical local view)

- Service: `unified_agent/ui/web/app.py`
- Default port: `5000`
- Role: full local agent dashboard and bridge for local operations.

---

## 2) Required Core for Baseline Healthy State

Minimum required services:

1. `mongodb`
2. `backend`
3. `frontend`

Baseline health criteria:

1. backend health endpoint responds (`/api/health`),
2. frontend loads and authenticates,
3. core workspace pages read data without fatal API errors.

If one of these three core services is down, the platform is not considered healthy.

---

## 3) Optional Services and Degraded Mode

Optional integrations and tooling include (non-exhaustive):

- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`
- security profile tools (`trivy`, `falco`, `suricata`, `zeek`)
- sandbox profile tools (`cuckoo`, `cuckoo-web`)

Degraded mode contract:

1. core SOC workflows must remain available without optional services,
2. integration-dependent pages should show explicit partial/unavailable status,
3. optional failures must not cascade into authentication, core dashboard, or threat/alert basics.

---

## 4) Secondary/Compatibility Surfaces

### `unified_agent/server_api.py`

- Separate FastAPI app with in-memory/JSON persistence.
- Useful for local/demo compatibility workflows.
- Not the canonical enterprise API control plane.

Operational contract:

1. do not treat `server_api.py` as system of record for enterprise deployment state,
2. use `backend/server.py` routes for primary production workflows.

---

## 5) Runtime Modes

### Minimal reliable mode

Run core services only:

`docker compose up -d mongodb backend frontend`

### Recommended local extended mode

Run core + common optional integrations:

`docker compose up -d mongodb backend frontend wireguard elasticsearch kibana ollama`

### Security profile mode

`docker compose --profile security up -d`

### Sandbox profile mode

`docker compose --profile sandbox up -d`

---

## 6) API Routing Contract

1. backend routers are mounted under `/api` (plus selected `/api/v1` routers with explicit prefixes).
2. frontend should prefer same-origin `/api` routing in proxied deployments.
3. environment-provided backend URLs must resolve to the same route contract (`/api/...`) across pages.

---

## 7) Local Dashboard Contract

1. Port `5000` is the substantive local dashboard (`unified_agent/ui/web/app.py`).
2. Built-in minimal UI in `unified_agent/core/agent.py` is fallback/diagnostic behavior and policy-gated by `SERAPH_ALLOW_MINIMAL_UI`.
3. Operator links should treat port `5000` as the canonical local agent UI.

---

## 8) Acceptance Criteria for “Working”

System is considered working when:

1. core services are healthy,
2. login succeeds and protected frontend routes load,
3. command workspace and at least one response/investigation workflow operate,
4. unified agent register/heartbeat/command flow can execute end-to-end (when agent is present),
5. optional integrations degrade gracefully with explicit status.

---

## 9) Current Contract Risks to Monitor

1. mixed frontend API-base construction patterns can reintroduce drift;
2. multi-surface runtime ownership confusion (`backend` vs `unified_agent/server_api.py`);
3. governance durability and replay semantics under restart/scale behavior;
4. optional integration ambiguity when external dependencies are misconfigured.

---

## 10) Contract Governance Priorities

1. CI contract tests for critical API workflows.
2. Explicit service ownership documentation in deployment guides.
3. Standardized degraded-mode status reporting for optional integrations.
