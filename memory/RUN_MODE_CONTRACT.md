# Metatron Run-Mode Contract

**Rebaselined:** 2026-04-29
**Purpose:** Define the minimum reliable stack, optional services, routing assumptions, and what "working" means for the current codebase.

## 1) Required Core

The platform is considered healthy only when these are available:

- `mongodb` for persisted platform state.
- `backend` running `backend.server:app` on port `8001` in the container image.
- `frontend` serving the React application.

The backend can use `MONGO_USE_MOCK` / `mongomock://` for test-like environments, but production operation requires a real MongoDB service.

## 2) Default Optional Integrations

These improve fidelity but must not be required for baseline UI/API health:

- `redis` / Celery workers for asynchronous task execution.
- `wireguard` for VPN operations.
- `elasticsearch` and `kibana` for SIEM/dashboard integrations.
- `ollama` for optional local model augmentation.
- Security-profile tools such as Falco, Suricata, Trivy, and sandbox services when enabled.

Expected behavior: affected pages show unavailable/degraded state without preventing login, command workspace loading, or core API operation.

## 3) Launch Modes

```bash
# Minimal reliable local stack
docker compose up -d mongodb backend frontend

# Fuller local stack with common optional services
docker compose up -d mongodb redis backend frontend wireguard elasticsearch kibana ollama

# Optional profile examples
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

## 4) Routing Contract

- Frontend routes are defined in `frontend/src/App.js`. `/` redirects to `/command`.
- Frontend authentication is handled by `frontend/src/context/AuthContext.jsx`.
- The preferred frontend API base logic lives in `frontend/src/lib/api.js`.
- Backend REST routers are registered in `backend/server.py`, primarily under `/api`.
- Some routers already include `/api/v1` prefixes and are mounted without an extra `/api` prefix.
- WebSockets are exposed at `/ws/threats` and `/ws/agent/{agent_id}`. Agent websocket access requires a machine token.

## 5) Security and Governance Runtime Contract

- `INTEGRATION_API_KEY` is mandatory in production for internal ingestion and workers.
- Production/strict mode rejects wildcard or missing CORS origins.
- Machine ingestion endpoints in `backend/routers/world_ingest.py` require a machine token.
- High-impact actions should pass through `OutboundGateService`, `GovernanceDecisionAuthority`, and `GovernanceExecutorService` before downstream execution.
- Sensitive token/tool paths enforce approved governance context through `backend/services/governance_context.py`.

## 6) Health Validation Sequence

1. `docker compose ps`
2. Backend health: `curl -fsS http://localhost:8001/api/health || curl -fsS http://localhost:8001/health`
3. Frontend availability: `curl -fsS http://localhost:3000` or deployed frontend URL.
4. Login and load `/command`, `/world`, `/unified-agent`, and one optional integration page.
5. If governance is enabled, create/approve/deny a gated decision and verify associated `triune_decisions`, `triune_outbound_queue`, and `agent_commands` records.

## 7) Working Definition

The system is "working" when:

1. Required core services are healthy.
2. Login succeeds and protected routes render.
3. Command, alerts/threats, world view, unified agent, and at least one response flow can read data.
4. Optional integrations degrade clearly when absent.
5. High-impact command paths are either explicitly gated or clearly marked as non-production/simulation-safe.
6. Runtime success states correspond to persisted backend state rather than UI-only optimism.

## 8) Current Drift Risks

- Mixed frontend API base construction can still cause deployment-specific route drift.
- `backend/server.py` remains a dense composition point; import failures in optional routers must remain visible.
- Some documentation and local scripts still reference older page slugs and service ports.
- The `memory/` Docker sidecar files describe a `src/` layout that is not present there; the runnable sidecar in this repo is `cas_shield_sidecar.py` or the bundled sidecar under `cas_shield_sentinel_bundle/`.
