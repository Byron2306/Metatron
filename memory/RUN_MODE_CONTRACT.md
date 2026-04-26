# Metatron / Seraph Run-Mode Contract

Updated: 2026-04-26  
Scope: operational source of truth for local, full, and degraded runtime modes.

## Required core

The dashboard is healthy only when these services are available:

| Service | Purpose | Default endpoint |
|---|---|---|
| `mongodb` | primary persistence for platform state, telemetry, commands, world events, governance records | `mongodb://mongodb:27017` in compose |
| `backend` | FastAPI API, WebSockets, router mesh, triune/world/governance services | `http://localhost:8001/api/health` |
| `frontend` | React SOC/operator dashboard | `http://localhost:3000` |

Redis is part of the default compose stack for Celery worker/beat and asynchronous integration work. The minimal UI/API path can be reasoned about with MongoDB, backend, and frontend, but compose currently starts Redis-backed services for the fuller runtime.

## Optional or profile-based services

The platform is designed to degrade when optional integrations are missing.

| Service/profile | Contract |
|---|---|
| `elasticsearch`, `kibana` | log/search dashboard features should show unavailable/degraded status instead of breaking core SOC pages |
| `wireguard` | VPN pages and peer operations depend on it; threat/agent workflows must remain usable without it |
| `ollama` / external LLM providers | AI reasoning quality improves when available; rule-based or empty-result fallback paths must not block core operations |
| `trivy`, `falco`, `suricata` (`security` profile) | container/runtime/network sensor depth; not required for baseline dashboard health |
| `cuckoo`, `cuckoo-web` (`sandbox` profile) | dynamic sandbox analysis; degraded status is acceptable when absent |
| external SMTP, MDM, SIEM, Twilio, SendGrid, Slack | integration-specific actions require credentials; local/test management APIs may still operate with configured in-process state |

## Launch modes

```bash
# Baseline local services
docker compose up -d mongodb redis backend frontend

# Recommended local stack with observability and AI helpers
docker compose up -d mongodb redis backend frontend elasticsearch kibana wireguard ollama

# Extended security sensors
docker compose --profile security up -d

# Sandbox mode
docker compose --profile sandbox up -d
```

## Routing contract

- `backend/server.py` mounts most routers under `/api`.
- Several routers carry native `/api/v1` prefixes, including CSPM/identity-style routes.
- The frontend should call `${REACT_APP_BACKEND_URL}/api/...` in development or same-origin `/api/...` behind a reverse proxy.
- WebSockets are exposed for threat streaming and agent channels.

## Health validation

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

For deeper checks:

```bash
python3 full_feature_test.py
python3 backend/scripts/integration_runtime_full_smoke.py
cd frontend && yarn test
```

Run targeted backend tests from `backend/tests/` when changing a specific service or router.

## Degraded-mode rules

1. Missing optional services must be visible as status or degraded messages.
2. Optional provider failure must not cascade into core threat, alert, world, agent, or governance pages.
3. High-impact actions must not silently execute through fallback paths; they should queue through governance or fail closed.
4. Deployment success should represent verified endpoint evidence whenever an execution adapter is used; queued/simulated states must be labeled.

## Current acceptance interpretation

The platform is "working" when:

1. MongoDB, backend, and frontend are healthy.
2. Auth and the protected layout load.
3. Core SOC reads work for command/dashboard, threats/alerts, world view, unified agent, settings, and response operations.
4. World events persist and strategic/high-impact classes can trigger triune recomputation.
5. Governance decisions can be listed and approved/denied.
6. Optional integrations degrade explicitly.

## Known risks to monitor

- API/client contract drift across a large router mesh and consolidated frontend workspaces.
- Script/default URL drift across `localhost:8001`, `localhost:8002`, and older examples.
- Optional integration semantics are inconsistent in some older modules.
- `backend/server.py` remains the central wiring point and can accumulate startup coupling.
- Some legacy documents and scripts may still describe old page counts, endpoint names, or smoke-test behavior.
