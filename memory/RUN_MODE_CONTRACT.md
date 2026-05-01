# Metatron Run-Mode Contract

Updated: 2026-05-01

This document is the source of truth for what must be running, what is optional, and how the current code routes traffic.

## Required core

The dashboard is healthy only when all three core services are available:

| Service | Evidence | Notes |
| --- | --- | --- |
| `mongodb` | `docker-compose.yml`, `backend/server.py` | Primary state store for platform data, telemetry, commands, governance records, and API state. |
| `backend` | `backend/server.py` | Canonical FastAPI product API. Compose exposes it on `127.0.0.1:8001` by default. |
| `frontend` | `frontend/src/App.js` | React SOC dashboard. Compose exposes it on `3000`. |

Redis is not part of the minimal health definition, but the current compose stack uses it for Celery worker/beat paths and background execution. Treat it as required for background-job parity.

## Optional and degraded-mode services

The platform should remain usable when optional services are not available. Pages or APIs tied to an optional dependency should show a degraded state rather than blocking core SOC workflows.

| Optional service/profile | Used for | Current evidence |
| --- | --- | --- |
| `wireguard` | VPN management and split-tunnel workflows | `docker-compose.yml`, `backend/vpn_integration.py`, `backend/routers/vpn.py` |
| `elasticsearch`, `kibana` | SIEM/dashboard integrations | `backend/services/siem.py`, `backend/kibana_dashboards.py`, `backend/routers/kibana.py` |
| `ollama` | Local LLM reasoning | `backend/services/ai_reasoning.py`, `backend/ai/ollama_client.py` |
| `trivy`, `falco`, `suricata` | Security-profile scanning/runtime detections | `docker-compose.yml`, `backend/container_security.py`, unified-agent integrations |
| `cuckoo`, `cuckoo-web` | Sandbox-profile malware analysis | `backend/services/cuckoo_sandbox.py`, `backend/sandbox_analysis.py` |
| External MDM/SMTP/SIEM credentials | Production integrations | `backend/mdm_connectors.py`, `backend/email_gateway.py`, `backend/services/siem.py` |

## Launch modes

Minimal local mode:

```bash
docker compose up -d mongodb backend frontend
```

Recommended local core mode:

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat
```

Full local stack:

```bash
docker compose up -d
```

Optional profiles:

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

## API routing contract

- `backend/server.py` is the canonical product API entrypoint.
- Most routers are mounted under `/api`.
- Selected routers carry native `/api/v1` prefixes, including CSPM, identity, attack paths, secure boot, and kernel sensors.
- The unified-agent control plane is mounted as `/api/unified/*`.
- WebSockets are exposed under `/ws/*`, including `/ws/threats` and `/ws/agent/{agent_id}`.
- Frontend API resolution lives in `frontend/src/lib/api.js`:
  - valid `REACT_APP_BACKEND_URL` becomes `${REACT_APP_BACKEND_URL}/api`;
  - otherwise same-origin `/api` is used.

## Canonical UI routes

- `/command` is the default route.
- `/unified-agent` is the canonical unified-agent dashboard.
- Legacy `/agents`, `/swarm`, `/agent-commands`, and `/agent-commands/:agentId` redirect to `/unified-agent`.
- `/email-security` is the canonical email workspace. `/email-protection` and `/email-gateway` redirect to tabbed views there.
- `/endpoint-mobility` is the canonical endpoint/mobile workspace. `/mobile-security` and `/mdm` redirect to tabbed views there.

## Health checks

Core checks:

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Working means:

1. Core services are healthy.
2. Authentication and protected layout load.
3. Core SOC pages can read data through `/api`.
4. Optional integrations fail visibly and safely.
5. Deployment, command, and remediation status semantics distinguish verified execution from queued, degraded, or credential-dependent flows.

## Known risk conditions to monitor

- Contract drift across 62 backend router modules and many frontend pages.
- Legacy script/API drift between older `/api/agent/*`, swarm, and `/api/unified/*` paths.
- Secondary local agent API (`unified_agent/server_api.py`) must not be confused with the canonical dashboard backend.
- Governance-sensitive state should continue moving toward durable storage and restart/scale-safe semantics.
- Production SMTP, MDM, SIEM, sandbox, and AI quality depends on configured external services and credentials.
