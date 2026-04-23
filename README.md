# Metatron / Seraph Security Platform

Code-aligned overview of the current platform architecture, runtime model, and operational contracts.

---

## What this repository contains

Metatron/Seraph is a multi-domain security platform with:

- **FastAPI backend** control plane (`backend/server.py`)
- **React frontend** SOC console (`frontend/`)
- **MongoDB + Redis** data/runtime backbone
- **Unified endpoint agent** surfaces (`unified_agent/`)
- Optional SIEM/sensor/sandbox/LLM services via Docker Compose profiles

Primary API contract is `/api/*` on backend port `8001`.

---

## Architecture at a glance

### Core path

1. Browser loads frontend UI
2. UI calls backend under `/api/*`
3. Backend persists and serves data from MongoDB
4. Background workers and schedulers enrich/score/respond
5. Unified agents register, heartbeat, poll commands, and send command results

### Main backend entry point

- `backend/server.py` creates the FastAPI app, loads env, configures CORS, mounts routers, and starts/stops background services.

### Main frontend API base behavior

- `frontend/src/lib/api.js`
  - uses `${REACT_APP_BACKEND_URL}/api` if valid and safe
  - otherwise falls back to same-origin `/api`

---

## Key backend contracts

### Health and root

- `GET /api/health`
- `GET /api/`

### Authentication

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/setup` (initial admin bootstrap flow)

### Unified agent control plane

- `POST /api/unified/agents/register`
- `POST /api/unified/agents/{agent_id}/heartbeat`
- `GET /api/unified/agents/{agent_id}/commands`
- `POST /api/unified/agents/{agent_id}/command-result`

### Integrations runtime

- `POST /api/integrations/<tool>/run` family
- runtime targets:
  - `server`
  - `unified_agent*` (queued through governed dispatch)

### World ingest (machine-token protected)

- `/api/ingest/entity`
- `/api/ingest/edge`
- `/api/ingest/detection`
- `/api/ingest/alert`
- `/api/ingest/policy-violation`
- `/api/ingest/token-event`

---

## Security and governance model

### Production boot guards

In production/strict modes:

- `INTEGRATION_API_KEY` is required for backend startup
- wildcard CORS is rejected
- weak/missing JWT secret is rejected

References:

- `backend/server.py`
- `backend/routers/dependencies.py`

### Remote admin access policy

- `REMOTE_ADMIN_ONLY` defaults to true in Compose
- non-local requests require admin role or allowlisted admin email

### High-impact action governance

`backend/services/outbound_gate.py` and `backend/services/governed_dispatch.py` enforce queue/decision workflows for sensitive action classes (agent/swarm/response/quarantine/tool execution).

This is a core control-plane safety boundary: high-impact actions are gated, tracked, and auditable.

---

## Unified agent surfaces (important distinction)

There are multiple agent-related surfaces:

1. **Canonical monolithic agent runtime**  
   - `unified_agent/core/agent.py`  
   - speaks to `/api/unified/...` endpoints

2. **Desktop UI core**  
   - `unified_agent/ui/desktop/main.py`  
   - local desktop-centric helper/control flow

3. **Local web dashboard**  
   - `unified_agent/ui/web/app.py`  
   - Flask-based local UI (typically port 5000)

4. **Auxiliary server API**  
   - `unified_agent/server_api.py`  
   - separate, in-memory/secondary FastAPI service

Operationally, treat (1) + backend `/api/unified/...` as the primary contract.

---

## Compose runtime model

### Core services (practical minimum)

- `mongodb`
- `redis`
- `backend`
- `frontend`

### Common optional services

- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`

### Security profile

- `trivy`
- `falco`
- `suricata`
- `zeek`
- `volatility`

### Sandbox profile

- `cuckoo-mongo`
- `cuckoo`
- `cuckoo-web`

References:

- `docker-compose.yml`
- `docker-compose.prod.yml`

---

## Quick start (local)

### 1) Start core stack

```bash
docker compose up -d mongodb redis backend frontend
```

### 2) Verify health

```bash
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

### 3) Optional full local stack

```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana ollama wireguard
```

### 4) Optional profiles

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

---

## Production deployment

Use Compose override:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

Expected production behavior:

- backend/frontend host ports hidden
- ingress through nginx
- strict backend security defaults enabled

Nginx config references:

- `nginx/nginx.conf`
- `nginx/conf.d/default.conf`

Note: TLS config expects cert/key files mounted under `nginx/ssl`.

---

## Domain feature map (current implementation)

- **Threat/alert/timeline/SOAR**: `backend/routers/*`, `backend/services/*`
- **Cognition and CLI analysis**: `backend/services/cce_worker.py`, `backend/services/cognition_fabric.py`
- **Threat intel/correlation**: `backend/threat_intel.py`, `backend/threat_correlation.py`
- **Email protection + gateway**: `backend/email_protection.py`, `backend/email_gateway.py`, routers
- **Mobile security + MDM connectors**: `backend/mobile_security.py`, `backend/mdm_connectors.py`, routers
- **CSPM/identity/zero-trust surfaces**: dedicated routers/services under `backend/`
- **Integrations runtime tools**: `backend/integrations_manager.py` (`SUPPORTED_RUNTIME_TOOLS`)

---

## Known operational caveats

1. Multiple agent/UI surfaces can create contract confusion if not explicitly distinguished.
2. Some scripts default to cloud/legacy URLs and should be overridden per environment.
3. Optional integrations (SIEM/LLM/sandbox/sensors) may be absent; core workflows should degrade gracefully.
4. Auxiliary services should not be treated as primary backend authority.

---

## Canonical docs in this repo

For code-evidenced platform assessments and contracts, see:

- `memory/PRD.md`
- `memory/RUN_MODE_CONTRACT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`

These documents were updated to align with current code logic and runtime behavior.
