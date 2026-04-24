# Metatron Architecture Map (Code-Evidence Refresh)

**Last reviewed:** 2026-04-24  
**Evidence basis:** `backend/server.py`, router modules, `frontend/src/App.js`, `unified_agent/*`, `docker-compose.yml`

---

## 1) Current topology at a glance

- **Primary runtime:** React frontend + FastAPI backend + MongoDB.
- **Default compose stack:** backend, frontend, mongodb, redis, celery worker/beat, elasticsearch, kibana, wireguard, nginx, plus optional security services.
- **Primary ingress surfaces:**
  - UI routes from `frontend/src/App.js`
  - REST APIs under `/api/*` and `/api/v1/*`
  - WebSockets under `/ws/*` and API-routed agent sockets behind nginx

---

## 2) Frontend architecture

Core shell:
- `frontend/src/App.js`
- `frontend/src/context/AuthContext.jsx`
- `frontend/src/components/Layout`

Routing model:
- Uses protected routes with auth context restoration.
- Current UX is workspace-centric (`/command`, `/investigation`, `/response-operations`, `/email-security`, `/endpoint-mobility`, etc.).
- Many legacy menu paths are now explicit redirects to workspace tabs (for compatibility).

Operational surface:
- The frontend page tree currently contains ~70 page modules (`frontend/src/pages`), but most user flows are consolidated into workspace pages.

---

## 3) Backend architecture

Entrypoint:
- `backend/server.py`

Backend composition pattern:
- Registers many routers under `/api` (e.g., auth, hunting, response, unified agent, email/mobile/MDM).
- Also mounts selected routers that already carry `/api/v1/*` prefixes (`cspm`, `identity`, `secure-boot`, `attack-paths`, `kernel`).

Security-relevant API domains:
- Identity/auth, enterprise controls, governance, telemetry chain.
- Detection/response: threats, hunting, correlation, timeline, quarantine, SOAR.
- Endpoint control: unified agent and swarm/agent commands.
- Cloud and posture: CSPM.
- Email/mobile domains: email protection, email gateway, mobile security, MDM connectors.

WebSocket endpoints in app:
- `/ws/threats`
- `/ws/agent/{agent_id}` (machine-token verified)

---

## 4) Authentication and trust controls

Evidence: `backend/routers/dependencies.py`, `backend/routers/auth.py`

- JWT bearer authentication (`HS256`) with runtime secret hardening:
  - production/strict mode refuses weak or missing `JWT_SECRET`.
- Role/permission model (`admin`, `analyst`, `viewer`).
- Optional **remote admin gate**:
  - non-local access can be limited to admins or allowlisted admin emails.
- Machine-token auth helpers exist for internal and websocket channels.

---

## 5) Unified agent control-plane architecture

Evidence: `backend/routers/unified_agent.py`, `unified_agent/core/agent.py`

- API prefix: `/api/unified/*` (router prefix `/unified` + server `/api` include).
- Implements:
  - agent enrollment/registration and heartbeat
  - command dispatch and command result lifecycle
  - monitor summaries and alert surfaces
  - installer/bootstrap endpoints
  - EDM dataset versioning/rollout/rollback control plane
- Agent auth supports enrollment key and per-agent token checks.

Important nuance:
- `unified_agent/server_api.py` is an optional sidecar/local API with in-memory stores and proxy behavior; it is not the authoritative persistence plane used by the main backend stack.

---

## 6) Domain capability map (architecture-level)

- **Email security**
  - `/api/email-protection/*` for content/authentication analysis and quarantine workflows.
  - `/api/email-gateway/*` for gateway-style processing, quarantine, policy, block/allow list management.
- **Mobile security**
  - `/api/mobile-security/*` for device registration, posture updates, app analysis, compliance/threat lifecycle.
- **MDM management**
  - `/api/mdm/*` for connector lifecycle, sync, device actions, and policy/device views.
- **CSPM**
  - `/api/v1/cspm/*` with authenticated scan start, provider config, findings/resources/compliance/dashboards.
  - Includes a demo-seed and demo-scan path when providers are not configured.

---

## 7) Data and durability model

- Primary persistence: MongoDB collections per domain (users, agents, CSPM scan/findings, telemetry, etc.).
- Many services contain graceful fallback behavior for missing optional dependencies.
- Several domains maintain in-memory state for convenience and dev usability (not full HA semantics).

---

## 8) Runtime flow summary

1. Agents/sensors feed telemetry and heartbeat to backend APIs.
2. Backend domain services correlate and persist operational/security state.
3. Frontend workspaces query backend APIs for SOC workflows.
4. Analysts trigger commands/remediation through governed APIs.
5. Outcome and audit signals propagate through event/telemetry services.

---

## 9) Architectural risks and active constraints

- Centralized `server.py` wiring remains dense.
- Capability breadth exceeds fully uniform assurance depth.
- Some integrations intentionally support mock/demo fallback paths.
- Contract stability must keep pace with high route and UI breadth.
