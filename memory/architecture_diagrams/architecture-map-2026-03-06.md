# Metatron / Seraph Architecture Map

**Updated:** 2026-04-30  
**Scope:** Current repository topology and runtime code logic.

---

## 1. System Topology at a Glance

- Primary app stack: `frontend` (React) + `backend` (FastAPI) + `mongodb`.
- Default compose support stack: `redis`, `celery-worker`, `celery-beat`, `elasticsearch`, `kibana`, `ollama`, `wireguard`, `nginx`.
- Optional profile-gated services: Trivy, Falco, Suricata, Zeek, Cuckoo, and bootstrap/Ollama helper jobs.
- Web UI routes: `frontend/src/App.js` currently declares 68 routes, including workspace redirects.
- REST API: most routes under `/api/*`; selected routers expose native `/api/v1/*` paths.
- WebSockets: `/ws/threats` and `/ws/agent/{agent_id}`.
- Endpoint-agent control plane: `/api/unified/*` and related swarm/agent command routes.

---

## 2. Frontend Architecture

Core shell:

- Router and protected layout: `frontend/src/App.js`, `frontend/src/components/Layout.jsx`.
- Auth/session context: `frontend/src/context/AuthContext.jsx`.
- UI page inventory: 68 JSX page files under `frontend/src/pages`.

Routing model:

- `/login` is public.
- `/` is protected and redirects to `/command`.
- Legacy pages frequently redirect into workspace pages:
  - `/dashboard`, `/alerts`, `/threats`, `/command-center` -> `/command?...`
  - `/threat-intel`, `/correlation`, `/attack-paths` -> `/investigation?...`
  - `/quarantine`, `/response`, `/edr`, `/soar` -> `/response-operations?...`
  - `/email-protection`, `/email-gateway` -> `/email-security?tab=...`
  - `/mobile-security`, `/mdm` -> `/endpoint-mobility?tab=...`

Operational page groups:

- Command/SOC: command workspace, dashboard tab, threats, alerts.
- Investigation: threat intel, correlation, attack paths, timeline, audit, reports.
- Response operations: quarantine, response automation, EDR, SOAR.
- Endpoint/mobility: unified agent, swarm, mobile security, MDM connectors.
- Platform security: zero trust, CSPM, kernel sensors, secure boot, identity.
- Advanced/security services: sandbox, browser isolation, VPN, containers, deception, VNS alerts, Kibana, Zeek, osquery.

---

## 3. Backend Architecture

FastAPI entry point:

- `backend/server.py`
- Runs on port `8001`.
- Health endpoint: `GET /api/health`.
- API root: `GET /api/`.

Composition pattern:

- Initializes MongoDB/Motor or optional `mongomock-motor`.
- Sets database handles for shared services.
- Configures CORS from `CORS_ORIGINS`; production/strict mode rejects wildcard origins.
- Imports and registers a large router mesh.
- Starts background services for CCE, network discovery, agent deployment, AATL/AATR, integrations scheduler, and governance executor.

Major API domains:

- Core: auth, users, dashboard, settings, websocket, reports.
- SOC analytics: threats, alerts, threat intel, hunting, correlation, timeline, audit.
- Response: response, quarantine, SOAR, ransomware, honeypots, honey tokens, deception.
- Endpoint: agents, agent commands, swarm, unified agent.
- Enterprise: enterprise, zero trust, multi-tenant, extension, governance.
- Advanced: advanced services, AI analysis, AI threats, ML prediction, sandbox, EDR, containers, VPN, CSPM.
- Email and mobility: email protection, email gateway, mobile security, MDM connectors.
- Triune/governance: Metatron, Michael, Loki, world ingest.

Special router behavior:

- CSPM and identity have native `/api/v1/...` prefixes and are included without an additional `/api` prefix.
- Attack paths, secure boot, and kernel sensors are imported fail-open and registered only when imports succeed.
- Deception is mounted under both `/api` and `/api/v1` for compatibility.

---

## 4. Service and Security Layer

Key service families:

- Governance/control: policy engine, token broker, tool gateway, governance authority/executor/context.
- AI/security reasoning: AATL, AATR, cognition engine, AI reasoning, CCE worker.
- Threat/memory: MCP server, vector memory, VNS/VNS alerts, telemetry chain.
- Deployment/ops: agent deployment, network discovery, SIEM, multi-tenant services.

Core engine modules include:

- Threat response, threat correlation, threat timeline, threat intelligence.
- Ransomware protection, quarantine, container security, browser isolation, zero trust.
- Identity protection, CSPM engine, ML threat prediction, sandbox analysis, quantum security, deception engine.
- Email protection, email gateway, mobile security, MDM connectors.

---

## 5. Endpoint and Agent Implementations

Unified agent stack:

- Main endpoint runtime: `unified_agent/core/agent.py`.
- Local API/UI helpers: `unified_agent/server_api.py`, `unified_agent/ui/web/app.py`, `unified_agent/ui/desktop/main.py`.
- Deployment/diagnostics: `unified_agent/auto_deployment.py`, tests and integration parsers under `unified_agent/`.

Agent implementation model:

- The agent registers and heartbeats to `/api/unified/...`.
- Monitor families cover process, network, registry, LOLBins, DNS, memory, DLP, vulnerability, AMSI, ransomware, rootkit, kernel security, self-protection, endpoint identity, firewall, CLI telemetry, hidden files, privilege escalation, email protection, mobile security, and YARA.
- Runtime depth depends on OS, privileges, installed tools, and local policy.

---

## 6. Data and Storage Architecture

Primary data:

- MongoDB database `seraph_ai_defense` stores platform state, telemetry, users, control-plane records, and domain documents.

Async and queueing:

- Redis is configured as Celery broker/result backend in compose.
- Celery worker and beat containers run from the backend image.

Observability and SIEM:

- Elasticsearch and Kibana are present in default compose.
- External SIEM forwarding logic is available through backend services.

Service-local state to watch:

- Email gateway queues/quarantine state.
- MDM manager connector/device state.
- Some governance and execution queues.
- These should be reviewed before clustered or restart-sensitive deployments.

---

## 7. End-to-End Runtime Flows

Primary SOC flow:

1. Agents, integrations, and sensors send telemetry to backend APIs and websockets.
2. Backend persists, enriches, correlates, and exposes threats/alerts/events.
3. Frontend workspaces render command, investigation, response, and domain views.
4. Analysts or automation trigger response, SOAR, deployment, MDM, email, or governance actions.
5. Backend dispatches work through services, queues, external integrations, or agent control paths.

Email flow:

1. Email protection service analyzes authentication, URLs, attachments, impersonation, and DLP signals.
2. Email gateway service can parse/process messages through REST and gateway abstractions.
3. Workspace UI exposes protection and gateway tabs.
4. Production inline prevention requires MTA/SMTP relay wiring.

Mobility flow:

1. Mobile security service models devices, threats, app analyses, and compliance reports.
2. MDM connectors sync devices/policies and execute actions through platform-specific APIs.
3. Endpoint mobility workspace exposes mobile and MDM tabs.
4. Production device management requires MDM credentials and provider permissions.

---

## 8. Current Architectural Risk Focus

- Contract governance across `/api`, `/api/v1`, frontend workspaces, and scripts.
- Consistent auth/permission coverage across all router surfaces.
- Visible status for optional/fail-open routers and background services.
- Durable state for queues, governance, gateway, and connector managers.
- Integration-specific verification for SMTP, MDM, SIEM, cloud, sandbox, and security sensors.
- Deep health checks beyond static `/api/health`.
