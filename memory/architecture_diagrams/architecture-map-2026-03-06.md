# Metatron / Seraph Architecture Map

**Reviewed:** 2026-05-01
**Purpose:** Current implementation map for the full product stack.

## 1) Topology at a glance

- **Primary product stack:** React frontend, FastAPI backend, MongoDB.
- **Background/runtime stack:** Redis, Celery worker, Celery beat, optional SIEM/security services.
- **Endpoint stack:** unified endpoint agent plus local agent APIs/UIs and integrations.
- **API shape:** most product APIs are mounted under `/api`; selected routers carry `/api/v1`; WebSockets are exposed under `/ws/*`.
- **Ports in main compose:** backend `8001`, frontend `3000`, MongoDB `27017`, Redis `6379`, WireGuard `51820/udp`.

## 2) Repository planes

| Plane | Current code | Role |
| --- | --- | --- |
| Presentation | `frontend/src/App.js`, `frontend/src/pages/`, `frontend/src/components/` | SOC dashboard, workspace pages, protected shell, route redirects, component primitives. |
| Product API | `backend/server.py`, `backend/routers/` | Canonical FastAPI control plane with 62 router modules. |
| Services | `backend/services/`, root backend service modules | Domain engines, governance, dispatch, SIEM, CCE, network discovery, deployment, world model, triune intelligence. |
| Endpoint | `unified_agent/core/agent.py` | Cross-platform endpoint sensor/control runtime and monitor modules. |
| Agent local surfaces | `unified_agent/server_api.py`, `unified_agent/ui/` | Local FastAPI, Flask dashboard, desktop tray, and native mobile/macOS shells. |
| Integrations | `unified_agent/integrations/`, `backend/routers/integrations.py` | Tool wrappers/parsers and backend integration APIs. |
| Validation | `backend/tests/`, `unified_agent/tests/`, `backend/scripts/`, `test_reports/` | Unit, integration, smoke, e2e, MITRE, parity, and evidence artifacts. |

## 3) Frontend architecture

The React application uses a protected `Layout` shell and routes declared in `frontend/src/App.js`.

Key route groups:

- **Command and SOC:** `/command`, `/world`, `/ai-activity`, `/investigation`, `/detection-engineering`, `/response-operations`.
- **Endpoint operations:** canonical `/unified-agent`; legacy `/agents`, `/swarm`, and `/agent-commands*` redirect there.
- **Email and mobility:** canonical workspace routes `/email-security` and `/endpoint-mobility`; older direct routes redirect to workspace tabs.
- **Security domains:** network, hunting, honeypots, reports, timeline, audit, settings, Zeek, osquery, ransomware, containers, VPN, zero trust, sandbox, browser isolation, Kibana, CSPM, deception, kernel sensors, secure boot, identity.

API base logic is centralized in `frontend/src/lib/api.js`:

- use `${REACT_APP_BACKEND_URL}/api` when a valid backend URL is provided;
- otherwise use same-origin `/api`.

## 4) Backend architecture

`backend/server.py` is the canonical backend entrypoint. It:

- initializes MongoDB via `MONGO_URL` and `DB_NAME`;
- supports `MONGO_USE_MOCK` / `mongomock://` for in-memory testing;
- configures strict CORS behavior for production/strict mode;
- seeds and wires service databases;
- mounts the router mesh;
- starts background workers and exposes health/root routes.

Router families include:

- **Core:** auth, users, dashboard, settings, websocket, reports.
- **SOC/analytics:** threats, alerts, threat intel, hunting, correlation, timeline, audit, AI analysis, AI threats, ML prediction.
- **Response:** response, quarantine, SOAR, ransomware, deception, honeypots, honey tokens.
- **Endpoint/control:** agents, agent commands, swarm, unified agent.
- **Enterprise/governance:** enterprise, governance, zero trust, multi-tenant, extension.
- **Advanced/security:** advanced, EDR, containers, VPN, CSPM, attack paths, secure boot, kernel sensors, identity, sandbox, browser isolation, Zeek, osquery, Sigma, MITRE, atomic validation.
- **Domain expansion:** email protection, email gateway, mobile security, MDM connectors.
- **Triune/world:** metatron, michael, loki, world ingest.

## 5) Unified agent architecture

`unified_agent/core/agent.py` is the primary endpoint behavior source. It contains:

- platform setup and local data/quarantine paths;
- trusted AI/developer process allowlists;
- monitor modules for process, network, registry, DNS, code signing, DLP/EDM, ransomware, rootkit/kernel, identity, CLI telemetry, email protection, mobile security, and related signals;
- local governance/remediation helpers;
- SIEM/VNS/MCP-style execution hooks;
- heartbeat, telemetry, and command behavior for central control-plane interaction.

`backend/routers/unified_agent.py` is the server-side control plane under `/api/unified/*`. It manages:

- agent registration and heartbeat;
- fleet listing, details, alerts, commands, and dashboards;
- monitor summary normalization through `MONITOR_TELEMETRY_KEYS`;
- EDM datasets, signatures, staged rollout, rollback, readiness, and hit telemetry;
- deployment and installer/download endpoints;
- world-state projection and triune event emission.

## 6) Data and event flows

### Core SOC flow

1. Agents, integrations, scanners, and user actions create telemetry or requests.
2. Backend routers persist state in MongoDB and call domain services.
3. Domain services correlate, enrich, score, and emit audit/world events.
4. Frontend workspace pages query `/api` and display operational state.
5. Operators trigger response/SOAR/deployment commands.
6. Backend queues, governs, dispatches, and audits the result.

### Unified agent flow

1. Agent registers at `/api/unified/agents/register`.
2. Agent sends heartbeat and telemetry, including monitor summaries.
3. Backend projects agent status into world entities and records audit/events.
4. Operators issue commands through `/api/unified/*` or related control routes.
5. Agent retrieves or receives commands and reports outcomes.

### EDM/DLP flow

1. Backend stores EDM datasets, metadata, signatures, and rollout state.
2. Rollout moves through staged cohorts with readiness checks.
3. Agent-side EDM matching reports hits back to `/api/unified/*`.
4. Backend evaluates telemetry, anomalies, and rollback conditions.

### Email/mobile flow

1. Email protection and gateway routers expose message analysis, quarantine, blocklist/allowlist, policy, and stats surfaces.
2. Mobile security and MDM routers expose devices, compliance, threats, connectors, sync, policies, and remote actions.
3. Workspace UI pages route these domains through `/email-security` and `/endpoint-mobility`.

## 7) Deployment/runtime model

Core healthy mode:

```bash
docker compose up -d mongodb redis backend frontend
```

Full default mode:

```bash
docker compose up -d
```

Profile-gated modes:

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

Optional integrations should degrade explicitly without breaking the core dashboard.

## 8) Current architectural risks

- `backend/server.py` remains a dense integration point.
- The number of routers and pages makes contract drift a persistent risk.
- Governance-sensitive state needs durable restart/scale semantics where still in memory.
- Secondary and legacy entrypoints require hardening parity with the main backend.
- External integrations depend on local credentials, services, and host capabilities.
- Security-critical denial paths need deeper automated regression coverage.

## 9) Current architecture summary

The implementation is no longer a narrow EDR prototype. It is a broad, modular cyber-defense platform with a canonical FastAPI control plane, workspace-oriented React UI, endpoint agent, EDM/DLP governance, AI-agentic detection, triune/world-model intelligence, email/mobile/MDM domains, and optional local security integrations. The main engineering emphasis should be contract assurance, runtime determinism, durable governance, and hardening consistency.
