# Metatron Full Architecture Map

**Reviewed:** 2026-04-25  
**Scope:** Current repository architecture map, replacing stale March counts while preserving the high-level topology.

## 1) System Topology at a Glance

Core stack:

- React SPA: `frontend/`
- FastAPI backend: `backend/server.py`
- MongoDB primary store: `mongodb`

Core-adjacent and optional services in root Compose:

- Redis, Celery worker, Celery beat
- Elasticsearch, Kibana
- Ollama and model pull helper
- Volatility, Trivy, Falco, Suricata, Zeek
- Cuckoo Mongo, Cuckoo, Cuckoo Web
- WireGuard
- Nginx
- Admin bootstrap helper

Entry channels:

- Browser UI through `frontend/src/App.js`
- REST APIs under `/api/*` and selected `/api/v1/*`
- Raw WebSockets under `/ws/threats` and `/ws/agent/{agent_id}`
- Unified-agent control plane under `/api/unified/*`

## 2) Frontend Architecture

Core shell:

- Router: `frontend/src/App.js`
- Protected layout: `frontend/src/components/Layout`
- Auth context: `frontend/src/context/AuthContext.jsx`

Route organization:

- 67 route entries in `App.js`
- 43 page components imported by `App.js`
- Index route redirects to `/command`
- Historical paths redirect into workspaces where possible

Primary workspaces:

- Command operations: `/command`
- World model: `/world`
- AI activity: `/ai-activity`
- Investigation: `/investigation`
- Detection engineering: `/detection-engineering`
- Response operations: `/response-operations`
- Email security: `/email-security`
- Endpoint mobility: `/endpoint-mobility`
- Unified agent: `/unified-agent`

## 3) Backend Architecture

FastAPI entrypoint:

- `backend/server.py`
- 61 router modules under `backend/routers`
- 65 include-router calls in the server wiring
- Most routers mount under `/api`
- CSPM, identity, attack paths, secure boot, kernel sensors, and deception compatibility mounts require `/api/v1` awareness

Major router families:

- Core platform: auth, users, dashboard, settings, reports, websocket
- SOC analytics: threats, alerts, threat intel, hunting, correlation, timeline, audit
- Response: response, quarantine, SOAR, ransomware, honeypots, honey tokens, deception
- Endpoint/agent: agents, agent commands, swarm, unified agent
- Enterprise: enterprise, zero trust, multi-tenant, extension, identity, governance
- Advanced/security: advanced, AI analysis, AI threats, ML prediction, sandbox, EDR, containers, VPN, CSPM, attack paths, secure boot, kernel sensors
- Email/mobile: email protection, email gateway, mobile security, MDM connectors
- Triune/world: metatron, michael, loki, world ingest

## 4) Service Layer

Service families under `backend/services` include:

- AI/cognition: AATL, AATR, cognition engine, CCE worker, AI reasoning
- Governance: authority, context, executor, governed dispatch
- Enterprise controls: identity, policy engine, token broker, tool gateway, telemetry chain
- Operations: agent deployment, network discovery, SIEM, outbound gate
- Advanced services: MCP server, vector memory, VNS, quantum security
- Multi-tenant and threat hunting support

Top-level backend modules also provide core engines for threat intel, timeline, response, ransomware, containers, browser isolation, deception, CSPM, sandbox, ML, and identity protection.

## 5) Endpoint and Agent Architecture

Unified agent:

- Main file: `unified_agent/core/agent.py`
- Local APIs/UI: `unified_agent/server_api.py`, `unified_agent/ui/web/app.py`, `unified_agent/ui/desktop/main.py`
- Deployment helpers: `unified_agent/auto_deployment.py`

Monitor model:

- Config-gated process and network monitors
- Enterprise monitors: registry, process tree, LOLBin, code signing, DNS, memory, whitelist, DLP, vulnerability, YARA
- Platform/privilege-dependent monitors: AMSI, WebView2, kernel/rootkit/self-protection
- Response/telemetry monitors: ransomware, identity, auto-throttle, firewall, CLI telemetry, hidden file, alias/rename, privilege escalation
- Email/mobile monitors: email protection and mobile security

Backend first-class telemetry keys are defined in `MONITOR_TELEMETRY_KEYS` in `backend/routers/unified_agent.py`.

## 6) Data and Storage Architecture

Primary store:

- MongoDB database `seraph_ai_defense`
- Optional in-memory mongomock mode for tests/development via `MONGO_USE_MOCK` or `mongomock://`

Async/background:

- Redis and Celery for broker/result and scheduled/background work

Observability and search:

- Elasticsearch/Kibana local stack
- SIEM integration service hooks

Telemetry/evidence:

- Tamper-evident telemetry chain service
- Unified-agent audit recording
- Governance executor and approval/evidence flows

## 7) Runtime Flows

### Core SOC flow

1. Agents, integrations, and UI actions emit events into backend APIs.
2. Backend persists and correlates events in MongoDB and optional SIEM/search stores.
3. React workspaces render dashboards, investigations, detections, and response operations.
4. Analysts initiate actions through response/SOAR/unified-agent APIs.
5. Governance and dispatch services mediate high-impact actions where wired.

### Unified-agent flow

1. Agent registers at `/api/unified/agents/register`.
2. Agent heartbeats and telemetry keep backend state current.
3. Backend exposes fleet, command, download, installer, EDM, and monitor-specific routes.
4. Agent-side monitors scan locally and report findings.

### Optional integration flow

1. Integration-specific services expose status and data.
2. Backend routers consume those services when configured.
3. UI pages should show degraded status if services or credentials are missing.

## 8) Current Architectural Risk Focus

- Contract drift across backend, frontend, scripts, and docs.
- Central startup/import coupling in `backend/server.py`.
- Optional integration health visibility.
- Governance durability and high-risk action evidence.
- Production validation of SMTP, MDM, CSPM, sandbox, VPN, and model integrations.
- Browser isolation depth vs product claims.
- Detection quality measurement and suppression governance.

## 9) Accurate Summary

The architecture is a broad adaptive defense fabric: core SOC, unified-agent control, AI/triune intelligence, governance, email/mobile/MDM, cloud/security tooling, and optional deployment profiles all exist in code. The most accurate architectural statement is **large implemented surface with conditional integrations and a strong need for generated contracts, explicit health semantics, and durable governance evidence**.
