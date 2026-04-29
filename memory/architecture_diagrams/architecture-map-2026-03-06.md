# Metatron Architecture Map

**Rebaselined:** 2026-04-29

## 1) Topology at a Glance

- **Frontend:** React application in `frontend/`, mounted by `frontend/src/index.js` and routed by `frontend/src/App.js`.
- **Backend:** FastAPI application in `backend/server.py`, backed by MongoDB through Motor or an optional mongomock test backend.
- **Optional runtime services:** Redis/Celery, WireGuard, Elasticsearch, Kibana, Ollama, Falco/Suricata/Trivy, and sandbox tooling depending on compose profiles and environment.
- **Local/agent plane:** `unified_agent/` provides an endpoint agent, a local FastAPI proxy/control API, and desktop UI utilities.
- **Sidecar plane:** `cas_shield_sidecar.py` is the runnable top-level sidecar; bundled/demo variants live under `cas_shield_sentinel_bundle/`.

## 2) Entry Channels

- Protected React routes under the SPA.
- REST APIs under `/api/*` plus selected `/api/v1/*` routers.
- WebSockets at `/ws/threats` and `/ws/agent/{agent_id}`.
- Machine ingestion at `/api/ingest/entity`, `/api/ingest/edge`, `/api/ingest/detection`, `/api/ingest/alert`, and `/api/ingest/policy-violation`.

## 3) Frontend Architecture

The current UI is workspace-oriented:

- `CommandWorkspacePage`: dashboard, command center, alerts, threats.
- `WorldViewPage`: world state, graph, events.
- `AIActivityWorkspacePage`: AI signals, intelligence, CLI sessions.
- `InvestigationWorkspacePage`: threat intel, correlation, attack paths.
- `DetectionEngineeringWorkspacePage`: Sigma, MITRE, atomic validation.
- `ResponseOperationsPage`: automation, EDR, SOAR, quarantine.
- `EmailSecurityWorkspacePage`: email protection and email gateway.
- `EndpointMobilityWorkspacePage`: mobile security and MDM connectors.

Legacy URLs redirect into these workspaces for compatibility.

## 4) Backend Router Mesh

`backend/server.py` imports and registers router modules for auth, users, threats, alerts, AI analysis, dashboard, network, hunting, honeypots, reports, agents, quarantine, settings, response, audit, timeline, websocket, OpenClaw, threat intel, integrations, ransomware, containers, VPN, correlation, EDR, SOAR, honey tokens, zero trust, ML prediction, sandbox, browser isolation, Kibana, Sigma, Zeek, osquery, atomic validation, MITRE coverage, extension, multi-tenant, attack paths, secure boot, kernel sensors, agent commands, CLI events, deception, swarm, AI threats, enterprise, CSPM, advanced services, triune services, unified agent, world ingest, email protection, mobile security, email gateway, MDM connectors, identity, and governance.

## 5) Service Layer

Key implemented service families:

- **Governance:** outbound gate, governed dispatch, governance authority, governance executor, governance context.
- **World model:** entity/edge/event services plus triune metadata emission.
- **Policy/token/tool controls:** policy engine, token broker, tool gateway, boundary control.
- **AI/security reasoning:** AATL, AATR, cognition engine/fabric, AI reasoning, CCE worker.
- **Memory and telemetry:** vector memory, VNS/VNS alerts, telemetry chain.
- **Operations:** agent deployment, network discovery, SIEM integration, sandbox, quantum security.

## 6) Data Architecture

MongoDB is the primary system of record. Governance paths use collections including `triune_decisions`, `triune_outbound_queue`, `policy_decisions`, and `agent_commands`. The world model stores entities, edges, detections, alerts, and policy-violation-derived events. Vector memory is currently in-process and exposed through advanced routes. The unified-agent local API also uses in-memory dictionaries for its local service state.

## 7) Runtime Flow

1. Agents, integrations, or operators send telemetry/API actions to the backend.
2. World-model and domain services persist/enrich state in MongoDB.
3. Frontend workspaces render the latest API state.
4. High-impact commands are queued through outbound governance gates.
5. Approvals/denials update governance records and associated agent commands.
6. The governance executor processes approved decisions when enabled.

## 8) Architectural Risk Focus

- Central wiring density in `backend/server.py`.
- Mixed frontend API base patterns.
- Optional integration degradation semantics.
- Durability and scale semantics for governance and local-agent memory surfaces.
- Documentation drift from fast-moving implementation.
