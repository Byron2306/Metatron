# Metatron Architecture Map

Updated: 2026-04-29

## System topology

Primary stack:

- React frontend: `frontend/src/App.js`
- FastAPI backend: `backend/server.py`
- MongoDB primary store
- Unified endpoint agent: `unified_agent/core/agent.py`

Optional stack:

- WireGuard, Elasticsearch, Kibana, Ollama
- Trivy, Falco, Suricata, Cuckoo/sandbox profiles
- External SMTP, MDM, SIEM, threat-intel, and integration tools

## Entry channels

| Channel | Path |
|---|---|
| Web UI | React routes in `frontend/src/App.js` |
| REST API | Most routes below `/api/*` |
| Threat WebSocket | `/ws/threats` |
| Agent WebSocket | `/ws/agent/{agent_id}` with machine-token verification |
| Unified agent API | `/api/unified/*` |
| World ingest | `/api/ingest/*` |
| MITRE coverage | `/api/mitre/coverage` |

## Backend layers

`backend/server.py` loads environment settings, creates Mongo or `mongomock`, sets shared database dependencies, initializes services, applies CORS, registers routers, and starts workers/schedulers/executors on startup.

Router families include auth, dashboard, settings, threats, alerts, threat intel, hunting, correlation, timeline, audit, response, quarantine, SOAR, ransomware, deception, unified agent, swarm, governance, zero trust, CSPM, VPN, containers, EDR, AI/advanced services, Sigma, Zeek, osquery, atomic validation, MITRE, email, mobile, MDM, identity, secure boot, and kernel sensors.

## World and Triune flow

```text
ingest/agent/integration event
        |
        v
backend/services/world_events.py
        |
        v
WorldModelService entities, edges, hotspots, campaigns
        |
        v
TriuneOrchestrator.handle_world_change()
        |
        +--> CognitionFabricService.build_cognition_snapshot()
        +--> MetatronService.assess_world_state()
        +--> MichaelService.plan_actions()
        +--> LokiService.challenge_plan()
        +--> beacon cascade / action context
```

UI state is exposed primarily through `backend/routers/metatron.py` and consumed by `WorldViewPage.jsx`.

## Governed action flow

```text
operator / triune / automation requests command
        |
        v
GovernedDispatchService
        |
        v
OutboundGateService + PolicyEngine
        |
        v
pending / approved decision with audit telemetry
        |
        v
GovernanceExecutorService
        |
        v
agent command, VPN/quarantine/domain operation, or other supported action
        |
        v
TelemetryChain records evidence
```

This flow is the safety boundary for high-impact automation.

## Unified agent flow

```text
UnifiedAgent endpoint runtime
        |
        +--> register: POST /api/unified/agents/register
        +--> heartbeat: POST /api/unified/agents/{id}/heartbeat
        +--> telemetry and monitor summaries
        +--> EDM hits and dataset refresh
        +--> local remediation primitives
        |
        v
backend/routers/unified_agent.py
        |
        +--> Mongo fleet state
        +--> world_entities projection
        +--> world event / Triune trigger when risk is elevated
        +--> governed command dispatch
```

## Frontend architecture

`frontend/src/App.js` uses protected routes and consolidated workspaces:

- `/command` for dashboard, threats, alerts, and command center.
- `/world` for Metatron/world state.
- `/ai-activity` for AI threat and cognition sessions.
- `/unified-agent` for fleet and command operations.
- `/investigation` for intel, correlation, and attack paths.
- `/detection-engineering` for Sigma, atomic validation, and MITRE.
- `/response-operations` for SOAR, EDR, quarantine, and response.
- `/email-security` for protection and gateway.
- `/endpoint-mobility` for mobile and MDM.

Legacy routes redirect into these workspaces.

## MITRE coverage architecture

`backend/routers/mitre_attack.py` exposes `GET /api/mitre/coverage`. It composes evidence from implemented detection families including Sigma, osquery, Zeek, atomic validation, threat intel, SIEM/EDR/YARA, deception, unified monitors, integrations, AI mapping, audit/world events, and roadmap targets.

## Data stores and evidence

- MongoDB stores platform state, telemetry, world model records, commands, decisions, and audit-relevant records.
- Elasticsearch/Kibana are optional observability/search surfaces.
- Test and evidence scripts under `backend/scripts/` generate validation artifacts in `test_reports/`.

## Main architectural risks

1. Dense backend startup and router wiring in `server.py`.
2. Durability of governance decisions and executor state.
3. Contract drift across backend, frontend, agent, scripts, and docs.
4. Explicit distinction between live, degraded, demo, and simulated modes.
5. Deployment success evidence and optional integration health.
