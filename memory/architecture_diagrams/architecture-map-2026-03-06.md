# Metatron / Seraph Architecture Map

Updated: 2026-04-27

## 1. System topology

```text
Browser / Operator
        |
        v
React frontend (frontend/)
        |
        v
FastAPI backend (backend/server.py)
        |
        +--> MongoDB primary state
        +--> Redis / Celery worker plane
        +--> Unified agent control plane
        +--> Optional Elastic/Kibana/Ollama/WireGuard services
        +--> Optional security and sandbox profile services
```

Primary code anchors:

- Backend entrypoint: `backend/server.py`
- Frontend router: `frontend/src/App.js`
- Unified agent: `unified_agent/core/agent.py`
- Deployment topology: `docker-compose.yml`
- CAS sidecar bundle: `cas_shield_sentinel_bundle/`

## 2. Frontend architecture

The frontend is a React 19 / React Router 7 application with a protected layout and workspace-oriented navigation.

Current primary workspace pages include:

- `CommandWorkspacePage`
- `AIActivityWorkspacePage`
- `ResponseOperationsPage`
- `InvestigationWorkspacePage`
- `EmailSecurityWorkspacePage`
- `EndpointMobilityWorkspacePage`
- `DetectionEngineeringWorkspacePage`
- `WorldViewPage`

Several legacy feature paths now redirect into workspace tabs. Documentation should describe the feature surface and, where relevant, mention the workspace route that owns the UI.

## 3. Backend router mesh

`backend/server.py` mounts 61 router modules plus direct health/root websocket routes. API surfaces use:

- `/api/*` for most routers.
- `/api/v1/*` for selected security domains such as CSPM, attack paths, identity, kernel sensors, and compatibility paths.
- `/ws/*` for direct threat and agent websockets.

Major API domains:

- Core: auth, users, dashboard, settings, reports.
- SOC: threats, alerts, hunting, threat intel, correlation, timeline, audit.
- Response: response, quarantine, SOAR, ransomware, honeypots, honey tokens, deception.
- Endpoint: agents, agent commands, swarm, unified agent.
- Detection engineering: Sigma, Zeek, osquery, atomic validation, MITRE ATT&CK.
- Advanced: MCP, vector memory, VNS, quantum, AI reasoning, sandbox, ML, browser isolation.
- Governance/enterprise: zero trust, enterprise identity/policy/token/tool/telemetry, multi-tenant, CSPM, identity protection.
- Domain expansion: email protection, email gateway, mobile security, MDM connectors.
- Triune/world: Metatron, Michael, Loki, world ingestion, cognition orchestration.

## 4. Service layer

Important service families:

- AI-native detection: `aatl.py`, `aatr.py`, `cognition_engine.py`, `cce_worker.py`, `ai_reasoning.py`.
- Triune/world: `cognition_fabric.py`, `triune_orchestrator.py`, `world_model.py`, `world_events.py`, `backend/triune/*`.
- Governance: `identity.py`, `policy_engine.py`, `token_broker.py`, `tool_gateway.py`, `telemetry_chain.py`.
- Security operations: `agent_deployment.py`, `network_discovery.py`, `siem.py`, `mcp_server.py`, `quantum_security.py`.
- Response engines and scanners: root-level backend modules such as `threat_response.py`, `cspm_engine.py`, `browser_isolation.py`, `container_security.py`, `email_gateway.py`, `mdm_connectors.py`.

## 5. Data and storage

Primary state is MongoDB database `seraph_ai_defense`.

Redis is used for Celery broker/result backend in the current Compose topology. Elasticsearch/Kibana provide optional local SIEM/search visualization. Some services still keep process-local state for fast-moving queues, connector state, or fallback paths; these remain durability targets.

## 6. Unified agent plane

The agent plane includes:

- Cross-platform monitoring and response in `unified_agent/core/agent.py`.
- Local UI/API shells in `unified_agent/ui/*` and `unified_agent/server_api.py`.
- Installer/download endpoints from the backend unified-agent router.
- Legacy and helper installers in `scripts/`.
- Tests under `unified_agent/tests/` and backend unified-agent suites.

Agent flows:

1. Agent registers.
2. Agent heartbeats with telemetry and posture.
3. Backend queues commands or policy/config updates.
4. Agent polls/receives commands and reports results.
5. EDM and other specialized telemetry loop back into backend analytics.

## 7. Optional integration profiles

Default optional integrations:

- WireGuard
- Elasticsearch/Kibana
- Ollama
- Nginx/reverse proxy

Security profile:

- Trivy
- Falco
- Suricata
- Zeek
- Volatility helper

Sandbox profile:

- Cuckoo
- Cuckoo MongoDB
- Cuckoo web UI

These integrations should degrade explicitly when unavailable.

## 8. Adjacent CAS Shield sidecar

The repository also includes CAS Shield Sentinel, a sidecar reverse proxy for CAS authentication protection. It is separate from the main Seraph API/frontend stack and implements:

- PASS_THROUGH
- FRICTION
- TRAP_SINK
- Pebbles trace IDs
- Mystique adaptive knobs
- Stonewall escalation

It intentionally avoids credential harvesting and request-body storage.

## 9. Architectural risk focus

- Contract drift across backend routers, frontend workspaces, scripts, and docs.
- Durable state for governance, deployment, connector, and queue-like features.
- Accurate deployment success semantics.
- Optional integration state clarity in API and UI.
- Detection-quality measurement and false-positive governance.
