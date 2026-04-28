# Metatron Full Architecture Map

Updated: 2026-04-28
Source basis: direct repository review of `backend/server.py`, `backend/routers/`, `backend/services/`, `frontend/src/App.js`, `unified_agent/`, and `docker-compose.yml`.

## 1. System topology

Primary stack:

- `frontend`: CRA/Craco React operator UI on port 3000.
- `backend`: FastAPI app `backend.server:app` on port 8001.
- `mongodb`: primary platform data store.
- `redis`: broker/result backend for Celery and async work.
- Optional services: Elasticsearch, Kibana, Ollama, WireGuard, Celery worker/beat, and security/sandbox tooling.

Primary entry channels:

- Browser UI routes from `frontend/src/App.js`.
- REST APIs under `/api/*` and selected native `/api/v1/*` routers.
- Raw WebSockets under `/ws/threats` and `/ws/agent/{agent_id}`.
- Unified-agent control plane under `/api/unified/*`.
- Swarm/agent command control under `/api/swarm/*` and related agent-command routes.

## 2. Frontend architecture

Core shell:

- `frontend/src/App.js`: route source of truth.
- `frontend/src/components/Layout`: authenticated app layout.
- `frontend/src/context/AuthContext.jsx`: session/auth context.
- `frontend/src/lib/api.js`: API base resolution.

Workspace model:

- `/command`: main command workspace; `/dashboard`, `/alerts`, `/threats`, and `/command-center` redirect into this workspace.
- `/ai-activity`: AI detection, intelligence, and CLI session workspace.
- `/response-operations`: response, quarantine, EDR, and SOAR workspace.
- `/investigation`: threat intel, correlation, and attack-path investigation workspace.
- `/detection-engineering`: Sigma, atomic validation, and MITRE-oriented workspace.
- `/email-security`: email protection and gateway workspace.
- `/endpoint-mobility`: mobile security and MDM workspace.

Standalone page groups:

- World view: `/world`.
- Network and hunting: `/network`, `/hunting`, `/honeypots`.
- Operations/reporting: `/reports`, `/timeline`, `/audit`, `/settings`.
- Detection/integration: `/zeek`, `/osquery-fleet`, `/ml-prediction`, `/sandbox`, `/browser-isolation`, `/kibana`, `/advanced`, `/heatmap`, `/vns-alerts`.
- Endpoint/control: `/unified-agent`, `/vpn`, `/ransomware`, `/containers`.
- Enterprise/security: `/cspm`, `/deception`, `/kernel-sensors`, `/secure-boot`, `/identity`, `/zero-trust`, `/honey-tokens`, `/tenants`, `/browser-extension`, `/setup-guide`.

## 3. Backend architecture

`backend/server.py` performs:

1. Environment loading.
2. MongoDB/mongomock client setup.
3. Router dependency DB injection.
4. Engine DB injection for audit, timeline, threat intel, ransomware, containers, VPN, correlation, EDR, atomic validation, attack paths, zero trust, response, browser isolation, and CSPM.
5. World model and Triune service creation.
6. CORS configuration.
7. Router registration.
8. WebSocket registration.
9. Startup of background workers/services.
10. Graceful shutdown of workers and MongoDB client.

Router domains include:

- Core SOC: auth, users, dashboard, threats, alerts, hunting, reports, audit, timeline, websocket, settings.
- Endpoint/agents: agents, agent commands, swarm, unified agent, CLI events.
- AI/Triune/world: AI analysis, AI threats, Metatron, Michael, Loki, world ingest, advanced.
- Security operations: response, quarantine, SOAR, ransomware, deception, honey tokens, honeypots.
- Infrastructure/detection: network, integrations, VPN, containers, EDR, browser isolation, sandbox, Kibana, Sigma, Zeek, osquery, atomic validation, MITRE ATT&CK.
- Enterprise: governance, enterprise, multi-tenant, CSPM, identity, extension, attack paths, secure boot, kernel sensors, zero trust.
- Email/mobile: email protection, email gateway, mobile security, MDM connectors.

## 4. Service layer

Service families under `backend/services`:

- Governance/control: `governance_authority`, `governance_context`, `governance_executor`, `governed_dispatch`, `outbound_gate`, `policy_engine`, `token_broker`, `tool_gateway`.
- Cognition/AI: `aatl`, `aatr`, `cce_worker`, `cognition_engine`, `cognition_fabric`, `ai_reasoning`, `triune_orchestrator`.
- World/memory/telemetry: `world_model`, `world_events`, `telemetry_chain`, `vector_memory`, `vns`, `vns_alerts`, `mcp_server`.
- Operations: `agent_deployment`, `network_discovery`, `siem`, `multi_tenant`, `identity`, `cuckoo_sandbox`, `boundary_control`, `attack_metadata`, `quantum_security`.

## 5. Unified agent architecture

Endpoint runtime:

- `unified_agent/core/agent.py`: main endpoint agent and monitor orchestration.
- Monitor families cover process, network, registry, process tree, LOLBins, code signing, DNS, memory, allowlisting, DLP, vulnerabilities, YARA, AMSI, ransomware, rootkit, kernel security, self-protection, identity, auto-throttle, firewall, WebView2, CLI telemetry, hidden files, alias/rename, privilege escalation, email protection, mobile security, scanners, VPN, VNS, MCP gate, execution broker, remediation, and local UI hooks.

Local control surfaces:

- `unified_agent/ui/web/app.py`: Flask local dashboard, default local port 5000.
- `unified_agent/ui/desktop/main.py`: Tkinter desktop shell.
- `unified_agent/server_api.py`: separate local/portal FastAPI service; not the primary production backend.

Backend control plane:

- `/api/unified/agents/register`
- `/api/unified/agents/{agent_id}/heartbeat`
- `/api/unified/agents`
- `/api/unified/agents/{agent_id}/command`
- `/api/unified/agents/{agent_id}/commands/tooling/{tool_name}`
- `/api/unified/agents/{agent_id}/remediation/propose`
- monitor, deployment, EDM, stats, dashboard, installer, and download endpoints.

## 6. Data and storage

- MongoDB database name defaults to `seraph_ai_defense`.
- Redis supports Celery broker/result flows.
- Elasticsearch/Kibana are optional observability/search/dashboard integrations.
- File/log volumes support Falco, Suricata, Zeek, osquery, atomic validation, VPN, and integration workflows.
- World entities/events and tamper-evident telemetry provide cross-domain state and audit signals.

## 7. End-to-end flows

### SOC flow

1. Agents, sensors, integrations, or users create telemetry/events.
2. Backend routes normalize and persist records.
3. Threat intel, correlation, hunting, timeline, and AI/cognition services enrich state.
4. Frontend workspaces display investigation and response context.
5. Analyst or automation requests action.
6. Governance gates high-impact work.
7. Executor/tool/token path performs or queues execution.
8. Audit and world events close the loop.

### Unified-agent flow

1. Agent registers and heartbeats to `/api/unified/*`.
2. Monitor telemetry is summarized and projected into world entities.
3. Commands or tooling requests are queued through governed dispatch when impactful.
4. Agent polls/receives work and reports results.
5. Backend records telemetry, status, audit, and world feedback.

### Triune governance flow

`Intent -> World Event -> Cognition Fabric -> Metatron -> Michael -> Loki -> Policy/Governance Decision -> Outbound Gate -> Approval -> Executor -> Token/Tool Enforcement -> Audit + World Feedback`

## 8. Current architectural risk focus

- Generated route/schema inventories for contract control.
- Explicit preflight for optional integrations and run modes.
- Universal governance enforcement for high-impact actions.
- Distinguishing queued, simulated, degraded, failed, and verified-success states.
- Documentation alignment around the primary backend and current frontend workspaces.
