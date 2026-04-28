# Feature Reality Report

Updated: 2026-04-28
Source basis: direct repository review of `backend/server.py`, `backend/routers/`, `backend/services/`, `frontend/src/App.js`, `unified_agent/`, `docker-compose.yml`, and committed validation reports.

## Executive verdict

Metatron / Seraph is a broad, code-heavy security platform with a real FastAPI backend, React operations UI, unified endpoint agent, governance/Triune control plane, and many implemented domain services. The current repository is not a small prototype: the active backend has 61 router modules, the service layer has 32 modules, and the frontend has 63 React `*Page` files plus consolidated workspace pages.

The accurate current reading is: **feature breadth is high, integration plumbing is substantial, and operational maturity is mixed by domain**. Core SOC, unified-agent, governance, email/mobile, CSPM, response, deception, and integration surfaces are present in code. Production confidence still depends on configuration, external credentials, optional runtime services, live endpoints, and stronger contract/assurance gates.

## Current implementation map

| Area | Current code reality | Maturity interpretation |
|---|---|---|
| Backend API | `backend/server.py` creates the primary FastAPI app, uses MongoDB via Motor or optional mongomock, wires database handles into core engines, mounts most routers under `/api`, mounts selected `/api/v1` routers as-is, and exposes `/ws/threats` plus `/ws/agent/{agent_id}`. | Real and central, but dense startup wiring remains a reliability and maintainability risk. |
| Router mesh | 61 router modules in `backend/routers`, covering auth, dashboard, threats, alerts, audit, timeline, reports, agents, swarm, unified agent, integrations, governance, Triune, identity, CSPM, email, mobile, deception, response, SOAR, EDR, VPN, sandbox, browser isolation, MITRE, atomic validation, osquery, zeek, sigma, and more. | Broad and active; contract drift risk remains because many domains evolve independently. |
| Service layer | 32 modules in `backend/services`, including governance authority/executor/context, outbound/tool/token gates, telemetry chain, world model/events, cognition fabric, Triune orchestrator, vector memory, VNS, SIEM, AATL/AATR, CCE worker, network discovery, and deployment. | Real domain services exist; consistency and durability vary by service. |
| Triune/world model | `WorldModelService`, `MetatronService`, `MichaelService`, `LokiService`, `TriuneOrchestrator`, `CognitionFabricService`, and `emit_world_event` are wired into event and governance flows. | Coherent architecture is present; some paths are still best-effort or optional-service dependent. |
| Governance | `governance_authority`, `outbound_gate`, `governance_executor`, `governed_dispatch`, `token_broker`, `tool_gateway`, and `telemetry_chain` form the canonical approval/execution/audit chain for high-impact work. | Strong design direction; remaining work is uniform enforcement and persisted linkage across every path. |
| Unified agent | `unified_agent/core/agent.py` implements endpoint monitoring, telemetry, remediation proposals, local UI integration, and control-plane communication. Backend `/api/unified/*` supports registration, heartbeat, commands, deployment artifacts, monitor telemetry, EDM, downloads, and dashboards. | One of the strongest implemented areas; real endpoint value depends on OS privileges and deployment environment. |
| Frontend | CRA/Craco React app with `frontend/src/App.js` routing to command, world, AI activity, response, investigation, detection engineering, email security, endpoint mobility, unified agent, CSPM, identity, and standalone pages. | Active UI, recently consolidated around workspaces and redirects; some legacy pages/files remain. |
| Integrations | `backend/integrations_manager.py` supports runtime tools such as amass, arkime, bloodhound, spiderfoot, velociraptor, purplesharp, sigma, atomic, falco, yara, suricata, trivy, cuckoo, osquery, and zeek. Unified-agent clients and integration parsers exist. | Framework is real; many tools require installed binaries, credentials, logs, agents, or containers. |
| Deployment/run modes | Compose defines backend on 8001, frontend on 3000, MongoDB, Redis, Celery worker/beat, Elasticsearch/Kibana/Ollama, WireGuard, and optional security tooling. | Baseline stack is clear; optional-service degradation must be expected. |

## Feature maturity table

| Domain | Status | Evidence | Practical notes |
|---|---|---|---|
| Core SOC dashboard, threats, alerts, reports, audit, timeline | PASS/PARTIAL | `backend/routers/dashboard.py`, `threats.py`, `alerts.py`, `reports.py`, `audit.py`, `timeline.py`; command workspace UI | Core routes and pages exist; live quality depends on seeded or ingested telemetry. |
| Unified agent control plane | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Registration, heartbeat, commands, monitor summaries, downloads, and telemetry projection are implemented. |
| Governance/Triune execution | PASS/PARTIAL | `backend/services/governance_*`, `outbound_gate.py`, `tool_gateway.py`, `token_broker.py`, `triune_orchestrator.py` | Strong canonical path exists; remaining risk is bypass closure and uniform audit linkage. |
| Email protection and gateway | PASS/PARTIAL | `backend/email_protection.py`, `backend/email_gateway.py`, routers, email workspace routes | Framework and APIs exist; production relay/reputation behavior requires real SMTP/DNS/environment configuration. |
| Mobile security and MDM connectors | PASS/PARTIAL | `backend/mobile_security.py`, `backend/mdm_connectors.py`, routers, endpoint mobility workspace | Connector framework and APIs exist; real device sync/actions require platform credentials. |
| CSPM/cloud posture | PASS/PARTIAL | `backend/cspm_engine.py`, `backend/routers/cspm.py` | Multi-cloud posture logic exists; real findings require cloud credentials and provider access. |
| Identity protection | PASS/PARTIAL | `backend/identity_protection.py`, `backend/routers/identity.py` | Ingest, incidents, and controls exist; containment depends on identity provider integration. |
| EDR/endpoint monitors | PASS/PARTIAL | `backend/edr_service.py`, `unified_agent/core/agent.py` monitor families | Broad coverage; OS-specific and privilege-specific behavior varies. |
| Response/SOAR/quarantine | PASS/PARTIAL | `backend/threat_response.py`, `quarantine.py`, `soar_engine.py`, routers | Real workflow logic with external provider fallbacks; high-risk actions should remain governed. |
| Integrations/runtime tooling | PARTIAL | `backend/integrations_manager.py`, `unified_agent/integrations_client.py` | Succeeds when dependencies are installed and targets are available; otherwise degraded/failed job states are expected. |
| Browser isolation | LIMITED/PARTIAL | `backend/browser_isolation.py`, UI page | URL analysis/filtering exists; full remote pixel-stream browser isolation is not the current code reality. |
| Optional AI augmentation | PARTIAL | `backend/ai/`, `services/ai_reasoning.py`, Ollama settings | Rule-based or fallback paths exist; model-backed quality depends on configured model services. |

## Corrections from older review language

- Root README statistics claiming 41 routers, 21 services, and 41 pages were stale. Current file counts are 61 router modules, 32 service modules, and 63 React `*Page` files.
- `python3 smoke_test.py` is not a simple smoke-test script. The root `smoke_test.py` is a standalone FastAPI-style edge/proxy app, so validation guidance should point to `/api/health`, `full_feature_test.py`, targeted pytest suites, or backend validation scripts instead.
- `unified_agent/server_api.py` is a separate local/portal FastAPI app that still references legacy `server_old.py` language. The primary Compose/backend entry is `backend.server:app` on port 8001.
- Older docs used strong "enterprise ready" language. The safer current statement is "broad implementation with enterprise-oriented architecture; production readiness depends on credentials, hardening, durability, contract tests, and runtime validation."

## Priority reality actions

1. Keep `backend/server.py`, `frontend/src/App.js`, and route/contract docs synchronized automatically.
2. Build generated route inventories and schema snapshots for CI drift checks.
3. Preserve explicit degraded states for optional integrations instead of reporting simulated success as completion.
4. Continue closing governance bypasses and linking every high-impact action to decision, token, execution, audit, and world-event records.
5. Validate production claims with end-to-end tests using real SMTP, MDM, cloud, endpoint, and integration credentials where applicable.

## Bottom line

The platform has substantial real code across endpoint, SOC, AI/cognition, governance, cloud, email, mobile, and response domains. Its strongest current differentiator is breadth plus governed automation architecture. Its main engineering risk is not lack of modules; it is keeping contracts, runtime prerequisites, durability, and assurance depth aligned with the breadth already present.
