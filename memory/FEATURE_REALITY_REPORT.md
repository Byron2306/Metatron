# Feature Reality Report

Generated: 2026-04-26
Scope: Qualitative code-evidence summary of the current repository.

This report replaces the older v6.7 feature-promotion narrative with a current
implementation summary. The platform is broad and operationally ambitious, but
the most important change in the current branch is the shift toward a canonical
world-model, triune governance, and governed outbound action flow.

## Executive verdict

Metatron/Seraph is a FastAPI + React + unified endpoint-agent platform with real
control-plane breadth across SOC workflows, endpoint telemetry, response,
advanced services, email/mobile security, and governance. The current codebase
shows materially implemented logic in many domains, while some integrations
remain framework-level or dependent on credentials, external services, and
environment-specific prerequisites.

The most accurate positioning is:

- Strong adaptive security control plane and dashboard.
- Strong unified-agent surface and local monitor breadth.
- Real triune/world-event/governance logic for strategic recomputation and
  high-impact action approval.
- Partial enterprise-production maturity because deployment truth, connector
  credentials, remote browser isolation, and assurance automation remain
  conditional or incomplete.

## Current runtime shape

### Backend

`backend/server.py` is the main FastAPI entrypoint. It:

- creates the app and CORS policy;
- connects MongoDB through Motor, with test/degraded support in surrounding
  dependencies;
- initializes world model and triune services;
- mounts the router mesh under `/api` plus selected `/api/v1` native routers;
- exposes `/api/health`;
- exposes WebSockets for threat and agent realtime flows.

The router mesh includes core SOC routes, response/quarantine/SOAR,
unified-agent and swarm routes, email/mobile/MDM routes, CSPM, advanced services,
triune services, world ingest, governance, and identity.

### Frontend

`frontend/src/App.js` is a React 19 + React Router application protected by
`AuthProvider`. The current route design consolidates older feature pages into
workspace views:

- `/command` for dashboard, alerts, threats, and command-center views.
- `/ai-activity` for AI signal and session-oriented views.
- `/investigation` for threat intel, correlation, and attack paths.
- `/response-operations` for response, EDR, SOAR, and quarantine.
- `/email-security` for email protection and gateway.
- `/endpoint-mobility` for mobile security and MDM.
- `/unified-agent` for agent, command, and swarm operations.
- Direct pages remain for world view, advanced services, zero trust, CSPM,
  reports, network, settings, VPN, containers, sandbox, kernel sensors, secure
  boot, deception, tenants, and related specialist views.

### Unified agent

`unified_agent/core/agent.py` is the main endpoint agent implementation. It
contains a large monitor catalog, including process, network, registry,
process-tree, LOLBin, code-signing, DNS, memory, application whitelist, DLP,
vulnerability, AMSI, ransomware, rootkit, kernel security, self-protection,
endpoint identity, auto-throttle, firewall, WebView2, CLI telemetry, hidden
file, alias/rename, privilege escalation, email protection, mobile security, and
YARA monitors.

Agent-side UI and support services include:

- Tk desktop UI: `unified_agent/ui/desktop/main.py`
- Flask local web UI: `unified_agent/ui/web/app.py`
- standalone FastAPI compatibility service: `unified_agent/server_api.py`
- integration parsers under `unified_agent/integrations/`

## Current strategic logic

### World event flow

Routers and services call `emit_world_event` in
`backend/services/world_events.py`. The helper:

1. classifies events as passive facts, local reflexes, strategic recomputes, or
   action-critical recomputes;
2. persists a canonical `world_events` document when a database is available;
3. decides whether triune recomputation should run;
4. invokes `TriuneOrchestrator.handle_world_change` when needed.

This means strategic detections, threat/campaign/risk/beacon signals, and
action-critical governance events can drive recomputation, while heartbeat and
local telemetry events can remain lower-cost reflex updates.

### Triune pipeline

`backend/services/triune_orchestrator.py` is the central pipeline:

1. builds a world snapshot from selected entities, hotspots, graph metrics,
   edges, campaigns, recent world events, active responses, trust state, and
   sector risk;
2. enriches it with `CognitionFabricService`;
3. asks Metatron to assess strategic pressure and policy tier;
4. asks Michael to rank candidate actions;
5. asks Loki to challenge the plan with hypotheses, hunts, deception ideas, and
   uncertainty markers;
6. optionally applies beacon-cascade logic;
7. returns a bundle with world snapshot, Metatron, Michael, Loki, and cascade
   sections.

Metatron is not only a stub: `backend/triune/metatron.py` calculates strategic
pressure from hotspot risk, sector risk, active responses, and cognitive
pressure, then maps that pressure to low/medium/high/critical policy tiers.

Michael ranks responses with explainable heuristics: action keywords,
entity risk, recency, and graph degree. It can call optional AI reasoning for
candidate explanations when available.

Loki generates dissent and adversarial-review output from the same cognitive
snapshot, including alternative hypotheses, hunt suggestions, deception
suggestions, and uncertainty markers.

### Governance and outbound gate

`backend/services/outbound_gate.py` enforces a central queue for high-impact
actions. Mandatory high-impact action types include response execution,
blocking/unblocking, swarm commands, agent commands, cross-sector hardening,
quarantine restore/delete/agent actions, tool execution, and MCP tool execution.

The gate:

- normalizes impact level;
- forces mandatory action classes to high impact and triune review;
- inserts `triune_outbound_queue` and `triune_decisions` records;
- emits a world event that can trigger triune recomputation;
- returns queue and decision IDs.

`backend/services/governed_dispatch.py` uses this gate for agent command writes.
It stores commands as `gated_pending_approval` with decision metadata and
authority context before execution.

`backend/routers/governance.py` exposes pending decisions, approve, deny, and an
executor run-once endpoint. `backend/services/governance_executor.py` maps
approved decisions into executable domain actions such as agent commands, swarm
commands, response actions, quarantine operations, and tool dispatch.

## Domain notes

### Unified agent and EDM

The unified-agent backend router is large and materially implemented. It covers
registration, heartbeat, telemetry, command delivery, deployment artifacts,
EDM dataset governance, EDM hit telemetry, audit recording through the
tamper-evident telemetry service, and world-event emission.

EDM is a strong implemented area: dataset metadata, versioning, rollouts,
readiness behavior, and endpoint hit telemetry exist, but production confidence
still depends on deployment coverage and regression tests.

### Advanced services and memory

Vector/case memory lives in `backend/services/vector_memory.py`, not in the
repository `memory/` documentation folder. It defines namespaces, trust levels,
memory entries, incident cases, and semantic search/case-similarity primitives.

`backend/routers/advanced.py` exposes memory store, search, case creation,
similar-case search, and stats endpoints. These actions also emit world events
and audit actions.

The advanced router also hosts MCP, VNS, AI reasoning, and quantum-related
surfaces. Several advanced capabilities have real code paths but may degrade or
depend on optional services such as Ollama, external tool bindings, or configured
runtime handlers.

### Email, mobile, and MDM

Email protection, email gateway, mobile security, and MDM routers are mounted in
the backend and workspace routes exist in the frontend.

Evidence:

- `backend/email_protection.py`
- `backend/routers/email_protection.py`
- `backend/email_gateway.py`
- `backend/routers/email_gateway.py`
- `backend/mobile_security.py`
- `backend/routers/mobile_security.py`
- `backend/mdm_connectors.py`
- `backend/routers/mdm_connectors.py`
- `/email-security` and `/endpoint-mobility` workspace routes

Current reality:

- API and UI surfaces are present.
- Email gateway can process API-submitted messages and manage quarantine,
  blocklists, allowlists, policies, and stats.
- MDM connectors model Intune, JAMF, Workspace ONE, and Google Workspace flows.
- Production SMTP relay and production MDM sync require real environment
  credentials and network access.

### CSPM, identity, kernel, and browser isolation

CSPM has multi-cloud modules and API surfaces, with authentication enforcement
on sensitive scan paths. Identity protection, secure boot, kernel sensors, and
enhanced kernel security are present. Browser isolation implements URL analysis,
filtering, and sanitization-style controls, but full remote browser isolation
with pixel streaming is still limited.

## What is materially real

- FastAPI router mesh and React dashboard routes.
- Mongo-backed control-plane records for many flows.
- World events and triune recomputation.
- Governed outbound high-impact action queue.
- Unified-agent monitor catalog and backend control plane.
- EDM governance and telemetry loop-back.
- Vector/case memory primitives.
- Email/mobile/MDM API and workspace surfaces.
- Docker Compose stack for local bring-up with optional integrations.

## What remains conditional

- Production SMTP relay deployment and external email reputation feeds.
- Live MDM platform sync without credentials.
- Remote browser isolation beyond filtering/sanitization.
- Deployment success truth across heterogeneous SSH/WinRM endpoints.
- Optional AI reasoning quality without configured model services.
- Connector reliability for optional tools and integrations.
- CI-enforced contract assurance across the full router/frontend/script surface.

## Current bottom line

The platform is best described as a governed adaptive defense system in active
hardening. It has broad implemented functionality and a coherent emerging
architecture around world state, cognition, triune judgment, governed dispatch,
and endpoint telemetry. Production-readiness claims should be scoped to the
configured environment and should distinguish implemented APIs from externally
credentialed integrations.
