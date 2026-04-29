# Seraph AI Defense System - Product Requirements Document

Updated: 2026-04-29
Product posture: governed adaptive defense fabric.

## Product overview

Seraph AI / Metatron is a cybersecurity platform for defending against AI-assisted and autonomous attacks. It combines endpoint telemetry, SOC operations, detection engineering, world-state modeling, Triune cognition, and policy-governed response.

The product runtime loop is:

1. Endpoint agents, integrations, and ingestion routes submit telemetry and security events.
2. Backend services store and enrich signals in MongoDB and the world model.
3. Triune cognition assesses changed world state and proposes/challenges action.
4. Governance services gate high-impact outbound actions.
5. Operators review state and execute workflows through React workspaces.

## Primary users

- SOC analyst: triage, investigation, timeline, alerts, threats, reports.
- Security engineer: detection engineering, Sigma, Zeek, osquery, atomic validation, MITRE coverage.
- Incident responder: response operations, quarantine, SOAR, EDR, command workflows.
- Endpoint/platform operator: unified agent fleet, deployment, telemetry, EDM, mobile/MDM.
- Security architect/CISO: world state, governance, policy, run-mode, evidence, and coverage.

## Current product surfaces

### Backend control plane

- Entrypoint: `backend/server.py`.
- API root: `/api` for most routers.
- Health: `/api/health`.
- WebSockets: `/ws/threats`, `/ws/agent/{agent_id}`.
- Database: MongoDB by default; `MONGO_USE_MOCK`/`mongomock://` for in-memory development/testing.

### Unified agent

- Backend routes: `backend/routers/unified_agent.py` mounted at `/api/unified/*`.
- Agent runtime: `unified_agent/core/agent.py`.
- Major capabilities: register, heartbeat, telemetry, monitor summary, command dispatch, installers/downloads, deployment APIs, EDM datasets/rollouts/hit telemetry.

### World and Triune cognition

- World service: `backend/services/world_model.py`.
- Event trigger: `backend/services/world_events.py`.
- Orchestrator: `backend/services/triune_orchestrator.py`.
- Services: `backend/triune/metatron.py`, `michael.py`, `loki.py`.
- UI/API state: `backend/routers/metatron.py`, `frontend/src/pages/WorldViewPage.jsx`.

### Governance

- Outbound gate: `backend/services/outbound_gate.py`.
- Governed dispatch: `backend/services/governed_dispatch.py`.
- Policy engine: `backend/services/policy_engine.py`.
- Governance executor: `backend/services/governance_executor.py`.
- Telemetry chain: `backend/services/telemetry_chain.py`.

### Detection and MITRE

- MITRE coverage endpoint: `GET /api/mitre/coverage` in `backend/routers/mitre_attack.py`.
- Evidence script: `backend/scripts/mitre_coverage_evidence_report.py`.
- Detection routes include Sigma, Zeek, osquery, atomic validation, hunting, correlation, threat intelligence, and AI threat services.

### Frontend workspaces

- Router: `frontend/src/App.js`.
- Auth/API base: `frontend/src/context/AuthContext.jsx`.
- Default route: `/command`.
- Consolidated workspaces: command, world, AI activity, unified agent, investigation, detection engineering, response operations, email security, endpoint mobility.

## Requirements

### R1. Core run mode

The system must run with MongoDB, backend, and frontend. Optional services must not break core SOC operation when unavailable.

### R2. Authentication and API routing

The frontend must protect all operational routes and call the backend through a safe API base: configured `REACT_APP_BACKEND_URL` when valid, otherwise same-origin `/api`.

### R3. Agent lifecycle

Agents must register, heartbeat, report telemetry, receive commands, and expose enough monitor summaries for fleet and world-state views.

### R4. World-state reasoning

Security events should be projectable into entities, edges, trust state, hotspots, campaigns, and attack-path summaries. Triune cognition should produce explainable assessment, planning, and challenge outputs.

### R5. Governed response

High-impact actions must be policy-gated, auditable, and traceable from request through approval and execution outcome.

### R6. MITRE evidence

ATT&CK coverage claims must be generated from `/api/mitre/coverage` or its evidence script, not manually maintained static counts.

### R7. Run-mode transparency

Every operator-facing feature should distinguish live, degraded, demo, simulated, and unavailable states.

### R8. Deployment truth

Deployment success must ultimately mean verified installation plus subsequent heartbeat. Queueing or simulation is not production success.

## Non-goals for the next hardening cycle

- Adding broad new feature domains before governance and contract gates pass.
- Claiming full incumbent XDR parity without scale and assurance evidence.
- Treating seeded demo data as production telemetry.

## Acceptance criteria

1. Core stack starts and `/api/health` returns healthy.
2. Login and protected route flow work.
3. `/api/unified/agents` and agent heartbeat/register flows work with configured auth/token expectations.
4. `/api/metatron/state` and world/Triune flows work with ingested or projected world events.
5. `/api/mitre/coverage` returns a coverage response and evidence report script can generate artifacts.
6. Governed command routes produce traceable pending/approved/executed states.
7. UI indicates when data is demo, simulated, degraded, or live.

## Current product risk

The product has extensive implemented code. Its primary risk is trust ambiguity: operators must know whether data and actions are live, simulated, demo-seeded, or degraded. The near-term product mandate is to make that truth impossible to miss.
