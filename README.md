# Metatron / Seraph AI Defense Platform

Metatron / Seraph is a governed adaptive cyber-defense platform. It combines a FastAPI control plane, React operator workspaces, a cross-platform unified endpoint agent, a world model, Triune reasoning services, governed response dispatch, and MITRE/detection engineering workflows.

## What is implemented

The current repository is organized around these runtime paths:

| Area | Source |
|---|---|
| Main API app | `backend/server.py` |
| React UI routes | `frontend/src/App.js` |
| Auth/API base | `frontend/src/context/AuthContext.jsx` |
| Unified agent API | `backend/routers/unified_agent.py` mounted under `/api/unified/*` |
| Endpoint agent | `unified_agent/core/agent.py` |
| World/Triune logic | `backend/services/world_model.py`, `world_events.py`, `triune_orchestrator.py`, `backend/triune/*` |
| Governance | `backend/services/outbound_gate.py`, `governed_dispatch.py`, `governance_executor.py`, `policy_engine.py`, `telemetry_chain.py` |
| MITRE coverage | `backend/routers/mitre_attack.py` at `GET /api/mitre/coverage` |
| Integrations | `backend/integrations_manager.py`, `backend/routers/integrations.py`, `unified_agent/integrations/*` |

## Architecture at a glance

```text
React operator workspaces
        |
        v
FastAPI backend (/api)
        |
        +--> MongoDB platform state
        +--> Unified agent fleet control
        +--> Detection engineering and MITRE coverage
        +--> Integrations and optional security tools
        +--> World model
                 |
                 v
          Triune orchestrator
          Metatron -> Michael -> Loki
                 |
                 v
          Governed dispatch / policy gate
                 |
                 v
          Approved agent or response action
```

## Core components

### Backend

`backend/server.py` builds the FastAPI app, loads environment settings, connects to MongoDB, applies CORS policy, initializes domain services, registers routers under `/api`, and starts background workers/schedulers such as CCE, network discovery, deployment, AATL/AATR, integrations, and governance executor.

Health endpoint:

```bash
curl -fsS http://localhost:8001/api/health
```

### Frontend

`frontend/src/App.js` defines protected React routes. The default route is `/command`. Older feature routes redirect into consolidated workspaces:

- `/command`
- `/world`
- `/ai-activity`
- `/unified-agent`
- `/investigation`
- `/detection-engineering`
- `/response-operations`
- `/email-security`
- `/endpoint-mobility`

The frontend uses `REACT_APP_BACKEND_URL` when safely configured and otherwise falls back to same-origin `/api`.

### Unified agent

The endpoint agent in `unified_agent/core/agent.py` registers with `/api/unified/agents/register`, heartbeats to `/api/unified/agents/{agent_id}/heartbeat`, reports telemetry and monitor summaries, participates in EDM workflows, and can receive governed commands.

### World model and Triune cognition

World events can update entities, edges, hotspots, campaigns, trust state, and attack-path summaries. `TriuneOrchestrator.handle_world_change()` builds a snapshot, adds cognition-fabric signals, asks Metatron to assess state, asks Michael to plan actions, and asks Loki to challenge the plan.

### Governed response

High-impact response is designed to move through policy and audit layers instead of direct execution:

1. request command/action,
2. queue through governed dispatch/outbound gate,
3. evaluate policy/approval tier,
4. record tamper-evident telemetry,
5. execute approved decisions through governance executor.

### MITRE coverage

Use `GET /api/mitre/coverage` as the source of truth for ATT&CK coverage reporting. The evidence script can generate report artifacts:

```bash
python backend/scripts/mitre_coverage_evidence_report.py
```

## Run modes

Required core services:

- MongoDB
- backend
- frontend

Optional integrations include WireGuard, Elasticsearch, Kibana, Ollama, Trivy, Falco, Suricata, Cuckoo, SMTP, MDM platforms, SIEMs, and external security tools. Optional features may run live, degraded, demo, simulated, or unavailable depending on configuration.

Important environment flags and settings include:

- `MONGO_URL`
- `DB_NAME`
- `MONGO_USE_MOCK`
- `CORS_ORIGINS`
- `ENVIRONMENT`
- `SERAPH_STRICT_SECURITY`
- `INTEGRATION_API_KEY`
- `REACT_APP_BACKEND_URL`
- `ALLOW_SIMULATED_DEPLOYMENTS`
- `MCP_ALLOW_SIMULATED_EXECUTION`

## Local development

A typical local workflow is:

```bash
# Backend dependencies and app
cd backend
python -m uvicorn server:app --host 0.0.0.0 --port 8001 --reload

# Frontend
cd frontend
npm install
npm start
```

For Docker-based operation, use the repository compose files for the services you need, then validate the backend health endpoint and open the frontend.

## Validation

Useful validation entry points:

```bash
# Backend tests
pytest backend/tests

# Unified agent tests
pytest unified_agent/tests

# Feature/API smoke validation
python full_feature_test.py

# MITRE coverage evidence
python backend/scripts/mitre_coverage_evidence_report.py
```

Some scripts expect a running backend at `http://localhost:8001` or a configured base URL. Check each script's environment variables before using it as release evidence.

## Documentation map

- `memory/FEATURE_REALITY_REPORT.md` - current implementation reality narrative.
- `memory/FEATURE_REALITY_MATRIX.md` - domain-by-domain reality matrix.
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - critical architecture/security evaluation.
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - updated system-wide assessment.
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security feature evidence review.
- `memory/RUN_MODE_CONTRACT.md` - required vs optional services and live/degraded/demo/simulated semantics.
- `memory/architecture_diagrams/architecture-map-2026-03-06.md` - current architecture map.

## Current engineering priorities

1. Persist governance decisions, approvals, dispatch state, executor outcomes, and token/audit use.
2. Add contract snapshots and CI checks for backend/frontend/agent payloads.
3. Label demo and simulated paths clearly in APIs and UI.
4. Tie deployment success to install evidence and heartbeat verification.
5. Use `/api/mitre/coverage` and evidence scripts for ATT&CK claims.
6. Expand denial-path tests for auth, machine tokens, governance, and admin actions.

## Positioning

Metatron / Seraph should be understood as a governed adaptive defense fabric in active hardening. Its differentiation is the combination of unified endpoint telemetry, world-state reasoning, Triune cognition, and policy-governed response. Its maturity depends on making those flows durable, measurable, and explicit about run mode.
