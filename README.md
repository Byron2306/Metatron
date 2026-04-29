# Metatron / Seraph AI Defense Platform

Metatron/Seraph is a FastAPI + React cybersecurity platform for SOC operations, endpoint/agent control, governed response automation, world-model security context, deception, cloud and identity posture, email/mobile protection, and optional AI-assisted investigation.

This README reflects the current code structure rather than older feature-count or marketing snapshots. Many security domains have concrete backend, frontend, and service code; production maturity still depends on runtime configuration, provider credentials, optional integrations, and governance/test coverage.

## Current Architecture

```text
React frontend
  frontend/src/App.js
  frontend/src/components/Layout.jsx
  frontend/src/context/AuthContext.jsx
        |
        | HTTP / WebSocket
        v
FastAPI backend
  backend/server.py
  backend/routers/*.py
  backend/services/*.py
        |
        v
MongoDB primary state

Optional runtime services: Redis/Celery, WireGuard, Elasticsearch, Kibana, Ollama, Falco, Suricata, Trivy, sandbox tooling, external cloud/email/MDM providers.

Endpoint/local plane:
  unified_agent/core/agent.py
  unified_agent/server_api.py
  unified_agent/ui/desktop/main.py
```

## Repository Map

| Path | Purpose |
|---|---|
| `backend/server.py` | Main FastAPI application, MongoDB wiring, router registration, startup/shutdown tasks, WebSockets. |
| `backend/routers/` | REST API domains for auth, SOC workflows, response, governance, world ingest, enterprise, CSPM, email, mobile, MDM, deception, and more. |
| `backend/services/` | Governance, world model, token/tool controls, AI/security reasoning, vector memory, deployment, telemetry, and operations services. |
| `frontend/src/App.js` | Protected React route shell and compatibility redirects. |
| `frontend/src/pages/` | Operator workspaces and feature dashboards. |
| `frontend/src/lib/api.js` | Preferred frontend API base URL helper. |
| `unified_agent/` | Endpoint agent, local API, integration notes, and desktop UI. |
| `memory/` | Rebaselined architecture, run-mode, feature reality, security, roadmap, and evaluation documents. |
| `test_reports/` | Historical validation and audit reports. |
| `cas_shield_sidecar.py` | Runnable top-level CAS shield sidecar implementation. |

## Runtime Requirements

### Required for baseline operation

- MongoDB
- Backend API
- Frontend UI

### Optional or degraded-mode integrations

- Redis/Celery for asynchronous workers.
- WireGuard for VPN workflows.
- Elasticsearch/Kibana for SIEM and dashboard integrations.
- Ollama or other model services for optional AI augmentation.
- Falco, Suricata, Trivy, Cuckoo/sandbox tooling, and other security tools when enabled.
- External provider credentials for cloud posture, email gateway, MDM, reputation, and live integration workflows.

Optional integrations should fail clearly as `unconfigured`, `degraded`, or `simulated` rather than blocking the core UI.

## Quick Start

### Minimal local stack

```bash
docker compose up -d mongodb backend frontend
```

### Fuller local stack

```bash
docker compose up -d mongodb redis backend frontend wireguard elasticsearch kibana ollama
```

### Optional profiles

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

### Basic checks

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health || curl -fsS http://localhost:8001/health
curl -fsS http://localhost:3000
```

If the repo-specific smoke test is available in your checkout, run:

```bash
python3 smoke_test.py
```

## Configuration Notes

Important environment variables include:

| Variable | Purpose |
|---|---|
| `MONGO_URL` | MongoDB connection string. Defaults to `mongodb://localhost:27017`. |
| `DB_NAME` | MongoDB database name. Defaults to `seraph_ai_defense`. |
| `MONGO_USE_MOCK` | Enables `mongomock-motor` for test-like environments. |
| `INTEGRATION_API_KEY` | Internal machine-to-machine token. Required in production. |
| `CORS_ORIGINS` | Comma-separated allowed frontend origins. Must be explicit in production/strict mode. |
| `ENVIRONMENT` | Environment name; `prod`/`production` enables stricter checks. |
| `SERAPH_STRICT_SECURITY` | Enables strict security checks outside production. |
| `GOVERNANCE_EXECUTOR_ENABLED` | Enables/disables the governance executor loop. |
| `GOVERNANCE_EXECUTOR_INTERVAL_SECONDS` | Executor polling interval. |
| `REACT_APP_BACKEND_URL` | Frontend build-time backend base URL. |

## Frontend Workspaces

The React app is authenticated by `AuthProvider`. `/login` is public; all other routes are protected and rendered inside `Layout`. `/` redirects to `/command`.

Primary workspaces:

| Route | Purpose |
|---|---|
| `/command` | Dashboard, command center, alerts, threats. |
| `/world` | Metatron/world-model overview, graph, events. |
| `/ai-activity` | AI detection signals, AI threat intelligence, CLI sessions. |
| `/investigation` | Threat intelligence, correlation, attack paths. |
| `/detection-engineering` | Sigma, MITRE coverage, atomic validation. |
| `/response-operations` | Response automation, EDR, SOAR, quarantine. |
| `/email-security` | Email protection and email gateway. |
| `/endpoint-mobility` | Mobile security and MDM connectors. |

Additional direct routes include network, hunting, honeypots, reports, timeline, audit, settings, Zeek, osquery fleet, ransomware, containers, VPN, honey tokens, zero trust, ML prediction, sandbox, browser isolation, Kibana, advanced services, heatmap, VNS alerts, browser extension, setup guide, tenants, unified agent, CSPM, deception, kernel sensors, secure boot, and identity.

Compatibility redirects preserve older URLs such as `/dashboard`, `/alerts`, `/threats`, `/agents`, `/swarm`, `/agent-commands`, `/edr`, `/soar`, `/quarantine`, `/email-gateway`, and `/mdm`.

## Backend API Surface

`backend/server.py` creates `FastAPI(title="Anti-AI Defense System API")`, configures MongoDB, injects the database into routers/services, configures CORS, and registers the API mesh. Most routers are mounted under `/api`; selected routers provide native `/api/v1` prefixes.

Major domains include:

- Auth, users, dashboard, settings, reports, audit, timeline.
- Threats, alerts, threat intelligence, hunting, correlation, MITRE, Sigma, atomic validation.
- Response, EDR, SOAR, quarantine, ransomware.
- Agents, agent commands, swarm, unified agent, CLI events.
- World ingest, Metatron/Michael/Loki triune services.
- Governance, enterprise controls, token/tool/policy services.
- CSPM, identity, zero trust, multi-tenant, browser extension.
- Email protection, email gateway, mobile security, MDM connectors.
- Deception, honeypots, honey tokens, browser isolation, sandbox, containers, VPN, Kibana, Zeek, osquery, kernel sensors, secure boot.

WebSockets:

- `/ws/threats` for threat updates.
- `/ws/agent/{agent_id}` for machine-token authenticated agent communication.

## Governance and High-Impact Actions

Governance is a real implemented control plane, not only documentation. Key components:

| Component | Role |
|---|---|
| `backend/services/outbound_gate.py` | Creates outbound queue and triune decision records; forces review for high-impact action types. |
| `backend/services/governed_dispatch.py` | Queues gated agent commands as `gated_pending_approval`. |
| `backend/routers/governance.py` | Lists pending decisions and supports approve/deny operations. |
| `backend/services/governance_authority.py` | Updates decision, queue, and policy-decision state and emits events. |
| `backend/services/governance_executor.py` | Processes approved decisions when enabled. |
| `backend/services/governance_context.py` | Enforces approved decision/queue context for sensitive paths. |

Important MongoDB collections include `triune_decisions`, `triune_outbound_queue`, `policy_decisions`, and `agent_commands`.

## World Model and Memory

Machine-authenticated world ingestion lives in `backend/routers/world_ingest.py` and supports entities, edges, detections, alerts, and policy violations. `WorldModelService` persists graph-like state, and world events can include triune metadata.

Vector/case memory exists in `backend/services/vector_memory.py` and is exposed through advanced APIs. It is currently an in-process memory service, not an external durable vector database.

## Feature Maturity Guidance

Use these labels when interpreting the codebase:

- **Implemented:** normal configured code path exists and runs.
- **Provider-dependent:** implementation exists but production fidelity requires external credentials, services, or permissions.
- **Simulation-safe:** fallback/test/demo behavior is intentional but should not be reported as live execution.
- **Limited:** local, in-memory, partial, or framework-only behavior.

Examples:

- Governance queue/decision logic: implemented, with assurance coverage still important.
- Email gateway and MDM connectors: implemented frameworks, provider-dependent for production fidelity.
- Browser isolation and optional AI augmentation: partial/provider-dependent.
- Unified-agent local API: useful local control plane with in-memory state.

## Documentation Index

The `memory/` directory contains the current rebaselined review set:

- `memory/RUN_MODE_CONTRACT.md` - required/optional services and working definition.
- `memory/FEATURE_REALITY_MATRIX.md` - PASS/PARTIAL/LIMITED feature reality table.
- `memory/FEATURE_REALITY_REPORT.md` - qualitative feature reality narrative.
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - architecture, security, and operations evaluation.
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - system-wide assessment rebaselined from March snapshots.
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security feature inventory.
- `memory/architecture_diagrams/architecture-map-2026-03-06.md` - current architecture map.
- `memory/SERAPH_BOARD_BRIEF_2026.md` - executive position and priorities.
- `memory/SERAPH_COMPETITIVE_WHITEPAPER_2026.md` - competitive positioning.
- `memory/SERAPH_IMPLEMENTATION_ROADMAP_2026.md` - technical roadmap.
- `memory/PRD.md` - current product requirements contract.

## Development Notes

- Prefer adding shared API helpers and contract tests before expanding page-local fetch logic.
- Treat high-impact actions as governance-gated by default.
- Keep provider-backed features honest: expose live, degraded, simulated, or unconfigured states.
- Keep README and memory docs aligned with code inventories rather than stale counts.

## License and Use

This repository contains security tooling and response automation. Run it only in environments where you have authorization, and configure integrations carefully before enabling high-impact response actions.
