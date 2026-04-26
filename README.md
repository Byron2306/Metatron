# Metatron / Seraph AI Defense Platform

Metatron/Seraph is a full-stack cybersecurity control plane for SOC operations, endpoint-agent management, threat response, triune governance, and AI-assisted investigation. The repository combines a FastAPI backend, MongoDB-backed state, a React operator dashboard, and a large unified endpoint agent.

This README reflects the current repository logic as of 2026-04-26. Older collateral in the repo may still describe legacy page counts, endpoint names, or smoke-test behavior.

## Repository layout

| Path | Purpose |
|---|---|
| `backend/` | FastAPI application, routers, domain services, triune services, Celery app, tests, and validation scripts |
| `frontend/` | React 19 + React Router + CRACO operator dashboard |
| `unified_agent/` | Endpoint agent, local desktop/web UIs, agent-side integrations, and agent tests |
| `memory/` | Architecture, run-mode, feature-reality, security, and roadmap review documents |
| `docs/` | Supplemental feature and integration notes |
| `test_reports/` | Historical validation reports and evidence artifacts |
| `docker-compose.yml` | Local/container stack for backend, frontend, MongoDB, Redis, observability, optional sensors, and sandbox profile |

## Current architecture

### Backend control plane

`backend/server.py` is the main FastAPI entrypoint. It:

- connects to MongoDB using Motor, with test/degraded paths where configured;
- initializes the world model and triune services;
- registers the router mesh under `/api` and selected native `/api/v1` prefixes;
- exposes `/api/health`;
- provides WebSocket channels for threat and agent activity.

Major router groups include:

- SOC and analytics: threats, alerts, dashboard, hunting, correlation, timeline, audit, reports;
- response: response operations, quarantine, SOAR, ransomware, honeypots, honey tokens, deception;
- endpoint and fleet: agents, agent commands, swarm, unified agent;
- enterprise/security posture: auth, settings, enterprise, zero trust, multi-tenant, CSPM, identity, attack paths, secure boot, kernel sensors;
- advanced plane: MCP, VNS, vector memory, quantum security, AI reasoning, sandbox, containers, VPN, integrations;
- newer domain surfaces: email protection, email gateway, mobile security, MDM connectors;
- governance and triune: Metatron, Michael, Loki, world ingest, governance decisions.

### Frontend dashboard

`frontend/src/App.js` defines the protected React dashboard shell. The current UI consolidates older pages into workspace-oriented routes:

- `/command`
- `/world`
- `/ai-activity`
- `/response-operations`
- `/investigation`
- `/detection-engineering`
- `/email-security`
- `/endpoint-mobility`
- `/unified-agent`
- plus specialized pages such as CSPM, deception, kernel sensors, secure boot, identity, VPN, sandbox, browser isolation, Kibana, reports, tenants, and setup guide.

Legacy routes such as `/alerts`, `/threats`, `/agents`, `/email-gateway`, `/mdm`, and `/soar` redirect into the consolidated workspaces.

Frontend commands:

```bash
cd frontend
yarn install
yarn start
yarn test
yarn build
```

### Unified endpoint agent

The endpoint agent lives primarily in `unified_agent/core/agent.py`. It contains monitor modules for process, network, registry, process tree, LOLBins, code signing, DNS, memory, application allowlisting, DLP/EDM, vulnerability checks, AMSI, ransomware, rootkit, kernel security, self-protection, endpoint identity, throttling, firewall, WebView2, CLI telemetry, hidden files, alias/path hijacking, privilege escalation, email protection, mobile security, and YARA.

Related agent surfaces:

- `unified_agent/ui/desktop/main.py` - local Tk desktop UI;
- `unified_agent/ui/web/app.py` - local Flask web UI wrapper;
- `unified_agent/server_api.py` - standalone agent-side FastAPI service with backend proxy behavior;
- `unified_agent/integrations/` - parsers/adapters for tools such as Amass, Arkime, BloodHound, SpiderFoot, and related utilities.

The backend integration surface is `backend/routers/unified_agent.py`, mounted at `/api/unified`. It handles registration, heartbeat, telemetry, install/download helpers, EDM datasets and hits, fleet stats, command metadata, and governed dispatch.

## Core runtime flows

### World events and triune reasoning

World-state changes are emitted through `backend/services/world_events.py`.

1. Routers and services call `emit_world_event(...)`.
2. Events are classified as passive, local-reflex, strategic recompute, or action-critical recompute.
3. Events are persisted to `world_events`.
4. Strategic and action-critical classes can trigger `TriuneOrchestrator.handle_world_change(...)`.
5. The orchestrator builds a world snapshot, enriches it with cognition signals, runs Metatron, Michael, and Loki, and returns a bundle.

Triune service responsibilities:

- `backend/triune/metatron.py` assesses strategic pressure, cognitive pressure, autonomous confidence, policy tier, risky entities, predicted sectors, and recommended posture.
- `backend/triune/michael.py` ranks response candidates with explainable heuristics and optional AI explanation hooks.
- `backend/triune/loki.py` challenges the selected plan with alternative hypotheses, hunt suggestions, deception ideas, and uncertainty markers.

### Governance and outbound action gating

High-impact action types are gated by `backend/services/outbound_gate.py`. Mandatory governed actions include response execution, response IP block/unblock, swarm commands, agent commands, cross-sector hardening, quarantine restore/delete/agent operations, tool execution, and MCP tool execution.

The gate:

- normalizes impact to at least `high` for mandatory actions;
- writes `triune_outbound_queue` and `triune_decisions`;
- emits a world event that can trigger triune recomputation.

`backend/services/governed_dispatch.py` persists gated agent commands as `gated_pending_approval` with `queue_id`, `decision_id`, authority context, transition log, and decision context. `backend/routers/governance.py` exposes pending decision list, approve, deny, and executor run-once endpoints.

### Vector memory and advanced services

Vector/case memory is implemented in `backend/services/vector_memory.py` and exposed through `backend/routers/advanced.py` under `/api/advanced/memory/*`.

Implemented concepts include:

- namespaces: verified knowledge, observations, threat intel, host profiles, incident cases, unverified;
- trust levels: verified, high, medium, low, untrusted;
- memory entries with provenance, evidence refs, related entries, optional case IDs, and embeddings;
- incident cases with symptoms, indicators, affected hosts, RCA, response steps, and similarity search.

The `memory/` directory in this repository is documentation collateral, not the runtime vector memory store.

### Email, mobile, and MDM domains

The email and mobility surfaces are implemented as backend services plus routers and frontend workspaces:

- `backend/email_protection.py` and `backend/routers/email_protection.py`;
- `backend/email_gateway.py` and `backend/routers/email_gateway.py`;
- `backend/mobile_security.py` and `backend/routers/mobile_security.py`;
- `backend/mdm_connectors.py` and `backend/routers/mdm_connectors.py`;
- frontend routes consolidated under `/email-security` and `/endpoint-mobility`.

These modules provide real local/API logic for analysis, quarantine/list management, device/compliance workflows, and connector management. Production SMTP relay behavior and live MDM sync depend on external servers, credentials, and platform APIs.

## Run modes

### Required core

For a healthy dashboard/API baseline:

- MongoDB
- backend
- frontend

Redis is part of the default compose stack for Celery worker/beat and asynchronous integration work.

### Optional or degraded services

The following services are optional for baseline SOC operation and should degrade explicitly when absent:

- Elasticsearch and Kibana;
- WireGuard;
- Ollama or external LLM providers;
- Trivy, Falco, Suricata through the security profile;
- Cuckoo through the sandbox profile;
- external SMTP, MDM, SIEM, Twilio, SendGrid, Slack, and other credentialed integrations.

## Quick start

```bash
cp .env.example .env  # if present for your environment
docker compose up -d mongodb redis backend frontend
curl -fsS http://localhost:8001/api/health
open http://localhost:3000
```

Recommended local stack with common optional services:

```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana wireguard ollama
```

Extended profiles:

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

## Validation and tests

Use targeted checks for the area you changed.

```bash
# Backend health
curl -fsS http://localhost:8001/api/health

# Broad API walk, expects backend at localhost:8001/api
python3 full_feature_test.py

# Integration runtime smoke
python3 backend/scripts/integration_runtime_full_smoke.py

# Frontend tests
cd frontend && yarn test

# Backend targeted tests
cd backend && pytest tests/test_triune_orchestrator.py tests/test_outbound_gate_and_snapshot.py
```

Note: root `smoke_test.py` is currently a CAS shield reverse-proxy style FastAPI service, not the main platform smoke test. Prefer `/api/health`, `full_feature_test.py`, targeted backend tests, and compose healthchecks for platform validation.

## Documentation map

The major review documents were updated to current code logic:

- `memory/FEATURE_REALITY_MATRIX.md` - concise maturity matrix by domain;
- `memory/FEATURE_REALITY_REPORT.md` - qualitative feature reality report;
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - system-wide evaluation rebaseline;
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - architecture/security/operations critical review;
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security feature evidence and limits;
- `memory/RUN_MODE_CONTRACT.md` - current run modes and degraded-mode contract;
- `memory/architecture_diagrams/architecture-map-2026-03-06.md` - architecture/data-flow map.

## Current engineering risks

- API/client contract drift across a large and fast-moving router mesh.
- `backend/server.py` remains a dense central startup and router-wiring point.
- Optional integrations have uneven degraded-mode semantics across older modules.
- Some execution paths are framework-ready but require external services or credentials for production behavior.
- Governance is now Mongo-backed for outbound queues/decisions, but broader restart/scale assurance should continue to be tested.
- Detection quality, false-positive governance, and compliance evidence need sustained benchmark/replay/evidence automation.

## Development notes

- Prefer existing routers/services and local helpers over new parallel abstractions.
- Keep high-impact actions behind governance gates.
- Update memory review docs when architecture, run modes, governance semantics, or feature reality materially changes.
- Use targeted tests and evidence-based summaries; avoid percentage-complete claims unless backed by repeatable validation.
