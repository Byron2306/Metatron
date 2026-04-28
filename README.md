# Metatron / Seraph AI Defense Platform

Metatron / Seraph is an adaptive cybersecurity platform that combines a FastAPI control plane, React operator console, unified endpoint agent, governed automation, Triune cognition, SOC workflows, response orchestration, and broad security-domain integrations.

This README reflects the current repository code logic as of 2026-04-28.

## Current implementation snapshot

| Area | Current source of truth |
|---|---|
| Backend API | `backend/server.py` (`backend.server:app`) on port 8001 |
| Frontend UI | `frontend/src/App.js`, CRA/Craco React app on port 3000 |
| Database | MongoDB database `seraph_ai_defense` by default |
| Async/broker | Redis plus Celery worker/beat paths in Compose |
| Endpoint agent | `unified_agent/core/agent.py` |
| Central agent API | `/api/unified/*` from `backend/routers/unified_agent.py` |
| Governance | `backend/services/governance_*`, `outbound_gate.py`, `token_broker.py`, `tool_gateway.py`, `telemetry_chain.py` |
| Triune cognition | `backend/services/triune_orchestrator.py`, `cognition_fabric.py`, `world_model.py`, `world_events.py`, `backend/triune/*` |
| Compose stack | `docker-compose.yml` |
| Run-mode contract | `memory/RUN_MODE_CONTRACT.md` |

Current repository counts:

- 61 backend router modules in `backend/routers` excluding `__init__.py`.
- 32 backend service modules in `backend/services` excluding `__init__.py`.
- 63 React `*Page` files in `frontend/src/pages`.
- 43 backend root-level Python modules.
- 20 unified-agent Python files.

## Architecture overview

```text
Operator Browser
    |
    v
React frontend (port 3000)
    |
    v
FastAPI backend (port 8001, /api and selected /api/v1 routes)
    |
    +--> MongoDB platform state
    +--> Redis / Celery background work
    +--> Governance, policy, token, tool, and audit services
    +--> Triune cognition and world model services
    +--> Runtime integrations and optional tools
    +--> Unified endpoint agents over REST/WebSocket
```

### Backend

`backend/server.py` is the primary backend entrypoint. It:

1. Loads environment settings from `backend/.env`.
2. Connects to MongoDB, or optional mongomock when configured.
3. Injects database handles into routers and core engines.
4. Creates world model and Triune services.
5. Configures CORS from `CORS_ORIGINS`.
6. Mounts the router mesh.
7. Exposes `/api/health`, `/api/`, `/ws/threats`, and `/ws/agent/{agent_id}`.
8. Starts background services for CCE, network discovery, deployment, AATL/AATR, integrations scheduling, and governance execution.

Most routers are mounted under `/api`. Some routers carry native `/api/v1` prefixes and are mounted as-is, including CSPM, identity, attack paths, secure boot, and kernel sensors. Deception is mounted under both `/api/deception` and `/api/v1/deception` for compatibility.

### Frontend

The frontend is a CRA/Craco React application. `frontend/src/App.js` is the route source of truth.

The authenticated root route redirects to `/command`. Several older routes now redirect into consolidated workspaces:

| Workspace | Purpose | Example redirects |
|---|---|---|
| `/command` | Dashboard, alerts, threats, command center | `/dashboard`, `/alerts`, `/threats`, `/command-center` |
| `/ai-activity` | AI signals, intelligence, CLI sessions | `/ai-detection`, `/ai-threats`, `/cli-sessions` |
| `/response-operations` | Quarantine, response, EDR, SOAR | `/quarantine`, `/response`, `/edr`, `/soar` |
| `/investigation` | Threat intel, correlation, attack paths | `/threat-intel`, `/correlation`, `/attack-paths` |
| `/detection-engineering` | Sigma, atomic validation, MITRE | `/sigma`, `/atomic-validation`, `/mitre-attack` |
| `/email-security` | Email protection and gateway | `/email-protection`, `/email-gateway` |
| `/endpoint-mobility` | Mobile security and MDM | `/mobile-security`, `/mdm` |
| `/unified-agent` | Agent, swarm, command, monitor, installer workflows | `/agents`, `/agent-commands`, `/swarm` |

Standalone pages remain for world view, network topology, hunting, reports, timeline, audit, settings, Zeek, Osquery, ransomware, containers, VPN, honey tokens, zero trust, ML prediction, sandbox, browser isolation, Kibana, advanced services, heatmap, VNS alerts, browser extension, tenants, CSPM, deception, kernel sensors, secure boot, and identity.

### Unified endpoint agent

The primary endpoint runtime is `unified_agent/core/agent.py`. It includes broad monitor and control families for process, network, DNS, memory, DLP, vulnerabilities, YARA, ransomware, rootkit, kernel security, self-protection, identity, email/mobile, CLI telemetry, local execution, remediation, scanners, VPN, and local UI hooks.

Central backend routes under `/api/unified/*` support:

- agent registration and heartbeat;
- fleet listing and endpoint posture maps;
- command dispatch and tooling requests;
- remediation proposals;
- monitor telemetry summaries;
- EDM dataset/version/rollout/reload flows;
- deployment and alert records;
- dashboard and stats;
- agent downloads and install scripts.

Local agent UIs are separate from the central backend:

- `unified_agent/ui/web/app.py`: Flask local dashboard, default localhost port 5000.
- `unified_agent/ui/desktop/main.py`: Tkinter desktop shell.
- `unified_agent/server_api.py`: separate local/portal FastAPI service; it is not the primary Docker Compose backend.

## Security and governance model

High-impact automation is designed to flow through a governed chain:

```text
Intent -> World Event -> Triune/Cognition Assessment -> Policy/Governance Decision
       -> Outbound Gate -> Approval -> Executor Release
       -> Token/Tool Enforcement -> Execution -> Audit + World Feedback
```

Important modules:

- `backend/services/governance_authority.py`
- `backend/services/governance_executor.py`
- `backend/services/governance_context.py`
- `backend/services/outbound_gate.py`
- `backend/services/governed_dispatch.py`
- `backend/services/policy_engine.py`
- `backend/services/token_broker.py`
- `backend/services/tool_gateway.py`
- `backend/services/mcp_server.py`
- `backend/services/telemetry_chain.py`
- `backend/services/world_events.py`

This architecture is real in code, but production claims should still be tied to validation evidence for the exact route and run mode being used.

## Triune cognition and world model

The Triune layer combines:

- **Metatron**: belief/state assessment and policy-tier suggestions.
- **Michael**: ranked command doctrine and readiness planning.
- **Loki**: dissent, uncertainty, deception, and alternative hypotheses.

Supporting services aggregate AATL, AATR, CCE, ML, AI reasoning, world events, and endpoint telemetry into cognition-aware decisions.

Key files:

- `backend/services/world_model.py`
- `backend/services/world_events.py`
- `backend/services/cognition_fabric.py`
- `backend/services/triune_orchestrator.py`
- `backend/triune/metatron.py`
- `backend/triune/michael.py`
- `backend/triune/loki.py`

## Security domains implemented

The repository contains real implementation surfaces for:

- SOC dashboard, threats, alerts, audit, reports, and timeline.
- Unified endpoint agent and swarm/command workflows.
- Threat intelligence, hunting, MITRE ATT&CK, Sigma, Atomic Red Team, Zeek, and osquery.
- Response, quarantine, SOAR, ransomware protection, deception, and honey tokens.
- EDR, network discovery, VPN, containers, sandboxing, browser analysis/isolation, and Kibana.
- CSPM, identity protection, zero trust, secure boot, kernel sensors, and attack paths.
- Email protection, email gateway, mobile security, and MDM connectors.
- Advanced services including MCP, vector memory, VNS, post-quantum/quantum security paths, AI reasoning, and governance.

Many domains are environment-dependent. For example, real SMTP gateway behavior needs SMTP configuration; MDM sync needs platform credentials; CSPM scans need cloud credentials; scanner integrations need installed tools, logs, containers, or live agent runtime.

## Run modes

See `memory/RUN_MODE_CONTRACT.md` for the authoritative run-mode contract.

### Minimal local core

```bash
docker compose up -d mongodb redis backend frontend
```

### Recommended local operator mode

```bash
docker compose up -d mongodb redis backend frontend celery-worker celery-beat elasticsearch kibana ollama wireguard
```

### Health checks

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Do not use `python3 smoke_test.py` as the canonical validation command. In this repository, root `smoke_test.py` is a standalone FastAPI-style app, not a simple smoke-test probe.

## Development setup

### Backend

```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.server:app --host 0.0.0.0 --port 8001
```

When running from the repository root, ensure Python can import both `backend` and its local modules. The Dockerfile sets `PYTHONPATH=/app/backend:/app`.

### Frontend

```bash
cd frontend
yarn install
yarn start
```

The frontend uses `REACT_APP_BACKEND_URL` when set; otherwise same-origin `/api` behavior is preferred where supported by the helper code.

### Unified agent

Typical local invocation depends on OS and privileges, but the main entrypoint is:

```bash
python -m unified_agent.core.agent --server http://localhost:8001
```

Use backend-served install/download endpoints under `/api/unified/agent/*` for packaged deployment flows.

## Validation and tests

Available validation assets include:

- `backend/tests/`: backend pytest suites for routers, governance, unified agent, enterprise features, CSPM, VPN/zero trust, Triune, and more.
- `unified_agent/tests/`: endpoint/local UI and agent behavior tests.
- `frontend/src/pages/__tests__/`: frontend page tests.
- `backend/scripts/full_stack_e2e_validate.py`
- `backend/scripts/e2e_threat_pipeline_test.py`
- `backend/scripts/integration_runtime_full_smoke.py`
- `backend/scripts/mitre_coverage_evidence_report.py`
- `test_reports/`: committed validation reports and artifacts.

Use targeted tests that match the run mode and dependencies you are validating.

## Documentation map

- `memory/FEATURE_REALITY_REPORT.md`: narrative feature reality assessment.
- `memory/FEATURE_REALITY_MATRIX.md`: status matrix and counts.
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`: system-wide evaluation.
- `memory/SYSTEM_CRITICAL_EVALUATION.md`: critical risks and engineering priorities.
- `memory/SECURITY_FEATURES_ANALYSIS.md`: security-domain inventory.
- `memory/RUN_MODE_CONTRACT.md`: required vs optional runtime services.
- `memory/architecture_diagrams/architecture-map-2026-03-06.md`: architecture map.
- `docs/triune_cognition_feature_summary.md`: Triune cognition details.
- `docs/triune_governance_integration_matrix.md`: governance chain details.

## Operational cautions

- Treat optional integrations as conditional until prerequisites are configured and validated.
- Treat queued work separately from verified execution success.
- Keep high-impact actions behind governance, token/tool enforcement, and audit linkage.
- Keep `backend.server:app` as the primary backend reference; `server_old.py` is legacy and `unified_agent/server_api.py` is a separate local/portal service.
- Update documentation when route inventories, run modes, or workspace routing change.
