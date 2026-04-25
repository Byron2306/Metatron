# Metatron / Seraph AI Defense Platform

Metatron/Seraph is a full-stack AI-era defense platform that combines a
FastAPI security control plane, React SOC workspaces, a unified endpoint agent,
Triune reasoning, governed dispatch, and optional security integrations.

This README reflects the current repository wiring as of 2026-04-25. For deeper
review material, see the `memory/` and `docs/` directories.

## Current Architecture

### Central backend

`backend/server.py` is the authoritative FastAPI composition root. It:

- loads environment configuration from `backend/.env`;
- initializes MongoDB or mongomock and shares the DB through router dependencies;
- mounts most routers under `/api/*`;
- mounts selected native `/api/v1/*` routers for identity, CSPM, attack paths,
  secure boot, and kernel sensors;
- exposes WebSockets at `/ws/threats` and `/ws/agent/{agent_id}`;
- starts CCE, network discovery, deployment, AATL/AATR, integration scheduling,
  and governance executor background services when configured.

Key backend surfaces include auth, dashboard, threats, alerts, reports, hunting,
timeline, audit, response, quarantine, SOAR, ransomware, deception, zero trust,
CSPM, identity, kernel sensors, secure boot, email protection, email gateway,
mobile security, MDM connectors, advanced services, unified-agent control,
swarm control, world ingest, Triune, and governance.

### React frontend

The React app is defined by `frontend/src/App.js` and uses protected workspace
routes rather than one route per legacy feature page. Primary workspaces include:

- `/command` - dashboard, command center, alerts, threats
- `/world` - world graph and Metatron state views
- `/ai-activity` - AI sessions, signals, and intelligence
- `/response-operations` - response, quarantine, SOAR, EDR
- `/investigation` - threat intel, correlation, attack paths
- `/detection-engineering` - sigma, Zeek, osquery, atomic validation, MITRE
- `/email-security` - email protection and email gateway tabs
- `/endpoint-mobility` - mobile security and MDM tabs
- `/unified-agent` - fleet, monitors, swarm, and agent deployment operations

Many historical paths remain as redirects into these workspaces, including
`/dashboard`, `/alerts`, `/threats`, `/agents`, `/soar`, `/swarm`,
`/email-gateway`, `/email-protection`, `/mobile-security`, and `/mdm`.

### Unified endpoint agent

`unified_agent/` is a separate endpoint/runtime package, not the React app. It
contains:

- `unified_agent/core/agent.py` - the monolithic endpoint runtime and monitors;
- `unified_agent/ui/web/app.py` - local Flask operator dashboard on port 5000;
- `unified_agent/ui/desktop/main.py` - desktop core/UI;
- `unified_agent/server_api.py` - standalone FastAPI agent server/proxy;
- `unified_agent/integrations_client.py` and `integrations/` helpers.

The product UI talks to the central backend contracts under `/api/unified/*` and
`/api/swarm/*`.

## Triune and Governance

The active high-impact action path is:

`Intent -> World Event -> Triune Assessment -> Policy Decision -> Outbound Gate -> Approval -> Executor Release -> Token/PEP Enforcement -> Execution -> Audit + World Feedback`

Important files:

- `backend/services/world_events.py`
- `backend/services/triune_orchestrator.py`
- `backend/services/cognition_fabric.py`
- `backend/triune/metatron.py`
- `backend/triune/michael.py`
- `backend/triune/loki.py`
- `backend/services/outbound_gate.py`
- `backend/services/governance_authority.py`
- `backend/routers/governance.py`
- `backend/services/governance_executor.py`
- `backend/services/token_broker.py`
- `backend/services/tool_gateway.py`
- `backend/services/mcp_server.py`
- `backend/services/telemetry_chain.py`

Triune cognition fuses AATL, AATR, CCE, ML, and AI-reasoning signals into
`world_snapshot["cognition"]`. Metatron uses that signal for strategic pressure
and policy-tier suggestions, Michael ranks cognition-informed actions, and Loki
adds dissent and uncertainty before high-impact work proceeds through governance.

## Runtime Modes

Required core services:

- `mongodb`
- `backend`
- `frontend`

Default optional services:

- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`

Profile-gated services include Trivy, Falco, Suricata, and Cuckoo.

### Minimal local stack

```bash
docker compose up -d mongodb backend frontend
```

### Recommended local full stack

```bash
docker compose up -d mongodb backend frontend wireguard elasticsearch kibana ollama
```

### Extended profiles

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

By default, Docker Compose binds the backend to `127.0.0.1:8001` and the
frontend to `127.0.0.1:3000`.

## Health and Validation

Basic checks:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8001/api/health
curl -fsS http://127.0.0.1:3000
python3 smoke_test.py
```

For targeted backend checks, run tests from the backend package, for example:

```bash
cd backend
pytest tests/test_triune_routes.py tests/test_outbound_gate_and_snapshot.py
```

For local agent UI contract checks:

```bash
cd unified_agent
pytest tests/test_canonical_ui_contract.py
```

## Configuration Notes

- Prefer same-origin `/api/...` routing behind a reverse proxy.
- `REACT_APP_BACKEND_URL` can point the frontend at a backend origin in local
  development.
- Production or strict modes should provide explicit `CORS_ORIGINS`,
  `JWT_SECRET`, and integration/machine tokens.
- `INTEGRATION_API_KEY` and related machine-token settings protect agent,
  world-ingest, and integration paths.
- Email gateway and MDM connector logic is implemented, but live production use
  requires real SMTP/MDM credentials and provider connectivity.
- Optional integrations should degrade gracefully when not enabled.

## Documentation Map

Major memory review documents:

- `memory/FEATURE_REALITY_REPORT.md` - qualitative implementation reality
- `memory/FEATURE_REALITY_MATRIX.md` - feature maturity matrix
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - strategic system scorecard
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - conservative risk/evaluation baseline
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security feature evidence
- `memory/RUN_MODE_CONTRACT.md` - required/optional runtime contract
- `memory/architecture_diagrams/architecture-map-2026-03-06.md` - architecture map
- `memory/PRD.md` - product requirements and version history

Triune and governance references:

- `docs/AI_TRIUNE_INTEGRATION.md`
- `docs/triune_cognition_feature_summary.md`
- `docs/triune_governance_integration_matrix.md`

Subsystem references:

- `frontend/README.md`
- `unified_agent/AGENT README.md`
- `unified_agent/LOCAL_DASHBOARD_CONTRACT.md`
- `DEPLOYMENT.md`

## Repository Layout

```text
backend/        FastAPI app, routers, services, Triune logic, tests
frontend/       React SOC frontend
unified_agent/  Endpoint agent, local dashboard, standalone agent server
docs/           Triune, governance, frontend, and ATT&CK planning docs
memory/         System review, evaluation, and architecture memory documents
deployment/     Deployment units and worker service definitions
scripts/        Installers, helpers, browser extension assets
test_reports/   Historical validation reports
```

## Current Operational Posture

The platform is feature-broad and increasingly governance-hardened. The most
important remaining release risks are contract drift across frontend/backend
paths, denial-path coverage for high-impact operations, optional dependency
semantics, environment-specific provider credentials, and assurance under
restart/scale scenarios.
