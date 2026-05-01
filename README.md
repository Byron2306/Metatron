# Metatron / Seraph AI Defense Platform

Metatron/Seraph is a full-stack cybersecurity platform that combines a FastAPI control plane, a React SOC dashboard, and a cross-platform unified endpoint agent. The current codebase is organized around endpoint/XDR operations, AI-agentic threat detection, SOAR and response workflows, email and mobile security, cloud posture management, deception, governance, and optional local security integrations.

This README reflects the repository state reviewed on 2026-05-01.

## Current implementation at a glance

| Area | Current code path | Summary |
| --- | --- | --- |
| Backend API | `backend/server.py`, `backend/routers/` | FastAPI app with MongoDB-backed state, 62 router modules, REST APIs under `/api` plus selected `/api/v1` routers, and WebSockets under `/ws/*`. |
| Frontend | `frontend/src/App.js`, `frontend/src/pages/`, `frontend/src/components/` | React dashboard with protected routes, workspace pages, legacy redirects, and same-origin `/api` fallback through `frontend/src/lib/api.js`. |
| Unified endpoint agent | `unified_agent/core/agent.py` | Large cross-platform agent with process, network, registry, DLP/EDM, ransomware, kernel, identity, CLI telemetry, email, mobile, and local governance/remediation modules. |
| Agent control plane | `backend/routers/unified_agent.py` | Registration, heartbeat, telemetry, commands, EDM datasets/rollouts, deployments, alerts, dashboard stats, WebSocket, and installer/download endpoints under `/api/unified/*`. |
| Runtime stack | `docker-compose.yml` | MongoDB, Redis, backend on port 8001, frontend on port 3000, Celery worker/beat, and optional security/AI/SIEM services. |
| Local agent UI | `unified_agent/server_api.py`, `unified_agent/ui/` | Agent-side FastAPI/Flask/desktop/native UI surfaces for local operation and demonstrations. |
| Tests and reports | `backend/tests/`, `unified_agent/tests/`, `test_reports/` | Backend, frontend, unified-agent, smoke, E2E, MITRE, parity, and integration validation artifacts. |

## Product capabilities represented in code

### Endpoint and agent operations

- Cross-platform unified agent runtime in `unified_agent/core/agent.py`.
- Backend fleet APIs in `backend/routers/unified_agent.py`, `backend/routers/swarm.py`, `backend/routers/agents.py`, and `backend/routers/agent_commands.py`.
- Installer/download helpers and deployment flows for Linux, Windows, and agent package delivery.
- Agent telemetry summarized into canonical monitor keys including registry, process tree, lolbin, code signing, DNS, DLP, ransomware, rootkit, kernel security, identity, CLI telemetry, email protection, mobile security, and WebView2.

### SOC, XDR, and response workflows

- Threat, alert, dashboard, timeline, audit, hunting, correlation, report, quarantine, response, and SOAR APIs under `backend/routers/`.
- Response engines in `backend/threat_response.py`, `backend/quarantine.py`, `backend/soar_engine.py`, `backend/ransomware_protection.py`, and related service modules.
- React workspaces such as `CommandWorkspacePage`, `InvestigationWorkspacePage`, `DetectionEngineeringWorkspacePage`, and `ResponseOperationsPage`.

### AI-agentic defense and governance

- Autonomous-agent detection and registry services in `backend/services/aatl.py` and `backend/services/aatr.py`.
- Cognition, governance, and dispatch services in `backend/services/cognition_engine.py`, `backend/services/cce_worker.py`, `backend/services/governance_*`, and `backend/services/governed_dispatch.py`.
- Enterprise identity, policy, token, tool-gateway, SIEM, and tamper-evident telemetry services under `backend/services/`.
- Triune intelligence routers and services for Metatron, Michael, and Loki in `backend/routers/{metatron,michael,loki}.py`, `backend/triune/`, and `backend/schemas/triune_models.py`.

### Data protection, EDM, and DLP

- EDM governance and telemetry in `backend/routers/unified_agent.py` and agent-side matching in `unified_agent/core/agent.py`.
- Enhanced DLP in `backend/enhanced_dlp.py`.
- Dataset versioning, rollout, rollback, readiness, signature, and hit telemetry paths exposed through `/api/unified/*`.

### Email and mobile security

- Email protection service and router: `backend/email_protection.py`, `backend/routers/email_protection.py`.
- Email gateway service and router: `backend/email_gateway.py`, `backend/routers/email_gateway.py`.
- Mobile security service and router: `backend/mobile_security.py`, `backend/routers/mobile_security.py`.
- MDM connector service and router: `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py`.
- UI entry points are workspace-routed through `/email-security` and `/endpoint-mobility`, with legacy redirects from `/email-protection`, `/email-gateway`, `/mobile-security`, and `/mdm`.

### Cloud, network, isolation, and integrations

- CSPM engine and cloud scanners in `backend/cspm_engine.py`, `backend/cspm_*_scanner.py`, and `backend/routers/cspm.py`.
- Network, VPN, Zeek, osquery, Sigma, container, sandbox, browser isolation, deception, honeypot, honey-token, MITRE, and atomic validation modules under `backend/` and `backend/routers/`.
- Unified-agent integrations for tools such as Zeek, Yara, Trivy, Falco, Suricata, Cuckoo, osquery, Amass, BloodHound, Arkime, SpiderFoot, and PurpleSharp under `unified_agent/integrations/`.

## Repository layout

```text
backend/                  FastAPI app, routers, services, schemas, tests, scripts
frontend/                 React dashboard and component library
unified_agent/            Endpoint agent, local APIs/UIs, integrations, tests
docs/                     Feature and integration notes
memory/                   Architecture, review, run-mode, roadmap, and reality docs
test_reports/             Validation and evidence reports
scripts/                  Installers, browser extension, checks, validation helpers
docker-compose.yml        Main local/container runtime
DEPLOYMENT.md             Deployment-oriented documentation
SYSTEM_FUNCTIONALITY.md   Additional capability inventory
```

## Runtime model

### Required core services

The platform is healthy only when these core services are available:

- `mongodb`
- `backend`
- `frontend`

### Optional/default integrations

The UI and APIs are expected to degrade gracefully when optional integrations are unavailable:

- `redis` and Celery for background work
- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`
- security-profile services such as `trivy`, `falco`, and `suricata`
- sandbox-profile services such as `cuckoo`

### API routing

- Backend listens on port `8001` in compose.
- Frontend listens on port `3000` in compose.
- Frontend API calls resolve through `frontend/src/lib/api.js`:
  - `REACT_APP_BACKEND_URL/api` when a valid backend URL is configured.
  - same-origin `/api` when no valid backend URL is configured.
- Most routers are mounted with `/api` in `backend/server.py`.
- Some routers carry native `/api/v1` prefixes, including CSPM, identity, attack-paths, secure-boot, and kernel-sensor surfaces.

## Quick start

```bash
cp .env.example .env
docker compose up -d mongodb redis backend frontend
```

Then open:

- Frontend: `http://localhost:3000`
- Backend health: `http://localhost:8001/api/health`

For the fuller local stack:

```bash
docker compose up -d
```

Security and sandbox profiles are optional and environment-dependent:

```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

## Development commands

Backend:

```bash
cd backend
pytest
```

Frontend:

```bash
cd frontend
yarn install
yarn test
```

Unified agent:

```bash
cd unified_agent
pytest
```

Lightweight repository checks and validation scripts live in `scripts/`, `backend/scripts/`, and `test_reports/`.

## Important implementation notes

- `backend/server.py` is the canonical product API entrypoint.
- `unified_agent/server_api.py` is a secondary agent-side/local-stack API, not the main dashboard backend.
- The canonical dashboard agent route is `/unified-agent`; older `/agents`, `/swarm`, and `/agent-commands*` routes redirect there.
- Email and mobile pages are consolidated into workspace pages, while older direct routes redirect to the appropriate workspace tab.
- Production/strict mode requires explicit CORS origins and production integration keys for relevant M2M paths.
- Optional integrations should expose clear degraded status instead of blocking core SOC workflows.

## Documentation map

- `memory/RUN_MODE_CONTRACT.md` - source of truth for required vs optional runtime services.
- `memory/FEATURE_REALITY_REPORT.md` - qualitative implementation reality summary.
- `memory/FEATURE_REALITY_MATRIX.md` - feature-by-feature maturity matrix.
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - engineering, security, and operational risk assessment.
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - current system-wide review snapshot.
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security-domain inventory.
- `memory/PRD.md` - product requirements summary aligned to current code.
- `memory/architecture_diagrams/architecture-map-2026-03-06.md` - architecture map updated to current implementation.

## Current maturity summary

The codebase is broad and feature-rich, with strong implementation depth in endpoint control, SOC workflows, DLP/EDM, email/mobile surfaces, cloud posture, deception, and governance concepts. The main remaining engineering risks are not missing feature categories; they are consistency and assurance concerns: contract governance across many routers/pages, production-hardening parity across legacy and secondary entrypoints, durable state for governance-sensitive workflows, optional integration behavior, and verification depth for security-critical denial paths.
