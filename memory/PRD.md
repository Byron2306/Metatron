# Seraph AI Defense System - Product Requirements Document (Reality-Aligned)

Last updated: 2026-04-19  
Scope: Current as-built platform in this repository.

## 1) Product statement

Seraph AI Defense System is a modular security platform combining:

- FastAPI backend (`backend/server.py`) with broad API coverage
- React operations console (`frontend/src`)
- Unified endpoint/agent stack (`unified_agent/`)
- Integrations runtime and governed execution paths
- Multi-domain security capabilities (identity, endpoint, network, email, cloud, response)

## 2) Product goals (current)

1. Detect, correlate, and prioritize suspicious activity across multiple domains.
2. Execute response and operational actions through auditable governance controls.
3. Provide a unified UI for command, investigation, response, world-model, and agent operations.
4. Support optional advanced subsystems (CSPM, sandboxing, SIEM-adjacent tooling, AI reasoning, quantum).
5. Preserve deployment flexibility across local dev, containerized stacks, and constrained environments.

## 3) In-scope system boundaries

### Included in this repo

- Backend API, services, and router mesh
- Frontend SPA and route workspaces
- Unified agent core and adapters
- Integration orchestration and ingestion
- Governance queue, approval, and executor flow
- Deployment configs and helper scripts

### Out of scope for this PRD snapshot

- SaaS control-plane billing/provisioning
- External MDR service operations
- Formal vendor support SLAs
- Production hard guarantees not represented in code contracts

## 4) Primary personas

1. Security Analyst
   - Investigates alerts and threats
   - Uses command/investigation dashboards and detection views

2. Security Engineer
   - Manages policies, integrations, detections, and automation
   - Operates advanced and governance endpoints

3. Platform Admin
   - Manages users, roles, tenants, and deployment/runtime posture
   - Operates critical admin and remote-control surfaces

4. Endpoint Operator / Agent Maintainer
   - Deploys/monitors unified agents
   - Uses agent telemetry and command channels

## 5) Functional requirements (as-built)

### FR-1 Authentication and access control

- JWT-based auth with role permissions via `backend/routers/auth.py` and `backend/routers/dependencies.py`
- Roles include admin/analyst/viewer with permission checks (`check_permission`, `has_permission`)
- Optional setup-token protected first-admin bootstrap (`/api/auth/setup`)
- Remote admin gate behavior controlled via `REMOTE_ADMIN_ONLY` and trusted-origin logic

### FR-2 Threat and alert operations

- Threat lifecycle endpoints: `backend/routers/threats.py`
- Alert lifecycle endpoints: `backend/routers/alerts.py`
- Timeline and audit exposure: `backend/routers/timeline.py`, `backend/routers/audit.py`
- Threat intelligence ingestion and retrieval: `backend/routers/threat_intel.py`

### FR-3 Response and quarantine

- Response operations via `backend/routers/response.py`
- Quarantine operations via `backend/routers/quarantine.py`
- Governed execution bridge handles approved queue actions in `backend/services/governance_executor.py`

### FR-4 Unified agent control plane

- API surface: `backend/routers/unified_agent.py`
- Agent command queueing: `backend/routers/agent_commands.py`
- Optional standalone unified agent API: `unified_agent/server_api.py`
- Endpoint runtime capabilities in `unified_agent/core/agent.py`

### FR-5 Integration runtime and ingestion

- Integrations API: `backend/routers/integrations.py`
- Runtime orchestration and jobs: `backend/integrations_manager.py`
- Supported runtime tools include amass/arkime/bloodhound/spiderfoot/velociraptor/purplesharp/sigma/atomic/falco/yara/suricata/trivy/cuckoo/osquery/zeek

### FR-6 Governance and auditable command gating

- Decision API: `backend/routers/governance.py`
- Outbound gate + queueing: `backend/services/governed_dispatch.py`
- Decision authority transitions: `backend/services/governance_authority.py`
- Execution processor: `backend/services/governance_executor.py`
- Telemetry-chain auditing hooks used across governed actions

### FR-7 World-model ingestion and entity graph

- Ingestion API: `backend/routers/world_ingest.py`
- World model services: `backend/services/world_model.py`, `backend/services/world_events.py`
- Triune-related services/routers participate in model enrichment and event flow

### FR-8 Domain security modules

Backend includes dedicated routers/modules for:

- Zero trust (`routers/zero_trust.py`)
- VPN (`routers/vpn.py`)
- EDR (`routers/edr.py`)
- SOAR (`routers/soar.py`)
- Ransomware (`routers/ransomware.py`)
- Container security (`routers/containers.py`)
- Browser isolation (`routers/browser_isolation.py`)
- Honey tokens + honeypots (`routers/honey_tokens.py`, `routers/honeypots.py`)
- Email protection + gateway (`routers/email_protection.py`, `routers/email_gateway.py`)
- Mobile security + MDM connectors (`routers/mobile_security.py`, `routers/mdm_connectors.py`)
- CSPM (`routers/cspm.py`)
- Identity (`routers/identity.py`)
- MITRE / Sigma / Zeek / Osquery / Atomic validation surfaces

### FR-9 Frontend workspace navigation and orchestration UX

`frontend/src/App.js` provides consolidated workspaces and compatibility redirects:

- Command workspace
- World workspace
- AI activity workspace
- Investigation workspace
- Response operations workspace
- Detection engineering workspace
- Email security workspace
- Endpoint & mobility workspace
- Unified agent and specialized feature pages

## 6) Non-functional requirements (current baseline)

1. **Modularity**: Router/service separation maintained in backend.
2. **Security defaults**:
   - production/strict mode secret and CORS checks
   - machine-token gates for internal ingestion surfaces
3. **Observability**:
   - health endpoint `/api/health`
   - audit/event emission across many operations
4. **Resilience**:
   - optional dependency behavior (many services fail-open/logged)
   - data directory fallback (`runtime_paths.ensure_data_dir`)
5. **Portability**:
   - local and Docker paths supported
   - unified agent supports multiple host environments

## 7) API and route requirements summary

- Backend is mounted from `backend/server.py` with `/api` as primary prefix.
- Several routers use embedded `/api/v1/*` prefixes for compatibility and versioned domains.
- WebSocket endpoints:
  - `/ws/threats`
  - `/ws/agent/{agent_id}` (machine-token validated)
- Root API metadata endpoint: `/api/`

## 8) Data requirements

### Primary data store

- MongoDB via Motor client in `backend/server.py`
- Database name configurable via `DB_NAME`

### Data directories and filesystem state

- Data root managed by `backend/runtime_paths.py`
- Primary default: `/var/lib/anti-ai-defense`
- Fallback: `/tmp/anti-ai-defense`

### Agent-side local state

- Unified agent local dirs under `~/.seraph-defender/` (see `unified_agent/core/agent.py`)

## 9) Deployment requirements

### Local backend

- Launch: `python3 backend/server.py` or `uvicorn backend.server:app --host 0.0.0.0 --port 8001`

### Frontend

- `cd frontend && yarn start`

### Containerized stack

- `docker-compose.yml` defines 21 services including backend, frontend, mongo, redis, celery worker/beat, elastic/kibana, tooling, and optional security profiles.

## 10) Testing requirements

Current repository evidence:

- Backend tests in `backend/tests/` (63 files)
- Unified agent tests in `unified_agent/tests/` plus additional agent test files
- Root/system tests: `e2e_system_test.py`, `full_feature_test.py`, and backend script validations

## 11) Current known requirement risks

1. Some frontend legacy call-sites still target stale endpoints (`/api/data`, `/api/login`, `/api/admin/users`).
2. Large API breadth creates drift risk without strict contract checks.
3. Legacy/alternate server code paths (`server_old.py`, unified_agent proxy assumptions) can diverge from primary backend behavior.
4. Optional subsystem dependencies may differ by host/runtime profile.

## 12) PRD acceptance criteria (updated)

The platform is considered aligned with this PRD when:

1. Core API boots and serves `/api/health` with DB connectivity.
2. Auth/login and role checks function across protected routes.
3. Frontend workspace routes load and can call corresponding backend APIs.
4. Integrations job lifecycle endpoints function (`/api/integrations/*`).
5. Governance decision approval and execution pipeline operates end-to-end.
6. Unified agent routes accept telemetry/commands and project operational state.
7. Security domain routers remain reachable under documented prefixes.

## 13) Change log (this rewrite)

- Replaced speculative version-history narrative with code-reality requirements.
- Grounded requirements in current module boundaries and route contracts.
- Added explicit governance, integrations, and world-ingest requirement model.
- Added measurable acceptance criteria tied to current runtime behavior.
