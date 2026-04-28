# Seraph AI Defender - Technical Implementation Roadmap

Updated: 2026-04-28
Source basis: direct repository review of `backend/server.py`, `backend/routers/`, `backend/services/`, `frontend/src/App.js`, `unified_agent/`, `docker-compose.yml`, and committed validation reports.

## Program charter

Deliver a governed adaptive defense platform whose claims are backed by exact code contracts, run-mode prerequisites, verified execution evidence, and audit-linked automation.

## Workstreams

| Workstream | Purpose | Current anchor files |
|---|---|---|
| Contract integrity | Prevent backend/frontend/script/agent API drift | `backend/server.py`, `backend/routers/*`, `frontend/src/App.js`, `frontend/src/lib/api.js`, `unified_agent/integrations_client.py` |
| Runtime reliability | Make run modes and optional dependency behavior deterministic | `docker-compose.yml`, `memory/RUN_MODE_CONTRACT.md`, `backend/integrations_manager.py` |
| Governance hardening | Ensure high-impact action decisions are enforced and audited | `services/governance_*`, `outbound_gate.py`, `token_broker.py`, `tool_gateway.py`, `telemetry_chain.py` |
| Unified-agent truth | Verify endpoint deployment, heartbeat, monitor, command, and remediation outcomes | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` |
| Detection quality | Measure detection precision, replay scenarios, and suppression safety | hunting/correlation/AI/agent monitor modules and test reports |
| Integration quality | Tier integrations by dependency readiness and validation evidence | `backend/integrations_manager.py`, `unified_agent/integrations/` |
| Documentation truth | Keep README and memory docs tied to current code logic | root `README.md`, `memory/*.md` |

## Roadmap phases

### Phase 1: Truth alignment

- Generate backend route inventory from FastAPI.
- Generate frontend route and API call-site inventory from React source.
- Compare unified-agent clients and scripts against canonical routes.
- Remove or clearly label legacy defaults involving `server_old.py`, old `/api/agent/*` paths, and incorrect smoke-test guidance.
- Publish a machine-readable endpoint compatibility map.

### Phase 2: Runtime preflight and degraded states

- Add a preflight command/API that reports required core services and optional integration readiness.
- Standardize statuses: `healthy`, `degraded`, `unavailable`, `credential_required`, `tool_missing`, `agent_required`, `failed`, `verified_success`.
- Require integration jobs to report missing binaries, credentials, logs, containers, or targets explicitly.
- Ensure frontend workspaces surface degraded states consistently.

### Phase 3: Verified execution

- Normalize deployment and command state machines around queue acceptance, delivery, execution, validation, and terminal result.
- Require completed deployment/action states to include evidence such as heartbeat, install marker, command result, or provider confirmation.
- Keep simulated/demo paths explicit and non-confusable with verified production success.

### Phase 4: Governance closure

- Enforce governance gates before all high-impact command delivery and tool execution paths.
- Require approved governance context for token issuance/revocation and approval-required tools.
- Persist linkage among policy decision, governance decision, queue entry, token, execution, audit record, and world event.
- Add denial-path and bypass-resistance tests.

### Phase 5: Detection and assurance quality

- Build replay scenarios for AI-agentic behavior, endpoint telemetry, email, identity, cloud, and mobile cases.
- Track precision/recall and false-positive suppression decisions.
- Expand validation reports by run mode and dependency profile.
- Document supported OS/privilege matrices for endpoint monitors.

### Phase 6: Productization

- Publish integration tiers: core-supported, optional-supported, experimental.
- Generate compliance evidence from audit/world-event records.
- Maintain operator runbooks for minimal, recommended, and full-security modes.
- Keep README, memory docs, and deployment docs synchronized with generated inventories.

## Success criteria

1. No undocumented route or API-client drift in CI.
2. Core run mode validates with backend health, frontend load, login, and representative SOC workflows.
3. High-impact action terminal states include governance and audit linkage.
4. Optional integrations fail explicitly and do not break the core dashboard.
5. Production claims cite run mode, prerequisites, and validation artifact.
