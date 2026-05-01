# Seraph AI Defender - Technical Implementation Roadmap

**Updated:** 2026-05-01
**Purpose:** Align future work with the current implementation rather than stale March snapshots.

## 1) Current foundation

The repository already contains the major product planes:

- FastAPI backend with 62 router modules (`backend/server.py`, `backend/routers/`).
- React SOC dashboard with protected workspace routes (`frontend/src/App.js`, `frontend/src/pages/`).
- Unified endpoint agent (`unified_agent/core/agent.py`).
- Agent control plane (`backend/routers/unified_agent.py`).
- Email, mobile, MDM, CSPM, deception, triune, governance, and integrations code.
- Docker Compose runtime with backend 8001, frontend 3000, MongoDB, Redis, Celery, and optional security/AI/SIEM services.

The roadmap should therefore emphasize convergence, reliability, assurance, and operator clarity.

## 2) Workstreams

### WS-A: Contract integrity

Objective: make backend, frontend, scripts, and docs share a durable API truth.

Priority tasks:
1. Generate a route inventory from `backend/server.py` and mounted routers.
2. Snapshot request/response schemas for critical routes.
3. Add CI checks for frontend API paths and script endpoint references.
4. Keep legacy redirects and aliases documented with deprecation intent.

Primary files:
- `backend/server.py`
- `backend/routers/`
- `frontend/src/lib/api.js`
- `frontend/src/App.js`
- `scripts/`

### WS-B: Runtime reliability

Objective: make success states represent real execution and make degraded mode explicit.

Priority tasks:
1. Strengthen deployment evidence for SSH/WinRM and unified-agent deployment paths.
2. Standardize background worker status for Celery, CCE, discovery, and optional integrations.
3. Add preflight checks for required services and credentials.
4. Update UI status panels for optional integrations.

Primary files:
- `backend/services/agent_deployment.py`
- `backend/services/network_discovery.py`
- `backend/services/cce_worker.py`
- `docker-compose.yml`
- `memory/RUN_MODE_CONTRACT.md`

### WS-C: Governance hardening

Objective: move governance primitives from strong concepts to restart-safe, audit-ready operation.

Priority tasks:
1. Persist policy decisions, token usage, approvals, and governed dispatch records.
2. Add replay prevention and max-use enforcement tests.
3. Add denial-path regression tests for high-risk actions.
4. Normalize hardening across primary and secondary API entrypoints.

Primary files:
- `backend/services/policy_engine.py`
- `backend/services/token_broker.py`
- `backend/services/tool_gateway.py`
- `backend/services/governed_dispatch.py`
- `backend/services/telemetry_chain.py`
- `backend/routers/dependencies.py`

### WS-D: Detection quality engineering

Objective: measure and improve detection quality rather than relying on feature count.

Priority tasks:
1. Build replay scenarios for endpoint, email, mobile, identity, and AI-agentic detections.
2. Track precision, false-positive suppressions, latency, and missed detections.
3. Add ATT&CK coverage evidence tied to executed tests.
4. Publish quality summaries in `test_reports/`.

Primary files:
- `backend/services/aatl.py`
- `backend/threat_hunting.py`
- `backend/email_protection.py`
- `backend/mobile_security.py`
- `unified_agent/core/agent.py`
- `backend/tests/`

### WS-E: Integration quality

Objective: prefer supported, tested connectors over connector sprawl.

Priority tasks:
1. Classify integrations as supported, best-effort, or experimental.
2. Add health contracts for MDM, SIEM, sandbox, Trivy/Falco/Suricata, and osquery integrations.
3. Document credential and environment prerequisites.
4. Add smoke tests for supported integrations where feasible.

Primary files:
- `backend/integrations_manager.py`
- `backend/routers/integrations.py`
- `unified_agent/integrations/`
- `unified_agent/integrations_client.py`
- `backend/mdm_connectors.py`

### WS-F: Platform experience

Objective: make operators understand what is live, degraded, simulated, or not configured.

Priority tasks:
1. Consolidate workspace navigation around canonical pages.
2. Surface run-mode status in the dashboard.
3. Keep root README and memory documents in sync with code changes.
4. Improve setup documentation for production SMTP, MDM credentials, CORS, and M2M keys.

Primary files:
- `frontend/src/App.js`
- `frontend/src/components/Layout.jsx`
- `frontend/src/pages/*WorkspacePage.jsx`
- `README.md`
- `DEPLOYMENT.md`
- `memory/*.md`

## 3) Near-term execution priorities

1. **Contract map and docs alignment**
   - Generate route/page inventory.
   - Update README and memory docs when route contracts change.

2. **Deployment truth**
   - Attach evidence to deployment completion.
   - Clarify queued, simulated, failed, and verified states.

3. **Governance durability**
   - Persist high-risk decisions and dispatch artifacts.
   - Test restart behavior.

4. **Optional integration clarity**
   - Health schema per optional integration.
   - UI language for unavailable vs degraded vs configured.

5. **Security denial-path tests**
   - CSPM, MDM admin, email gateway write actions, unified commands, and governed tool execution.

## 4) Acceptance gates

| Gate | Requirement |
| --- | --- |
| Contract integrity | Critical frontend paths map to active backend routes or documented redirects. |
| Runtime truth | Deployment success includes verification evidence or is explicitly marked as unverified/simulated. |
| Governance | High-risk actions produce policy, token, dispatch, and telemetry evidence. |
| Detection quality | Key detection domains have replay or regression coverage. |
| Integration status | Optional services expose clear configured/degraded/unavailable state. |

## 5) Expected outcome

Seraph should continue to position as a governed adaptive defense platform. The next engineering gains should come from reliability, contract assurance, production hardening, and measured detection quality rather than additional ungoverned feature breadth.
