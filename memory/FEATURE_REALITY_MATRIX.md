# Metatron Feature Reality Matrix (Code-Revalidated)

Generated: 2026-04-14  
Scope: Quantitative/contract reality matrix verified against current backend/frontend/runtime code.

## Legend

- **PASS**: Implemented and routable in normal configured environments.
- **PASS/PARTIAL**: Implemented with meaningful runtime constraints (credentials, optional services, or known auth semantics issue).
- **PARTIAL**: Capability family exists but depth/operational mode is limited.

---

## Feature Maturity Table

| Domain | Status | Evidence Anchors | Notes |
|---|---|---|---|
| Backend Router Mesh | PASS | `backend/server.py`, `backend/routers/*` | Large active route surface registered under `/api` plus `/api/v1/*` routers. |
| Auth + Access Control | PASS/PARTIAL | `backend/routers/dependencies.py` | JWT, bcrypt/PBKDF2 fallback, remote-admin gate; `"admin"` permission token mismatch affects some routes. |
| Unified Agent APIs | PASS | `backend/routers/unified_agent.py` | Registration, heartbeat, commands, EDM datasets/rollouts, deployments, installers, monitor stats. |
| Email Protection | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | Analysis, auth checks, DLP checks, quarantine + policy lists. |
| Email Gateway | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Processing/quarantine/list controls; policy update endpoint gated by broken admin-permission token usage. |
| Mobile Security | PASS | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device lifecycle/compliance/threat/app-analysis/dashboard endpoints. |
| MDM Connectors | PASS/PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Connector framework and actions are real; multiple admin endpoints impacted by permission mismatch. |
| CSPM | PASS | `backend/routers/cspm.py`, `backend/cspm_engine.py` | Authenticated scan start, durable scan/finding transitions, provider config/report/export APIs. |
| Identity Protection | PASS | `backend/routers/identity.py`, `backend/identity_protection.py` | Durable incidents, provider ingest token gates, token-abuse analytics, response action workflow. |
| Deployment Service | PASS/PARTIAL | `backend/services/agent_deployment.py` | Real SSH/WinRM deployments + retries + state transitions; simulation is explicitly gated. |
| Governance Pipeline | PASS | `backend/routers/governance.py`, `backend/services/g*` | Pending/approve/deny/executor routes with DB-backed triune decision processing. |
| Browser Isolation | PARTIAL | `backend/browser_isolation.py`, router | URL analysis/filtering exists; full remote-browser isolation is not default runtime behavior. |

---

## Contract and Permission Matrix

| Area | Current Contract | Verified Behavior | Risk |
|---|---|---|---|
| JWT secret handling | Required/strict in prod-like mode | Weak/missing JWT secret causes warnings or startup failure in strict/prod mode | Low |
| Remote admin gate | Non-local access restricted | `REMOTE_ADMIN_ONLY` enforces admin/allowlist gate for remote requests | Low |
| Machine-token endpoints | Header token required for ingest/ws paths | `require_machine_token` and websocket token checks present | Low |
| `check_permission("write")` endpoints | Role-based permission check | Works for `admin` and `analyst` roles via permission table | Low |
| `check_permission("admin")` endpoints | Intended admin-only behavior | Fails for all roles because `"admin"` is not a permission literal in `ROLES` | **High** |

---

## API Surface Reality Highlights

| Domain | Representative Paths | Status |
|---|---|---|
| Core auth | `/api/auth/register`, `/api/auth/login`, `/api/auth/me`, `/api/auth/setup` | PASS |
| Unified agents | `/api/unified/agents/register`, `/api/unified/agents/{id}/heartbeat`, `/api/unified/deployments` | PASS/PARTIAL (admin check issue on some operations) |
| Email protection | `/api/email-protection/analyze`, `/api/email-protection/quarantine` | PASS |
| Email gateway | `/api/email-gateway/process`, `/api/email-gateway/blocklist`, `/api/email-gateway/policies/{name}` | PASS/PARTIAL |
| Mobile | `/api/mobile-security/devices`, `/api/mobile-security/analyze-app` | PASS |
| MDM | `/api/mdm/connectors`, `/api/mdm/sync/now`, `/api/mdm/devices/{id}/wipe` | PASS/PARTIAL |
| CSPM | `/api/v1/cspm/scan`, `/api/v1/cspm/findings`, `/api/v1/cspm/dashboard` | PASS |
| Identity | `/api/v1/identity/events/*`, `/api/v1/identity/analytics/token-abuse`, `/api/v1/identity/response/actions` | PASS |

---

## Runtime/Deployment Reality

| Runtime Concern | Current State |
|---|---|
| Primary stack topology | `docker-compose.yml` defines MongoDB, Redis, backend, frontend, celery worker/beat, optional security/sandbox services. |
| Health model | Backend exposes `/api/health`; compose healthchecks defined for core services. |
| API base on frontend | `frontend/src/lib/api.js` and auth context resolve API root to `${REACT_APP_BACKEND_URL}/api` or `/api`. |
| Startup workers | Backend startup initializes CCE, network discovery, deployment service, AATL/AATR, scheduler, governance executor. |
| Optional integrations | Security/sandbox/cloud/provider functionality depends on profile activation and credentials. |

---

## Remaining High-Impact Gaps

1. Fix admin permission-token mismatch (`check_permission("admin")` usage).
2. Confirm live production credentials/workflows for SMTP relay and MDM connectors where required.
3. Continue reducing legacy surface ambiguity (primary backend vs adjunct portal APIs).

---

## Bottom Line

The platform is broad and substantially real in code, but critical docs must account for the **authorization semantics edge case** and **provider credential dependencies**. The largest issue is contract correctness in access-control expression, not lack of core feature implementation.
