# Feature Reality Matrix (Code-Verified)

Generated: 2026-04-19  
Scope: Quantitative snapshot of currently implemented behavior from repository code

## Legend
- `PASS`: Implemented and wired with active backend/API or agent runtime behavior.
- `PARTIAL`: Implemented but with material limits, placeholder breadth, or mixed durability model.
- `LIMITED`: Exposed in UI/contracts but not fully backed by implementation.

---

## Feature Maturity Score Table

| Domain | Score (0-10) | Status | Evidence Highlights |
|---|---:|---|---|
| Backend Router Mesh | 9.0 | PASS | `backend/server.py` includes broad `/api` and `/api/v1` router composition |
| Unified Agent Control Plane | 9.0 | PASS | `backend/routers/unified_agent.py` (register/heartbeat/commands/deployments/EDM) |
| Endpoint Monitor Fleet | 9.0 | PASS | `unified_agent/core/agent.py` monitor registry includes email/mobile/kernel/ransomware/etc. |
| EDM + DLP Governance | 8.8 | PASS | Unified EDM dataset/version/publish/rollback routes + agent telemetry loops |
| Email Protection | 8.8 | PASS | `backend/email_protection.py` + `backend/routers/email_protection.py` |
| Email Gateway | 8.5 | PASS | `backend/email_gateway.py` + `backend/routers/email_gateway.py` |
| Mobile Security | 8.5 | PASS | `backend/mobile_security.py` + `backend/routers/mobile_security.py` |
| MDM Connectors | 6.8 | PARTIAL | Intune/JAMF implemented; Workspace ONE/Google Workspace listed but not implemented in manager |
| CSPM | 8.6 | PASS/PARTIAL | Auth + DB durability paths present; mixed in-memory/global state still used |
| Identity + Governance Planes | 8.2 | PASS/PARTIAL | Rich controls and routes; assurance consistency is ongoing |
| Zero Trust + Browser Isolation | 7.5 | PARTIAL | Feature-complete APIs with uneven depth depending on scenario |
| Kernel/Secure Boot | 8.0 | PASS/PARTIAL | Secure boot + kernel sensors wired; maturity depends on host/runtime conditions |

---

## Current Reality Matrix

| Domain | Status | Code Evidence | Practical Notes |
|---|---|---|---|
| API Composition | PASS | `backend/server.py` | Extensive router inclusion across SOC, agent, enterprise, triune, and security domains. |
| Auth + RBAC Controls | PASS | `backend/routers/dependencies.py` | JWT resolution hardening, role checks, and permission dependencies are active. |
| Unified Agent Lifecycle | PASS | `backend/routers/unified_agent.py` | Register/heartbeat/command paths are comprehensive and DB-integrated. |
| EDM Rollout + Dataset Governance | PASS | `backend/routers/unified_agent.py` | Dataset versions, publish, rollback, and rollout progression endpoints are present. |
| Email Protection APIs | PASS | `backend/routers/email_protection.py` | Analyze/auth/DLP/quarantine/protected-users and sender/domain list operations. |
| Email Gateway APIs | PASS | `backend/routers/email_gateway.py` | Stats/process/quarantine/policy/blocklist/allowlist endpoints with auth guards. |
| Mobile Security APIs | PASS | `backend/routers/mobile_security.py` | Device, threat, compliance, app analysis, and dashboard endpoints wired. |
| MDM Connector APIs | PARTIAL | `backend/routers/mdm_connectors.py` | API exposes 4-platform catalog; backend connector manager supports Intune/JAMF only. |
| MDM Connector Runtime | PARTIAL | `backend/mdm_connectors.py` | `MDMPlatform` enum includes 4 platforms, but manager adds only Intune/JAMF. |
| CSPM Auth + Governance | PASS | `backend/routers/cspm.py` | Scan start requires authenticated user and uses outbound gating + world events. |
| CSPM Data Durability | PASS/PARTIAL | `backend/routers/cspm.py` | DB-backed scans/findings with transition logs exist; still coupled with in-memory globals. |
| Frontend Routing + Workspaces | PASS | `frontend/src/App.js` | Consolidated workspace-style routing with tab redirects and guarded app shell. |
| Frontend MDM UX | PARTIAL | `frontend/src/pages/MDMConnectorsPage.jsx` | UI advertises 4 connector platforms; practical backend support is currently 2. |

---

## Corrected Claims vs Older Documentation

1. **MDM platform support is not fully 4-platform operational in runtime manager code.**  
   - Intune and JAMF are implemented connector classes.  
   - Workspace ONE and Google Workspace are currently exposed as options/metadata but not wired connector classes in `MDMConnectorManager.add_connector`.

2. **Email Gateway and Email Protection claims are broadly accurate and materially implemented.**

3. **CSPM hardening claim is valid for authentication and guarded actions; durability model is improved but still hybrid (DB + in-memory state).**

---

## Open Gaps (Most Actionable)

1. Add Workspace ONE and Google Workspace connector classes and manager integration.
2. Reduce contract drift between frontend-advertised capabilities and backend runtime support.
3. Replace sync helper patterns that call `asyncio.run(...)` in background contexts with cleaner async execution strategy.
4. Continue converging on fully durable state (less mixed in-memory/global control-plane state).

---

## Bottom Line

The platform is strong, broad, and active across backend, agent, and frontend layers.  
The most material documentation correction is MDM breadth: **2 connectors implemented (Intune/JAMF), 2 connectors currently listed but not implemented in runtime manager behavior**.
