# Metatron Feature Reality Matrix

Generated: 2026-04-17  
Scope: Quantitative and contract-focused implementation snapshot.

## Legend
- `PASS`: Real logic executes in standard configured runs.
- `PASS/PARTIAL`: Real logic exists, but durability/integration parity is incomplete.
- `PARTIAL`: Contract/API exists with notable runtime or implementation gaps.

---

## Platform Metrics Snapshot

| Metric | Current value |
|---|---:|
| Routers included in backend app (`server.py`) | 65 |
| Router modules in `backend/routers` | 65 |
| Route decorators across routers (approx) | 694 |
| Frontend route entries in `App.js` | 65 |
| Unified agent configured monitor keys | 27 |
| Unified agent `*Monitor` classes | 21 |

---

## Domain Reality Matrix

| Domain | Status | Evidence | Practical Notes |
|---|---|---|---|
| Backend route mesh | PASS | `backend/server.py`, `backend/routers/*.py` | Large modular API surface is real and wired. |
| Auth/JWT/CORS hardening | PASS | `backend/routers/dependencies.py`, `backend/server.py` | Strict/prod paths enforce stronger JWT/CORS behavior. |
| Unified agent registration/heartbeat/command | PASS | `backend/routers/unified_agent.py` | Core lifecycle is implemented and active. |
| EDM dataset governance | PASS | `backend/routers/unified_agent.py` | Versioning, signatures, publish, rollback, rollout/readiness endpoints are present. |
| Agent monitor runtime | PASS | `unified_agent/core/agent.py` | 27 configured monitor keys; platform-conditional monitor loading. |
| Deployment service realism | PASS/PARTIAL | `backend/services/agent_deployment.py` | Real SSH/WinRM paths + retries; simulation can be gated by env flag. |
| CSPM scan/findings plane | PASS/PARTIAL | `backend/routers/cspm.py` | Authenticated scans, transitions, and gating are real; demo fallback exists when providers are absent. |
| CSPM provider governance | PASS | `backend/routers/cspm.py` | Configure/remove provider operations queue via gating flow. |
| Email protection APIs | PASS/PARTIAL | `backend/email_protection.py`, `backend/routers/email_protection.py` | Rich API and logic; operational sets/quarantine are in-memory. |
| Email gateway APIs | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Gateway controls and scoring exist; state durability remains process-bound. |
| Mobile security APIs | PASS/PARTIAL | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Feature-rich, but service state is mainly in-memory maps. |
| MDM connector contract | PASS/PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Contract exposes 4 platforms; manager add path currently supports Intune + JAMF only. |
| Frontend workspace routing | PASS | `frontend/src/App.js`, `frontend/src/components/Layout.jsx` | Workspace-first UX is the current route model. |
| Email workspace wiring | PASS | `frontend/src/pages/EmailSecurityWorkspacePage.jsx` | Protection/gateway tab model is active. |
| Endpoint mobility workspace wiring | PASS | `frontend/src/pages/EndpointMobilityWorkspacePage.jsx` | Mobile/MDM tab model is active. |

---

## Critical Corrections to Prior Matrix Claims

1. **MDM completeness requires correction**
   - Prior matrices treated all 4 providers as fully implemented.
   - Current manager instantiation path supports Intune and JAMF only.

2. **Email/Mobile production durability requires correction**
   - Prior matrices implied stronger persisted operational state.
   - Current services still rely heavily on in-memory structures.

3. **CSPM "fully live cloud-backed" claims require nuance**
   - CSPM is strong and authenticated.
   - Scan behavior includes explicit demo-seed path when no providers are configured.

---

## Residual Gap List

1. Persist email/mobile operational state with durable storage parity.
2. Implement/enable Workspace ONE and Google Workspace connector manager paths.
3. Expand CI contract tests for workspace-critical routes and payloads.
4. Continue reducing startup coupling concentration in `backend/server.py`.

---

## Bottom Line

Metatron’s implementation reality is strong and broad.  
The most important remaining work is **durability and parity closure**, not foundational feature scaffolding.
