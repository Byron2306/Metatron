# Feature Reality Matrix (Code-Verified)

Generated: 2026-04-24  
Scope: quantitative, code-backed implementation matrix

## Legend
- `PASS`: implemented and executable in normal configured environments.
- `PARTIAL`: implemented but constrained by missing runtime parity, optional dependencies, or incomplete lifecycle coverage.
- `LIMITED`: present primarily as stub/metadata/partial compatibility behavior.

---

## Platform Snapshot

| Metric | Value |
|---|---:|
| Backend router files (`backend/routers/*.py`) | 62 |
| Router definitions (`APIRouter(...)`) | 65 |
| Endpoint decorators (`@router.get/post/put/delete/patch`) | 694 |
| Frontend pages (`frontend/src/pages/*.jsx`) | 68 |
| Docker services (`docker-compose.yml`) | 21 |

---

## Domain Reality Matrix

| Domain | Status | Evidence | Practical Notes |
|---|---|---|---|
| Backend route composition | PASS | `backend/server.py` | 65 `include_router(...)` calls, broad domain coverage. |
| Auth + RBAC + machine token helpers | PASS | `backend/routers/dependencies.py` | JWT, permission checks, remote admin gate, machine token validation utilities. |
| CORS strictness controls | PASS | `backend/server.py` | Strict/prod mode rejects wildcard origins. |
| Core SOC APIs (threats/alerts/hunting/timeline/response/SOAR) | PASS | `backend/routers/*.py` | Operational breadth is high and fronted by active UI routes/workspaces. |
| Unified agent lifecycle + EDM APIs | PASS | `backend/routers/unified_agent.py` | Registration, heartbeat, telemetry shaping, EDM governance/rollout surfaces. |
| Endpoint monitor stack | PASS | `unified_agent/core/agent.py` | 27 unique monitor assignments (+ conditional WebView2). |
| Email Protection | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | SPF/DKIM/DMARC, phishing, DLP, quarantine/protected user management. |
| Email Gateway | PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Inline decisioning works; allowlist delete endpoint is missing. |
| Mobile Security | PASS | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device lifecycle/compliance/threat flows and dashboard APIs. |
| MDM Connector Management | PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Intune + JAMF runtime support; enum/docs mention extra platforms not provisioned by manager. |
| CSPM | PASS | `backend/routers/cspm.py`, `backend/cspm_engine.py` | Auth-protected scan endpoint, provider state, durable finding/scan records. |
| Advanced services (MCP/Memory/VNS/Quantum/AI) | PASS/PARTIAL | `backend/routers/advanced.py`, `backend/services/*` | Large operational surface; some runtime behavior depends on optional infra. |
| Governance approval/executor loop | PASS | `backend/routers/governance.py`, `backend/services/governance_executor.py` | Pending/approve/deny and run-once executor paths are in place. |
| Browser isolation | PARTIAL | `backend/browser_isolation.py`, router | Functional controls present; full remote-browser parity still limited. |
| Compose runtime topology | PASS | `docker-compose.yml` | 21 services, including backend/frontend/db, observability, security tools, and workers. |

---

## Endpoint Surface Checks (Selected)

| Area | Count |
|---|---:|
| Email Gateway router endpoints | 12 |
| Email Protection router endpoints | 17 |
| MDM Connectors router endpoints | 18 |

---

## Corrected Reality Notes

1. **MDM support is not 4-platform runtime-complete.**  
   `MDMConnectorManager.add_connector(...)` currently provisions Intune and JAMF only.

2. **Email Gateway allowlist is not full CRUD today.**  
   Add/list exists; remove endpoint is not present.

3. **Large API surface increases drift risk.**  
   High endpoint count plus active frontend workspace redirects requires explicit contract testing discipline.

---

## Residual Risk Tags

- `contract_drift`: High
- `capability_claim_parity`: High
- `hardening_consistency`: Medium
- `optional_integration_variability`: Medium
- `core_feature_absence`: Low

---

## Bottom Line

Core capability reality is strong.  
Main risk is consistency and parity management across docs, UI assumptions, and backend contracts.
