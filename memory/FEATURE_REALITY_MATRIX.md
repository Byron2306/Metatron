# Metatron Feature Reality Matrix (Rebaselined)

**Generated:** 2026-04-16  
**Scope:** Quantitative implementation snapshot with corrected status levels.

## Legend

- `PASS`: Real logic executes under normal configured conditions.
- `PARTIAL`: Implemented with meaningful constraints (durability, auth normalization, dependency assumptions, or incomplete adapters).
- `LIMITED`: Present as compatibility/placeholder scaffolding without full runtime depth.

---

## Current Reality Matrix

| Domain | Status | Evidence | Practical Notes |
|---|---|---|---|
| Backend primary route composition | PASS | `backend/server.py` | Broad modular wiring; still a dense central orchestration file. |
| Unified agent register/heartbeat | PASS | `backend/routers/unified_agent.py` | Authenticated agent lifecycle with monitor and telemetry ingestion. |
| Agent command governance | PASS | `backend/routers/unified_agent.py`, `backend/services/governed_dispatch.py` | High-impact command flows are queued for triune approval. |
| EDM dataset lifecycle | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Dataset versioning, signatures, fanout, staged rollouts, rollback. |
| Deployment queue/execution | PASS/PARTIAL | `backend/services/agent_deployment.py` | Real SSH/WinRM + retries + transitions; quality depends on credentials/env readiness. |
| Unified deployment durability | PASS | `backend/routers/unified_agent.py` | `state_version` + transition logs and sync with deployment tasks. |
| Identity incident durability | PASS | `backend/routers/identity.py` | Versioned incident transitions and persisted incident/action collections. |
| CSPM scan orchestration | PASS/PARTIAL | `backend/routers/cspm.py`, `backend/cspm_engine.py` | Authenticated scan flow and durability paths, but auth consistency is not uniform for all endpoints. |
| Auth/RBAC baseline | PASS | `backend/routers/dependencies.py`, `backend/routers/auth.py` | JWT hardening, role checks, optional setup token, remote admin gate. |
| Email protection analysis | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | SPF/DKIM/DMARC, phishing/URL/attachment/DLP, quarantine APIs. |
| Email gateway API processing | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Decision engine + quarantine/list/policy APIs; in-memory queue/state and integration constraints remain. |
| Mobile security workflows | PASS/PARTIAL | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device/threat/compliance/app analysis implemented; runtime state is in-memory. |
| MDM connector management | PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Manager adds Intune/JAMF connectors; additional listed platforms not fully implemented in manager routing. |
| Frontend security workspaces | PASS/PARTIAL | `frontend/src/pages/*.jsx,*.tsx` | Broad page coverage; some pages depend on backend module maturity parity. |

---

## Security and Hardening Matrix

| Control | Status | Evidence |
|---|---|---|
| Production JWT secret enforcement | PASS | `backend/routers/dependencies.py` (`_resolve_jwt_secret`) |
| Strict CORS enforcement | PASS | `backend/server.py` (`_resolve_cors_origins`) |
| Remote admin gate | PASS | `backend/routers/dependencies.py` (`REMOTE_ADMIN_ONLY`) |
| Machine-token route protection | PASS | multiple routers via `require_machine_token` / related helpers |
| CSPM scan auth | PASS | `backend/routers/cspm.py` (`Depends(get_current_user)`) |
| Uniform auth across all CSPM routes | PARTIAL | `backend/routers/cspm.py` |

---

## Reality-Critical Gaps

1. In-memory operational state in selected domain services.
2. MDM platform claim breadth exceeds manager instantiation depth.
3. Route-level auth consistency still needs normalization in some surfaces.
4. Core orchestration remains centralized in large files.

---

## Bottom Line

The platform has strong real implementation density where it matters most (unified control plane, governance, durability patterns), but domain parity and consistency hardening remain the central work needed to match the strongest enterprise expectations.
