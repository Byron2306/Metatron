# Feature Reality Matrix (Code-Evidence Refresh)

**Reviewed:** 2026-04-24  
**Purpose:** Quantitative status snapshot aligned to current code logic

---

## Legend
- **PASS**: Real logic executes in normal configured environments.
- **PARTIAL**: Real implementation exists, but live depth depends on external prerequisites or incomplete provider branches.
- **LIMITED**: Present mainly as scaffold, fallback, or reduced-depth path.

---

## Domain Score Matrix

| Domain | Score (0-10) | Status | Evidence Anchors |
|---|---:|---|---|
| Core API Composition | 9.2 | PASS | `backend/server.py`, `backend/routers/*` |
| AuthN/AuthZ Controls | 8.9 | PASS | `backend/routers/dependencies.py`, `backend/routers/auth.py` |
| Unified Agent Control Plane | 9.3 | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` |
| Email Protection | 8.7 | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` |
| Email Gateway | 8.4 | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` |
| Mobile Security | 8.2 | PASS | `backend/mobile_security.py`, `backend/routers/mobile_security.py` |
| MDM Connectors | 6.8 | PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` |
| CSPM Plane | 8.4 | PASS/PARTIAL | `backend/cspm_engine.py`, `backend/routers/cspm.py` |
| Identity Protection Surface | 8.1 | PASS | `backend/routers/identity.py`, related services |
| Quarantine/Response/SOAR | 8.3 | PASS | `backend/quarantine.py`, `backend/threat_response.py`, `backend/soar_engine.py` |
| Browser Isolation | 6.5 | PARTIAL | `backend/browser_isolation.py` |
| Kernel / Secure Boot Surfaces | 7.8 | PASS/PARTIAL | `/api/v1/kernel`, `/api/v1/secure-boot` routers/services |

---

## Current Reality Matrix

| Capability | Status | Evidence | Practical Note |
|---|---|---|---|
| Backend-router mesh mounted and active | PASS | `backend/server.py` | High route breadth; central wiring remains dense. |
| JWT + role permissions | PASS | `backend/routers/dependencies.py` | Includes production/strict secret enforcement and remote admin gating. |
| Unified agent enrollment + heartbeat + commands | PASS | `backend/routers/unified_agent.py` | Includes auth checks, command lifecycle, installer endpoints. |
| EDM governance controls | PASS | `backend/routers/unified_agent.py` | Dataset versioning, publish, rollout, advance, rollback endpoints. |
| Email risk analysis APIs | PASS | `backend/routers/email_protection.py` | SPF/DKIM/DMARC + URL/attachment/DLP analysis exposed. |
| Email gateway management APIs | PASS | `backend/routers/email_gateway.py` | Processing/quarantine/policy/list operations present. |
| Mobile device posture workflows | PASS | `backend/routers/mobile_security.py` | Register, update status, analyze app, compliance/threat flows. |
| MDM platform abstraction | PARTIAL | `backend/mdm_connectors.py` | Intune/JAMF implemented; Workspace ONE/Google currently scaffolded in enums/UI metadata but not manager branch implementation. |
| MDM live-provider behavior | PARTIAL | `backend/mdm_connectors.py` | Contains mock token/response fallback paths for missing dependencies/credentials. |
| CSPM authenticated scan start | PASS | `backend/routers/cspm.py` | `POST /api/v1/cspm/scan` requires current user. |
| CSPM no-provider usability path | PASS/PARTIAL | `backend/routers/cspm.py` | Seeds demo data and returns demo scan if no providers configured. |
| Frontend workspace routing | PASS | `frontend/src/App.js` | Legacy routes redirected to workspace tabs; protected-route shell is active. |

---

## Evidence-Based Corrections to Prior Claims

1. **Outdated inventory counts** (routers/services/pages) from older docs should be treated as stale snapshots, not present facts.  
2. **MDM claim correction:** multi-platform framing should be "framework present; live execution strongest for Intune/JAMF paths today, with explicit fallback/mock behavior."  
3. **CSPM claim correction:** operational APIs are real, but no-provider mode intentionally returns seeded demo posture data.  
4. **Unified agent sidecar clarification:** `unified_agent/server_api.py` remains a local in-memory/proxy utility, not the authoritative persisted backend control plane.

---

## Bottom line

Current implementation reality is strongest in core API composition, control-plane orchestration, and cross-domain SOC workflow coverage. Remaining maturity work is concentrated in production integration depth (especially external provider connectors) and uniform assurance hardening across all surfaces.
