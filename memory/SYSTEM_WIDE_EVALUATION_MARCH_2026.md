# Metatron/Seraph AI Defender - System-Wide Evaluation (Updated)

Date: 2026-04-14  
Classification: Code-evidence system evaluation  
Scope: Rebaseline against current backend/frontend/runtime implementation.

---

## Executive Summary

The platform remains high-breadth and implementation-heavy, with strong evidence of active hardening and durability patterns in multiple domains (CSPM, Identity, Deployment, Unified Agent EDM controls).  

The biggest system-wide correction is not capability breadth; it is **authorization contract consistency**. Several endpoints currently use `check_permission("admin")`, but the permission table does not include an `"admin"` permission token, causing those routes to reject all users.

### Updated System Position

- Architecture breadth: **High**
- Operational implementation depth: **High**
- Security control consistency: **Medium-High**
- Contract consistency: **Medium (improving, with clear active mismatch)**
- Enterprise readiness: **Strong with specific integration and auth-gate caveats**

---

## 1) Major Verified Improvements

### 1.1 Backend Runtime Maturity

Evidence:
- `backend/server.py`
- `backend/runtime_paths.py`

Verified:
- Mongo initialization supports real backend and mock mode.
- CORS logic enforces stricter behavior in strict/prod mode.
- Startup orchestration launches CCE, network discovery, deployment service, AATL/AATR, integrations scheduler, and governance executor.
- Writable data-path fallback handling exists via runtime path helper.

### 1.2 Durable State Transition Patterns

Evidence:
- `backend/routers/cspm.py`
- `backend/routers/identity.py`
- `backend/services/agent_deployment.py`

Verified:
- Multiple domains implement explicit transition logs and versioned state updates.
- Conflict handling patterns are present for concurrent updates.
- Terminal-state protections exist for findings/incidents/deployment tasks.

### 1.3 Unified Agent Control Surface

Evidence:
- `backend/routers/unified_agent.py`
- `backend/services/agent_deployment.py`

Verified:
- Full agent lifecycle APIs (register, heartbeat, command, command result, status).
- Deployment queueing and retries with explicit simulation gating.
- EDM dataset/version/rollout endpoints are implemented and extensive.

### 1.4 Domain Breadth Still Strong

Evidence:
- Email: `backend/routers/email_protection.py`, `backend/routers/email_gateway.py`
- Mobile/MDM: `backend/routers/mobile_security.py`, `backend/routers/mdm_connectors.py`
- Cloud/Identity: `backend/routers/cspm.py`, `backend/routers/identity.py`

Verified:
- Domain-specific endpoint families are materially implemented and wired into backend runtime.

---

## 2) Critical Current Risks

### 2.1 Permission-Token Mismatch (High)

Evidence:
- `backend/routers/dependencies.py` permission model (`ROLES`)
- Routes using `check_permission("admin")` in:
  - `backend/routers/email_gateway.py`
  - `backend/routers/mdm_connectors.py`
  - `backend/routers/mobile_security.py`
  - `backend/routers/unified_agent.py`
  - `backend/routers/swarm.py`
  - `backend/routers/agents.py`

Finding:
- `check_permission` expects a permission string (for example `write`, `manage_users`), not a role name.
- Because `"admin"` is not listed as a permission in `ROLES`, those endpoints fail authorization even for admin-role users.

Impact:
- Operationally important admin-marked APIs are effectively inaccessible.

### 2.2 Integration-Dependent Feature Completion (Medium)

Finding:
- Some domains are framework-complete but still require external credentials/services for full real-world value:
  - CSPM providers,
  - MDM providers,
  - SMTP relay/infrastructure details.

### 2.3 Entry Surface Ambiguity (Medium)

Finding:
- Primary backend contract is `backend/server.py` (:8001), while `unified_agent/server_api.py` (:8002) provides additional portal/proxy behavior.
- Documentation must clearly mark which interface is authoritative.

---

## 3) Domain Scorecard (0-5)

| Domain | Score | Notes |
|---|---:|---|
| Core API architecture | 4.4 | Strong modular surface; central bootstrap still dense. |
| AuthN/AuthZ design | 3.8 | JWT + role model strong; permission literal mismatch lowers practical score. |
| Unified agent plane | 4.4 | Broad lifecycle/EDM/deployment flows with durable transitions. |
| CSPM | 4.3 | Authenticated scan path, stateful findings, provider config model. |
| Identity protection | 4.3 | Ingest analytics/response pipeline and durable incident model. |
| Email security | 4.1 | Deep route/service implementation; policy admin route issue noted. |
| Mobile/MDM | 4.1 | Broad capability with admin-route gating issue. |
| Reliability/operations | 4.0 | Compose healthchecks + startup workers; optional dependencies still variable. |
| Verification maturity | 3.9 | Strong targeted tests, but high-change surfaces still need broader denial-path coverage. |

Composite: **4.1 / 5**

---

## 4) Recommended Next Actions (Technical Priority Order)

1. **Fix authorization semantics immediately**
   - Replace `check_permission("admin")` with a valid permission model or explicit role gate.

2. **Normalize contract docs to active runtime**
   - Re-anchor docs around primary backend API contract and list adjunct/compatibility surfaces separately.

3. **Separate framework-complete vs integration-complete status in all reporting**
   - Prevent overstatement for credential-dependent features.

4. **Expand regression suite for authorization/denial paths**
   - Add targeted tests for role/permission combinations across affected routers.

---

## 5) Final Conclusion

Metatron/Seraph is a strong, feature-rich platform with real implementation depth across core SOC and endpoint/cloud/identity flows.  

The immediate system-level maturity limiter is not missing security domains; it is **policy enforcement consistency** in selected admin-gated routes. Correcting that issue materially improves practical enterprise readiness.
