# Metatron Security Features Analysis (Code-Evidence Refresh)
**Generated:** 2026-04-15  
**Classification:** Current-State Code Evidence

---

## Overview

This document summarizes security-relevant implementation based on current repository code paths.  
Focus: what is demonstrably implemented, what is conditional, and where assurance risk remains.

---

## 1) Core Security Control Surfaces

## 1.1 Authentication and Identity

| Capability | Evidence | Status |
|---|---|---|
| JWT creation/validation | `backend/routers/dependencies.py` | Implemented |
| Production/strict JWT secret enforcement | `dependencies.py` (`_resolve_jwt_secret`) | Implemented |
| Password hashing (bcrypt + PBKDF2 fallback) | `dependencies.py` | Implemented |
| Auth routes (`login`, `register`, `me`, setup flow) | `backend/routers/auth.py` | Implemented |

## 1.2 Authorization and Access Control

| Capability | Evidence | Status |
|---|---|---|
| Role-permission map (`admin`, `analyst`, `viewer`) | `dependencies.py` | Implemented |
| Permission dependency wrappers (`check_permission`) | `dependencies.py` | Implemented |
| Remote admin gating for non-local requests | `dependencies.py` (`REMOTE_ADMIN_ONLY`) | Implemented |
| Optional remote allowlist by admin email | `dependencies.py` (`REMOTE_ADMIN_EMAILS`) | Implemented |

## 1.3 Machine-to-Machine Controls

| Capability | Evidence | Status |
|---|---|---|
| Shared-token route dependencies (`require_machine_token`) | `dependencies.py` | Implemented |
| Constant-time machine token compare | `dependencies.py` (`hmac.compare_digest`) | Implemented |
| WebSocket machine-token verification | `dependencies.py`, `backend/server.py` | Implemented |
| World ingest token contract | `backend/routers/world_ingest.py` | Implemented |

---

## 2) Governance and High-Impact Action Controls

| Capability | Evidence | Status |
|---|---|---|
| Governance context requirement defaults in prod/strict | `backend/services/governance_context.py` | Implemented |
| Outbound gate queueing for high-impact actions | `backend/services/outbound_gate.py` | Implemented |
| Mandatory high-impact action categories | `outbound_gate.py` (`MANDATORY_HIGH_IMPACT_ACTIONS`) | Implemented |
| Governance executor background loop | `backend/services/governance_executor.py` | Implemented |
| Governance execution audit integration | `governance_executor.py` + telemetry chain | Implemented |

### Practical interpretation

- Architecture supports “queue -> decision -> governed execution” behavior.
- In production-like deployments, direct unguided execution can be blocked by governance-context rules.
- Durability/scale behavior should be validated under restart and concurrent workload scenarios.

---

## 3) API/Platform Hardening Controls

| Capability | Evidence | Status |
|---|---|---|
| CORS explicit origin enforcement in prod/strict | `backend/server.py` (`_resolve_cors_origins`) | Implemented |
| Integration API key requirement in production | `backend/server.py` (`INTEGRATION_API_KEY`) | Implemented |
| CSPM scan endpoint authenticated | `backend/routers/cspm.py` (`Depends(get_current_user)`) | Implemented |
| Backend health endpoint | `backend/server.py` (`/api/health`) | Implemented |

### Notable CSPM behavior

`/api/v1/cspm/scan` is authenticated and includes governance gate integration before scan orchestration, with fallback behavior if gate emission fails.

---

## 4) Domain Security Capabilities (Current Surface)

| Domain | Evidence (examples) | Status |
|---|---|---|
| Threat detection/intel/correlation | `threat_intel.py`, `threat_correlation.py`, routers | Implemented |
| Response/quarantine/SOAR | `threat_response.py`, `quarantine.py`, `soar_engine.py` | Implemented |
| Identity and zero-trust | `routers/identity.py`, `routers/zero_trust.py`, services | Implemented |
| Email protection | `backend/email_protection.py`, router | Implemented |
| Email gateway | `backend/email_gateway.py`, `routers/email_gateway.py` | Implemented |
| Mobile security | `backend/mobile_security.py`, router | Implemented |
| MDM connectors | `backend/mdm_connectors.py`, `routers/mdm_connectors.py` | Implemented |
| Kernel/host security services | kernel sensor/secure boot routes and modules | Implemented |
| SIEM/Sensor integrations | compose + backend integration modules | Implemented/Optional |

---

## 5) Deployment-Security Characteristics

## 5.1 Baseline compose (`docker-compose.yml`)

- Core services: MongoDB, Redis, backend, frontend, Celery worker/beat.
- Security/sandbox integrations are present with optional profiles for subsets.
- Many ports default to loopback binds via `BIND_*` variables.

## 5.2 Production overlay (`docker-compose.prod.yml`)

- Backend/frontend/data service ports are internalized.
- Nginx is the intended external ingress surface.
- `ENVIRONMENT=production` and strict security posture flags are enabled by default.

---

## 6) Security Risks / Assurance Gaps

1. **Consistency risk across all active and legacy routes**  
   Hardening controls are strong in primary paths; parity across every surface remains a maintenance burden.

2. **Contract drift and mixed frontend API path construction**  
   Inconsistent endpoint construction patterns in pages increase risk of security bugs and misrouting.

3. **Verification depth**  
   Broader negative-path testing is needed for authz/governance bypass resistance and strict-mode invariants.

4. **Operational secret complexity**  
   The integration-rich model depends on disciplined secret/env management in production.

---

## 7) Bottom Line

Security feature breadth is substantial and materially implemented in code.  
Current posture is strongest when running in strict/production modes with disciplined config.  
The next maturity step is not adding many new security features; it is enforcing **consistency and automated assurance** across the existing large surface area.

