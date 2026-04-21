# Metatron Feature Reality Matrix (Code-Verified)

**Last revalidated:** 2026-04-21  
**Scope:** Quantitative and qualitative implementation snapshot from current repository logic

---

## Legend

- `PASS` = Real code path executes in normal configured environments.
- `PARTIAL` = Real implementation exists, but behavior depends on credentials/integration/runtime prerequisites.
- `LIMITED` = Present but constrained by in-memory state, demo fallback, compatibility path, or incomplete backend implementation.

---

## Domain Maturity Matrix

| Domain | Status | Evidence | Notes |
|---|---|---|---|
| Unified agent registration and heartbeat | PASS | `backend/routers/unified_agent.py` | Enrollment + token-based auth flow implemented |
| Unified agent command/control | PASS | `backend/routers/unified_agent.py` | Command queue/result/status flows implemented |
| Agent monitor execution | PASS | `unified_agent/core/agent.py` | Broad monitor set initialized, results aggregated in heartbeat |
| EDM dataset governance and rollout | PASS | `backend/routers/unified_agent.py` | Dataset versions, publish, rollout, readiness, rollback routes present |
| EDM endpoint-side matching | PASS | `unified_agent/core/agent.py` | DLP monitor includes EDM engine and hit loop-back |
| Deployment queue and state transitions | PASS | `backend/services/agent_deployment.py` | Versioned task/device transitions, retries, event emission |
| SSH/WinRM deployment execution | PARTIAL | `backend/services/agent_deployment.py` | Real methods present; requires valid credentials/connectivity |
| Simulated deployment mode | PARTIAL | `backend/services/agent_deployment.py` | Explicitly gated by `ALLOW_SIMULATED_DEPLOYMENTS` |
| CSPM provider config and scan flows | PARTIAL | `backend/routers/cspm.py` | Durable scans/findings + triune gating; real provider creds still required |
| CSPM demo fallback path | LIMITED | `backend/routers/cspm.py` | Seeds demo dataset when no providers are configured |
| Email protection analysis | PASS | `backend/email_protection.py`, router | SPF/DKIM/DMARC + URL/attachment/impersonation/DLP checks |
| Email gateway policy and processing | PASS | `backend/email_gateway.py`, router | Gateway decisioning + quarantine/list management are present |
| Mobile security service | PASS | `backend/mobile_security.py`, router | Device/threat/compliance/app analysis logic implemented |
| MDM connector framework | PARTIAL | `backend/mdm_connectors.py`, router | Manager currently instantiates Intune + JAMF connectors only |
| Identity router/service durability | PARTIAL | `backend/routers/identity.py` | Core flows exist; broader enterprise hardening remains uneven |
| Zero trust / governance surface | PARTIAL | `backend/routers/governance.py`, `services/*` | Broad feature set with varying depth by subsystem |
| Frontend page/API coverage | PARTIAL | `frontend/src/pages/*`, router map | Broad page set; contract drift risk remains due to velocity |

---

## Security and Access-Control Reality

| Control | Status | Evidence | Notes |
|---|---|---|---|
| JWT secret hardening in strict/prod | PASS | `backend/routers/dependencies.py` | Refuses weak/missing secret in strict/prod mode |
| Remote admin gate for non-local access | PASS | `backend/routers/dependencies.py` | `REMOTE_ADMIN_ONLY` and optional allowed email list |
| CORS strictness in strict/prod | PASS | `backend/server.py` | Rejects wildcard/no-origin config in strict/prod |
| Websocket machine-token validation | PASS | `backend/server.py`, dependencies | `/ws/agent/{agent_id}` validates machine token headers |
| Permission-model consistency | PARTIAL | `backend/routers/*` | Mixed permission vs role-like checks (`check_permission("admin")`) |

---

## Deployment and Runtime Reality

| Area | Status | Evidence | Notes |
|---|---|---|---|
| Containerized runtime topology | PASS | `docker-compose.yml` | 21 services defined, including optional security profiles |
| Localhost bind defaults for key services | PASS | `docker-compose.yml` | Backend, frontend, DB, redis and others default to loopback binds |
| Background worker startup orchestration | PASS | `backend/server.py` | CCE, network discovery, deployment, governance executor start attempts |
| Health endpoints | PASS | `backend/server.py` | `/api/health` and service-level health checks in compose |
| Full production integration certainty | PARTIAL | cross-module | Depends on secrets, cloud credentials, and external integration readiness |

---

## Reality Corrections vs Older Documentation

1. MDM support claims must be revised: enum lists four platforms, but manager add path currently supports only Intune and JAMF.
2. CSPM should be described as durable and triune-gated, but not always "live cloud only" because demo seeding exists.
3. Deployment should be described as real SSH/WinRM capable with explicit simulation flag, not purely simulated.
4. Permission enforcement language should note mixed semantics instead of claiming uniform RBAC.

---

## Current Overall Rating

- **Capability breadth:** Very high  
- **Execution realism:** Medium-high  
- **Durability consistency:** Medium  
- **Hardening consistency:** Medium  
- **Composite operational maturity (current code reality):** **~3.9 / 5**

