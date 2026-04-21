# Metatron / Seraph Platform - System-Wide Evaluation (Updated)

**Last revalidated:** 2026-04-21  
**Evaluation basis:** Direct code review of backend, unified agent, frontend, and deployment topology.

---

## 1) Executive Rebaseline

Earlier snapshots overstated some domain completeness. Current code shows:

- Strong platform breadth and substantial real logic across core domains.
- Mixed maturity across modules due to persistence and contract consistency differences.
- Partial mismatch between documented capability breadth and actual instantiated connectors in MDM.

**Current classification:** Advanced multi-domain security platform in an active hardening/consistency phase.

---

## 2) Verified Platform Surface

## Backend and control plane

- FastAPI server with broad router composition in `backend/server.py`.
- Unified agent lifecycle APIs (`/api/unified/*`) in `backend/routers/unified_agent.py`.
- CSPM plane in `backend/routers/cspm.py` with provider config, scans, findings, and dashboards.
- Email, mobile, and MDM routers present and wired.

## Agent and endpoint runtime

- Unified agent core implemented in `unified_agent/core/agent.py`.
- Register + heartbeat contract to backend is implemented.
- DLP/EDM engine logic, dataset reload/update commands, and EDM hit loop-back are implemented.

## Frontend

- Large React page surface in `frontend/src/pages`.
- Dedicated pages exist for key domains (UnifiedAgent, CSPM, EmailGateway, EmailProtection, MobileSecurity, MDMConnectors, etc.).

## Runtime topology

- `docker-compose.yml` defines a broad local stack including backend/frontend, MongoDB, Redis, Celery worker/beat, Elastic/Kibana, and optional security tooling.

---

## 3) Domain-by-Domain Reality (Updated)

| Domain | Current status | Evidence | Notes |
|---|---|---|---|
| Unified agent registration/heartbeat | **Operational** | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Enrollment + token flow implemented |
| Unified command and telemetry loop | **Operational** | `backend/routers/unified_agent.py` | Command queue/result/status APIs present |
| EDM governance and rollout APIs | **Operational** | `backend/routers/unified_agent.py` | Dataset versioning, publish, rollout, rollback, telemetry summary |
| Endpoint deployment | **Operational / Conditional** | `backend/services/agent_deployment.py` | Real SSH/WinRM paths + explicit simulation gate |
| CSPM API and scanning | **Operational / Conditional** | `backend/routers/cspm.py` | Durable scan/finding transitions; demo seed fallback if no providers |
| Email protection | **Operational** | `backend/email_protection.py`, router | Authentication checks + phishing/attachment/url/DLP analysis |
| Email gateway | **Operational** | `backend/email_gateway.py`, router | Process, quarantine, policies, lists; primarily in-memory state |
| Mobile security | **Operational** | `backend/mobile_security.py`, router | Device/threat/compliance/app-analysis paths active |
| MDM connectors | **Partially aligned with docs** | `backend/mdm_connectors.py`, router | Enum lists 4 platforms; manager instantiates Intune + JAMF only |

---

## 4) Security & Governance Posture

## Positive controls confirmed

- JWT secret enforcement in production/strict mode.
- CORS explicit-origin enforcement in production/strict mode.
- Remote admin restrictions via `REMOTE_ADMIN_ONLY`.
- Machine-token helpers for service-to-service and websocket contexts.
- CSPM scan endpoint uses authenticated dependency.

## Key consistency gaps

- Permission model mismatch risk (`check_permission("admin")` in places while permission table is capability-based).
- Mixed durability semantics (DB-backed transitions in some domains, in-memory state in others).
- Demo fallback paths in CSPM need strict production separation in reporting/evidence.

---

## 5) Reliability and Operability

## What is materially improved

- Deployment service supports real remote install methods with retries and state transitions.
- Startup orchestrates multiple background services with guarded error handling.
- Container stack and health checks are richer than minimal dev snapshots.

## What still limits enterprise confidence

- Several domain services depend on process-local state unless additional persistence is added.
- High integration breadth increases startup and dependency complexity.
- Contract assurance and schema-change discipline still require stronger CI enforcement.

---

## 6) Updated Risk Register

## High

1. Permission semantic drift (role vs permission checks).
2. State durability inconsistency across domain services.
3. Contract drift across large API/page surfaces.

## Medium

4. Demo-mode results blending with operational telemetry expectations.
5. Connector capability claims exceeding current concrete implementations (MDM breadth mismatch).
6. Legacy compatibility behaviors adding maintenance burden.

---

## 7) Recommended Priority Work

1. Normalize authorization model and route checks.
2. Persist currently in-memory service state where enterprise durability is required.
3. Add CI contract tests for high-change routers and frontend consumers.
4. Enforce explicit demo/simulated labels in API responses and dashboards.
5. Align documentation claims to instantiated, tested connector scope.

---

## 8) Final System-Wide Assessment

Seraph is a credible, high-scope security platform with real multi-domain behavior in core paths. The primary maturity challenge is now **platform consistency** (auth semantics, persistence uniformity, and contract governance), not raw feature count.
