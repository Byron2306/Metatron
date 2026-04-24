# Feature Reality Report (Rebaselined)

Generated: 2026-04-24  
Scope: code-verified implementation narrative (backend, frontend, agent, compose runtime)

---

## Executive Reality Statement

The repository contains a large, operational security platform with broad API/domain coverage.  
Previous memory docs overstated certain areas (notably MDM connector breadth) and contained endpoint assumptions that are not currently true (email gateway allowlist delete).  
This report reflects the current live code.

---

## Verified System Footprint

- Backend router files: **62**
- FastAPI router definitions: **65**
- Endpoint decorators (`@router.get/post/put/delete/patch`): **694**
- Frontend pages in `frontend/src/pages`: **68**
- Docker services in root compose: **21**

---

## Feature Maturity Table (0-10)

| Domain | Score | Status | Reality Notes |
|---|---:|---|---|
| Core SOC operations | 9.0 | PASS | threats/alerts/hunting/response/timeline/quarantine/SOAR all wired |
| Unified agent control plane | 9.0 | PASS | registration, heartbeat, commanding, EDM governance routes |
| Endpoint monitor depth | 8.8 | PASS | 27 unique monitor assignments (+ conditional WebView2) |
| Security hardening baseline | 8.2 | PASS | strict JWT + strict-mode CORS + remote admin gating |
| Email protection | 8.8 | PASS | SPF/DKIM/DMARC, phishing, DLP, quarantine, protected-user surfaces |
| Email gateway | 8.0 | PASS/PARTIAL | inline scoring + quarantine; allowlist delete missing |
| Mobile security | 8.2 | PASS | device lifecycle, compliance, app/threat analysis |
| MDM connectors | 6.8 | PARTIAL | Intune + JAMF runtime; Workspace ONE/Google currently not provisioned |
| CSPM | 8.0 | PASS | auth-protected scan path, durable records, provider workflows |
| Advanced services (MCP/VNS/memory/quantum/AI) | 8.0 | PASS/PARTIAL | broad route surface, mixed optional-runtime dependencies |
| Governance/Triune dispatch | 7.8 | PASS | pending/approve/deny/executor workflows present |
| Browser isolation | 6.5 | PARTIAL | mature URL/session controls, not full remote-browser parity |

---

## Reality by Domain

### 1) Core SOC and Detection Flows

Real and implemented:
- Threat CRUD and enrichment paths
- Alert lifecycle and auditability
- Timeline and forensic-oriented views
- SOAR execution and response actioning

Evidence:
- `backend/routers/threats.py`
- `backend/routers/alerts.py`
- `backend/routers/timeline.py`
- `backend/routers/soar.py`
- `backend/routers/response.py`

### 2) Unified Agent and Endpoint Coverage

Real and implemented:
- Unified fleet registration and heartbeat
- Monitor telemetry summaries
- EDM dataset governance and rollout APIs
- Local monitor stack across endpoint behaviors

Evidence:
- `backend/routers/unified_agent.py`
- `unified_agent/core/agent.py`

### 3) Email Protection and Email Gateway

#### Email Protection (real)
- Authentication checks (SPF/DKIM/DMARC)
- URL and attachment heuristics
- impersonation and DLP analysis
- quarantine + protected-user operations

Evidence:
- `backend/email_protection.py`
- `backend/routers/email_protection.py`

#### Email Gateway (real, with limits)
- message parsing + policy scoring
- allow/block checks for sender/domain/IP
- quarantine release/delete, policy update, stats

Limit corrected:
- no allowlist delete endpoint in current router

Evidence:
- `backend/email_gateway.py`
- `backend/routers/email_gateway.py`

### 4) Mobile Security and MDM Connectors

#### Mobile Security (real)
- device registration/status update/compliance
- threat and app-analysis workflows

Evidence:
- `backend/mobile_security.py`
- `backend/routers/mobile_security.py`

#### MDM Connectors (partially real)
- `IntuneConnector` and `JAMFConnector` classes are implemented and used by manager
- Workspace ONE and Google Workspace appear in enums/platform metadata but are not wired in manager connector creation

Evidence:
- `backend/mdm_connectors.py`
- `backend/routers/mdm_connectors.py`

### 5) Hardening and Access Control

Real and implemented:
- production/strict mode JWT secret enforcement
- CORS wildcard rejection in strict/prod contexts
- remote-admin-only gate for non-local access
- machine-token helpers for service/agent channels
- CSPM scan auth requirement

Evidence:
- `backend/routers/dependencies.py`
- `backend/server.py`
- `backend/routers/cspm.py`

---

## Corrected Gap Matrix

| Prior Claim | Current Reality |
|---|---|
| 4 MDM platform connectors fully implemented | Runtime manager currently provisions 2 (Intune, JAMF) |
| Email gateway supports full allowlist CRUD | Allowlist create/list implemented; delete route absent |
| Legacy counts in docs reflect current system | Router/page/endpoint counts changed significantly and are now updated |

---

## Priority Actions

1. Align MDM docs/UI to 2-platform runtime reality or finish Workspace ONE + Google connector manager integration.
2. Add `DELETE /api/email-gateway/allowlist` (or document intentional omission).
3. Add CI contract checks for top-change routers to reduce drift.
4. Normalize version metadata and release labels across docs and API.

---

## Bottom Line

The platform is genuinely feature-rich and operational across core SOC, endpoint, email, mobile, and governance domains.  
The primary risk is no longer missing major surfaces; it is maintaining accurate contracts and capability parity as the codebase evolves quickly.
