# Metatron Feature Reality Matrix

**Updated:** 2026-04-30  
**Scope:** Current implementation reality without stale maturity percentages.

---

## Legend

- `REAL`: active code path exists and is wired into normal runtime.
- `FRAMEWORK`: substantial implementation exists, but production value depends on external services, credentials, privileges, or environment.
- `PARTIAL`: narrower implementation than the product label may imply.
- `ASSURANCE-FOCUS`: present, but high blast radius means more validation remains important.

## Current Reality Matrix

| Area | Status | Evidence | Practical interpretation |
|---|---|---|---|
| FastAPI backend | REAL | `backend/server.py` | Version 3.0 app on port 8001; MongoDB via Motor/mock mode; `/api/` and `/api/health`. |
| Router surface | REAL | `backend/routers/` | 62 router files on disk; 65 `include_router` registrations in `server.py`; app WebSockets for threats and agents. |
| React frontend | REAL | `frontend/src/App.js`, `Layout.jsx` | 69 page components on disk; 66 route declarations; protected routes and consolidated workspaces. |
| Unified endpoint agent | REAL | `unified_agent/core/agent.py` | v2.0 cross-platform agent with broad monitor and response modules. |
| Agent backend integration | REAL | `backend/routers/unified_agent.py` | Registration, heartbeat, telemetry, monitor summary, EDM/DLP, commands, deployment/control surfaces. |
| Agent portal | REAL | `unified_agent/server_api.py` | Separate FastAPI v2.0 portal/proxy with WebSockets and JSON persistence; comments still reference old backend naming. |
| Governed dispatch | REAL / ASSURANCE-FOCUS | `services/governed_dispatch.py`, `services/outbound_gate.py` | Impactful commands are queued as `gated_pending_approval` with decision metadata. |
| Governance approvals | REAL / ASSURANCE-FOCUS | `routers/governance.py`, `services/governance_executor.py` | Pending decisions can be approved/denied; executor releases approved actions and records audit/world events. |
| Static governance guardrails | REAL | `backend/scripts/governance_guardrails.py` | Checks scoped mutating endpoints, shell usage, and direct queue writes. |
| Triune orchestration | REAL / FRAMEWORK | `services/triune_orchestrator.py`, `backend/triune/` | World snapshot + cognition -> Metatron -> Michael -> Loki. Persona service depth varies by implementation. |
| World model/events | REAL | `services/world_model.py`, `services/world_events.py`, `routers/world_ingest.py` | Agent state and domain events can update world entities and trigger Triune reasoning. |
| CCE worker | REAL | `services/cce_worker.py`, `services/cognition_engine.py` | Polls CLI commands, groups sessions, analyzes machine-like behavior, stores summaries. |
| AATL/AATR | REAL / FRAMEWORK | `services/aatl.py`, `services/aatr.py`, `routers/ai_threats.py` | AI-agent threat layer and registry are initialized and routable. |
| Email protection | FRAMEWORK | `backend/email_protection.py`, `routers/email_protection.py` | SPF/DKIM/DMARC/phishing/DLP logic exists; live value depends on DNS/feed/config paths. |
| Email gateway | FRAMEWORK | `backend/email_gateway.py`, `routers/email_gateway.py` | Relay/quarantine/policy surfaces exist; production SMTP deployment must be configured. |
| Mobile security | FRAMEWORK | `backend/mobile_security.py`, `routers/mobile_security.py` | Device risk/compliance APIs exist; device truth depends on live enrollment/input. |
| MDM connectors | FRAMEWORK | `backend/mdm_connectors.py`, `routers/mdm_connectors.py` | Intune/JAMF/Workspace ONE/Google connector logic exists; live sync requires credentials. |
| CSPM | FRAMEWORK | `backend/cspm_engine.py`, `routers/cspm.py` | Multi-cloud posture surfaces exist; cloud credentials determine production depth. |
| Identity | REAL / FRAMEWORK | `backend/identity_protection.py`, `routers/identity.py`, `services/identity.py` | Identity routes and service controls exist; enterprise response depth depends on integration. |
| Deception | REAL | `backend/deception_engine.py`, `routers/deception.py` | Mounted under `/api` and `/api/v1`; integrates with honey tokens/ransomware managers. |
| Browser isolation | PARTIAL | `backend/browser_isolation.py` | URL analysis/filtering/sanitization exists; full remote browser isolation should not be claimed. |
| Kernel / secure boot | FRAMEWORK | `secure_boot_verification.py`, kernel sensor routers/services | Requires OS support, privileges, and runtime device/log access. |
| Deployment service | FRAMEWORK / ASSURANCE-FOCUS | `services/agent_deployment.py` | Real SSH/WinRM-oriented paths exist; verified install evidence should remain a quality gate. |
| Docker stack | REAL | `docker-compose.yml` | MongoDB, Redis, backend, Celery, frontend, and integration/security services are composed. |
| Contract tests | REAL / GROWING | `.github/workflows/contract-assurance.yml`, `backend/tests/` | 63 backend test files; CI focuses on control-plane/durability subset. |
| Unified-agent tests | REAL | `unified_agent/tests/` | 4 test files cover monitor regression, canonical UI contract, endpoint fortress, and CLI identity signals. |

## Updated Acceptance Snapshot

- Backend API composition: code evidence confirms active modular composition through `backend/server.py`.
- Frontend route consolidation: code evidence confirms current route declarations and redirects in `frontend/src/App.js`.
- Governance path: code evidence confirms gated command persistence, pending decision APIs, approval/denial handling, and executor processing.
- Agent telemetry path: code evidence confirms monitor taxonomy, world-state projection, and audit hooks in `backend/routers/unified_agent.py`.
- Test posture: code evidence confirms backend and unified-agent test suites plus CI workflows, but coverage is not uniform across all advertised feature domains.

## Bottom Line

The repository has high feature breadth and several strong real control paths. The most accurate matrix language is `REAL` for active backend/frontend/agent/governance logic, `FRAMEWORK` for integrations that need live credentials or services, and `PARTIAL` for areas such as full remote browser isolation where code exists but the product label can overstate current runtime depth.
