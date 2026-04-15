# Feature Reality Matrix (Code-Evidence Snapshot)

Generated: 2026-04-15  
Purpose: Quantitative-style status matrix aligned to live code paths

## Status Legend

- PASS: Implemented and wired into normal runtime paths.
- PARTIAL: Implemented but materially dependent on external runtime conditions, data quality, or non-default setup.
- LIMITED: Present as a compatibility layer, fallback, or shallow implementation.

---

## Platform Core Matrix

| Domain | Status | Primary Evidence | Notes |
|---|---|---|---|
| API control plane | PASS | `backend/server.py` | Main FastAPI app mounts large router surface and startup workers. |
| Authentication + RBAC | PASS | `backend/routers/dependencies.py`, `backend/routers/auth.py` | JWT, role checks, strict secret handling in production/strict mode. |
| Websocket ingestion/control | PASS | `backend/server.py` (`/ws/threats`, `/ws/agent/{agent_id}`) | Agent websocket validates machine token. |
| Threat/alert lifecycle | PASS | `backend/routers/threats.py`, `backend/routers/alerts.py` | CRUD and dashboard-connected workflows are active. |
| World model persistence | PASS | `backend/services/world_model.py` | Entities, edges, campaigns, risk calculation paths. |
| World events + trigger routing | PASS | `backend/services/world_events.py` | Event classification and optional Triune trigger are active. |
| Triune orchestration (Metatron/Michael/Loki) | PASS | `backend/services/triune_orchestrator.py`, `backend/triune/*.py` | End-to-end strategic pipeline is implemented. |
| Cognition fabric fusion | PASS | `backend/services/cognition_fabric.py` | AATL/AATR/CCE/ML/AI signals merged into snapshot output. |
| Governance decision + queue execution | PASS/PARTIAL | `backend/services/outbound_gate.py`, `governance_authority.py`, `governance_executor.py` | Functional flow exists; some policy/rate semantics remain process-local. |
| Unified agent control plane | PASS | `backend/routers/unified_agent.py` | Register/heartbeat/commands/EDM/rollout/install endpoints. |
| Unified agent runtime | PASS | `unified_agent/core/agent.py` | Monitor scans, command polling, telemetry, remediation pathing. |
| Local agent dashboard (canonical) | PASS | `unified_agent/ui/web/app.py`, `unified_agent/run_local_dashboard.sh` | Flask dashboard on port 5000 is the intended primary local UI. |
| Secondary agent server API | LIMITED | `unified_agent/server_api.py` | Separate FastAPI with in-memory/JSON state and legacy wording; not canonical control plane. |
| Frontend route shell | PASS | `frontend/src/App.js`, `frontend/src/components/Layout.jsx` | Workspace-based route consolidation with protected shell. |
| Frontend auth wiring | PASS | `frontend/src/context/AuthContext.jsx` | Uses `/api/auth/*` with bearer token handling. |

---

## Security Domain Matrix

| Capability | Status | Evidence | Operational Caveat |
|---|---|---|---|
| EDM + DLP dataset governance | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Mature API + agent ingest path; assurance still depends on rollout discipline. |
| Identity protection APIs | PASS | `backend/routers/identity.py`, `backend/services/identity.py` | Present and integrated with world/governance events. |
| CSPM API plane | PASS/PARTIAL | `backend/routers/cspm.py`, `backend/cspm_engine.py` | Implemented; cloud credential quality determines depth. |
| Email protection | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | Functional analysis paths; production efficacy depends on upstream feed/ops tuning. |
| Email gateway | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Gateway logic exists; production relay posture depends on real SMTP integration. |
| Mobile security | PASS | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device and threat workflows are implemented. |
| MDM connectors | PASS/PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Connector framework exists; provider credentials are external prerequisites. |
| Deception engine | PASS | `backend/deception_engine.py`, `backend/routers/deception.py` | Router mounted on both `/api` and `/api/v1` for compatibility. |
| Kernel sensors and secure boot surfaces | PASS/PARTIAL | `backend/routers/kernel_sensors.py`, `backend/routers/secure_boot.py` | Feature depth depends on host kernel/capability setup. |
| Browser isolation | PARTIAL | `backend/browser_isolation.py`, frontend page wiring | URL/risk controls exist; full remote browser isolation remains limited. |
| AI-assisted reasoning | PARTIAL | `backend/services/ai_reasoning.py`, `backend/routers/advanced.py` | Rule-based core exists; model quality depends on configured LLM backends. |

---

## Frontend Integration Reality

| Area | Status | Evidence | Notes |
|---|---|---|---|
| Workspace navigation model | PASS | `frontend/src/App.js` | Legacy routes mostly redirect to workspace tabs. |
| Sidebar route ownership | PASS | `frontend/src/components/Layout.jsx` | 7 sections, 38 nav items, including external agent UI link to `:5000`. |
| API base handling | PASS/PARTIAL | `frontend/src/context/AuthContext.jsx`, page-level API builders | Works, but mixed API-builder patterns remain a maintenance risk. |
| Unified agent UI convergence | PASS | `/agents`, `/swarm`, `/agent-commands` routes redirect to `/unified-agent` | Legacy imports still exist in `App.js` but are not route-mounted. |

---

## Verification Evidence (Current Repo)

- Backend tests: `backend/tests/test_triune_orchestrator.py`, `test_triune_routes.py`, `test_governance_token_enforcement.py`, `test_unified_agent_*.py`.
- Unified agent tests: `unified_agent/tests/test_monitor_scan_regression.py`, `test_endpoint_fortress.py`, `test_cli_identity_signals.py`, `test_canonical_ui_contract.py`.
- Root/system scripts: `e2e_system_test.py`, `full_feature_test.py`, `test_unified_agent.py` (environment dependent).

---

## Bottom Line

The matrix confirms a code-real platform with broad PASS coverage.  
The largest remaining gap is not module absence; it is enterprise assurance quality under variable runtime conditions (credentials, integrations, restart/scale durability, and schema discipline).
