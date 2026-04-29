# Metatron Feature Reality Matrix

Updated: 2026-04-29
Scope: quantitative implementation snapshot based on current code paths.

## Legend

- `PASS`: real code executes in a normal configured environment.
- `PARTIAL`: real code exists, but production behavior depends on credentials, external tools, durable state, or scale hardening.
- `LIMITED`: compatibility, demo, simulated, or reduced-depth behavior is present.

## Current matrix

| Domain | Status | Evidence | Practical interpretation |
|---|---|---|---|
| FastAPI backend composition | PASS | `backend/server.py` | Main app, Mongo/mongomock, CORS, service initialization, startup/shutdown workers, and router mesh are implemented. |
| Auth and protected frontend | PASS | `backend/routers/auth.py`, `frontend/src/context/AuthContext.jsx`, `frontend/src/App.js` | JWT login/me flow and protected React routes are implemented; strict production config still matters. |
| Unified agent register/heartbeat/control | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Agent lifecycle, telemetry, command, monitor summaries, installer/download endpoints, EDM, and deployment APIs exist. |
| Governed agent dispatch | PASS/PARTIAL | `backend/services/governed_dispatch.py`, `outbound_gate.py`, `governance_executor.py` | Command gating and approval/execution concepts are real; durability and multi-worker semantics need hardening. |
| World model and Triune orchestration | PASS | `backend/services/world_model.py`, `world_events.py`, `triune_orchestrator.py`, `backend/triune/*` | World events can trigger Metatron assessment, Michael planning, Loki challenge, and beacon cascade. |
| Metatron UI state APIs | PASS | `backend/routers/metatron.py`, `frontend/src/pages/WorldViewPage.jsx` | World/state endpoints are wired to the UI. |
| MITRE ATT&CK coverage | PASS | `backend/routers/mitre_attack.py` | `/api/mitre/coverage` aggregates live/static evidence across many detection sources and returns coverage metrics. |
| Detection engineering | PASS | `backend/routers/sigma.py`, `zeek.py`, `osquery.py`, `atomic_validation.py`, detection workspace UI | Sigma, Zeek, osquery, atomic validation, and MITRE views are present. Runtime depth depends on tool availability. |
| AATL/AATR and cognition | PASS/PARTIAL | `backend/services/aatl.py`, `aatr.py`, `cognition_engine.py`, `cce_worker.py`, `cognition_fabric.py` | Machine-paced CLI analysis and cognition fabric are implemented; model-backed depth depends on runtime models/data. |
| Email gateway/protection | PASS/PARTIAL | `backend/email_gateway.py`, `email_protection.py`, related routers, email workspace UI | Gateway/protection logic and APIs are implemented. Production relay and reputation depth require live SMTP/integration setup. |
| Mobile security and MDM | PASS/PARTIAL | `backend/mobile_security.py`, `mdm_connectors.py`, related routers, endpoint-mobility UI | Multi-platform framework exists. Live inventory/actions require Intune/JAMF/Workspace ONE/Google credentials and event plumbing. |
| CSPM | PASS/PARTIAL | `backend/cspm_engine.py`, `backend/routers/cspm.py`, CSPM UI | Multi-cloud posture plane exists and is authenticated; cloud credentials and scale testing determine depth. |
| Identity protection | PASS/PARTIAL | `backend/identity_protection.py`, `backend/routers/identity.py` | Identity incidents and APIs exist; enterprise AD/IdP response automation remains an expansion area. |
| Response/SOAR/quarantine | PASS/PARTIAL | `backend/soar_engine.py`, `quarantine.py`, `threat_response.py`, response workspace UI | Core workflows exist; high-risk action governance and audit evidence should remain enforced. |
| Network/VPN/browser isolation | PARTIAL | `backend/vpn_integration.py`, `browser_isolation.py`, network routes/UI | URL analysis and WireGuard paths exist; full remote browser isolation/pixel streaming remains limited. |
| Kernel/endpoint hardening | PASS/PARTIAL | `backend/enhanced_kernel_security.py`, `ebpf_kernel_sensors.py`, agent monitors | Strong framework; kernel-level results depend on OS support and privileges. |
| Integrations | PARTIAL | `backend/integrations_manager.py`, `backend/routers/integrations.py`, `unified_agent/integrations/*` | Managers, jobs, and parsers exist; production status varies by connector/tool credentials. |
| Frontend API wiring | PASS | `frontend/src/App.js`, workspace pages, latest wiring audits | Routes are consolidated and older paths redirect. Empty-state demo data remains in some pages. |
| Test/validation evidence | PASS/PARTIAL | `backend/tests/`, `unified_agent/tests/`, `backend/scripts/*`, `test_reports/*` | Broad tests and evidence scripts exist; current verification should be rerun per environment. |

## Maturity scores

| Area | Score (0-10) | Notes |
|---|---:|---|
| Backend and API composition | 8.5 | Powerful but central `server.py` coupling remains. |
| Unified agent/control plane | 8.5 | Broad real implementation; deployment truth and command durability still matter. |
| Triune/world governance | 8.0 | Strong current differentiator; needs persistence/scale assurance. |
| MITRE/detection engineering | 8.0 | Good aggregation model; runtime quality depends on enabled sensors. |
| Frontend workspaces | 8.0 | Consolidated and protected; demo fallback semantics should be explicit. |
| Email/mobile/MDM frameworks | 7.5 | Implemented framework; production depth depends on credentials and external services. |
| Deployment/reliability | 6.5 | Real paths exist but verification and degraded-mode contracts need tightening. |
| Security hardening assurance | 7.0 | Improved strict-mode/CORS/auth patterns; denial-path coverage should expand. |
| Overall platform maturity | 7.8 | Advanced feature breadth with active hardening priorities. |

## Gaps that matter most

1. Durable governance state for decisions, approvals, command delivery, and executor outcomes.
2. Contract tests for backend/frontend/agent payloads, especially unified-agent and governance routes.
3. Deployment completion semantics tied to install evidence and heartbeat, with simulation clearly labeled.
4. Explicit run-mode status in the UI for optional integrations and demo data.
5. Security regression suites for denial paths, token scopes, command gating, and machine-token ingestion.
