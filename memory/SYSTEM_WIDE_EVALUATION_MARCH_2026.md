# Metatron / Seraph System-Wide Evaluation

Updated: 2026-04-29
Classification: code-evidence system assessment.

## Executive summary

The March 2026 documents emphasized feature expansion such as Email Gateway and MDM Connectors. The current repository still contains those implementations, but the broader system has evolved into a governed security fabric with five central runtime axes:

1. FastAPI control plane in `backend/server.py`.
2. Unified endpoint agent in `unified_agent/core/agent.py` with `/api/unified/*` lifecycle and command APIs.
3. World model and Triune cognition through `WorldModelService`, `emit_world_event`, `TriuneOrchestrator`, Metatron, Michael, and Loki.
4. Governance and dispatch through outbound gate, governed dispatch, policy engine, telemetry chain, and governance executor.
5. React workspace UI in `frontend/src/App.js` with protected routes and consolidated workspaces.

The platform should be positioned as an advanced adaptive defense system in hardening phase, not as a finished turnkey incumbent replacement.

## Implemented system areas

| Area | Implemented code | Current assessment |
|---|---|---|
| Core API | `backend/server.py` | Real app composition, DB setup, CORS, workers, routers, WebSockets. |
| Unified agent | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Strong fleet and telemetry implementation with broad monitor set. |
| World/Triune | `backend/services/world_model.py`, `world_events.py`, `triune_orchestrator.py`, `backend/triune/*` | Current strategic center of the platform. |
| Governance | `backend/services/outbound_gate.py`, `governed_dispatch.py`, `governance_executor.py`, `policy_engine.py` | Real safety layer for outbound actions; durability is the key gap. |
| Detection engineering | Sigma, Zeek, osquery, atomic validation, MITRE router | Strong breadth; runtime depends on enabled integrations/sensors. |
| Email/mobile | `email_gateway.py`, `email_protection.py`, `mobile_security.py`, `mdm_connectors.py` | Implemented frameworks; production value requires credentials and live integrations. |
| Integrations | `integrations_manager.py`, integration routers and agent scripts | Functional orchestration and parsing, connector quality varies. |
| Frontend | `frontend/src/App.js`, workspace pages | Protected, consolidated, API-backed UI with legacy redirects. |
| Testing/evidence | `backend/tests/`, `unified_agent/tests/`, `backend/scripts/*`, `test_reports/*` | Broad evidence exists; should be rerun for the target environment. |

## Current capability narrative

### Endpoint and fleet operations

Unified agents can register, heartbeat, send telemetry, receive commands, and participate in EDM workflows. Monitor summaries are normalized in the backend and can be projected into the world model. Agent-side code includes endpoint, network, identity, DLP, email, mobile, YARA, ransomware, kernel, and self-protection monitor families.

### World-state reasoning

Security events can be converted into graph/world state. The orchestrator builds snapshots containing entities, edges, hotspots, campaigns, trust state, active responses, sector risk, and attack-path summaries. Metatron assesses, Michael plans, and Loki challenges proposed action paths.

### Governance and action control

The governance stack is built to prevent unmediated high-risk automation. Governed dispatch and outbound gate queue or gate commands; policy engine models approval classes; telemetry chain records auditable actions; governance executor dispatches approved decisions.

### MITRE coverage

`GET /api/mitre/coverage` computes coverage from multiple evidence families. It should be used as the source of truth for current ATT&CK coverage reporting rather than static documentation tables.

### UI and operator workflows

The UI now defaults `/` to `/command`. Older routes such as `/alerts`, `/threats`, `/agents`, `/soar`, `/edr`, `/email-gateway`, and `/mdm` redirect into current workspaces. API base resolution uses configured backend URL when safe and otherwise same-origin `/api`.

## Updated maturity scorecard

| Domain | Score (0-5) | Rationale |
|---|---:|---|
| Product capability breadth | 4.6 | Very broad implemented surface. |
| Architecture depth | 4.1 | World/Triune/governance model is strong; startup coupling remains. |
| Operational reliability | 3.5 | Core run mode is clear; optional dependency behavior must be more explicit. |
| Security hardening | 3.6 | Good strict-mode patterns; denial-path coverage should expand. |
| Governance maturity | 3.7 | Real mechanisms; durability and scale assurance are pending. |
| Detection quality engineering | 3.4 | Good coverage aggregation; empirical evaluation loop needs more depth. |
| Enterprise readiness | 3.7 | Strong for controlled environments; not yet turnkey at incumbent scale. |

Composite: **3.8 / 5**.

## Priority recommendations

1. Persist governance decisions, command dispatch state, executor outcomes, and token/audit usage.
2. Add route/schema snapshot generation and CI contract checks for backend/frontend/agent payloads.
3. Make run mode visible in API responses and UI: live, degraded, demo, simulated, or unavailable.
4. Tie deployment success to verified install evidence plus subsequent agent heartbeat.
5. Use `/api/mitre/coverage` and evidence scripts for all ATT&CK claims.
6. Expand denial-path tests for auth, machine tokens, governance, and admin actions.

## Conclusion

Metatron / Seraph has substantial implemented code and meaningful differentiation. The current strategic story is governed adaptive defense: endpoint and integration signals feed a world model, Triune cognition reasons over changes, and policy-governed dispatch controls response. The highest-value work is hardening and evidence discipline.
