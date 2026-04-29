# Seraph AI Defender - Technical Implementation Roadmap

Updated: 2026-04-29
Goal: harden the implemented governed adaptive defense fabric.

## North-star outcome

Deliver a platform where endpoint and integration telemetry feed a durable world model, Triune cognition proposes and challenges actions, and every high-impact outbound action is policy-governed, auditable, reversible where possible, and backed by evidence.

## Current baseline

Implemented foundations:

- FastAPI control plane in `backend/server.py`.
- Unified agent runtime in `unified_agent/core/agent.py` and `/api/unified/*` control plane.
- World model and Triune orchestration in `backend/services/world_model.py`, `world_events.py`, `triune_orchestrator.py`, and `backend/triune/*`.
- Governed dispatch and action execution in `outbound_gate.py`, `governed_dispatch.py`, `governance_executor.py`, `policy_engine.py`, and `telemetry_chain.py`.
- MITRE coverage aggregation in `backend/routers/mitre_attack.py`.
- Consolidated React workspaces in `frontend/src/App.js`.

## Workstreams

### WS-A: Contract integrity

Owns API/client/agent schema correctness.

Deliverables:
- Route inventory generated from FastAPI routers.
- Request/response schema snapshots for critical routes.
- CI checks for unified-agent, governance, auth, world ingest, and MITRE coverage contracts.
- Frontend API linting for workspace pages.

### WS-B: Governance durability

Owns enterprise-safe autonomous action state.

Deliverables:
- Durable policy decision store.
- Durable pending-action and dispatch queue state.
- Executor outcome records with trace IDs.
- Replay prevention for tokens and approvals.
- Restart/scale regression tests.

### WS-C: Deployment truth and run modes

Owns production-vs-demo clarity.

Deliverables:
- Deployment state machine: queued -> executing -> installed -> heartbeat_verified -> completed/failed.
- Response metadata that distinguishes live, degraded, demo, simulated, and unavailable modes.
- UI run-mode/dependency panels.
- Preflight command for required and optional services.

### WS-D: Detection quality engineering

Owns measurable detection performance.

Deliverables:
- Scenario replay harness for endpoint, world, and MITRE coverage paths.
- Precision/recall and false-positive metrics for selected threat classes.
- Suppression object model with owner, expiry, reason, and governance.
- ATT&CK evidence reporting tied to `/api/mitre/coverage`.

### WS-E: Integration certification

Owns connector quality and support tiers.

Deliverables:
- Connector health contract for email, MDM, SIEM, sandbox, VPN, and external tools.
- Tier labels: supported, best-effort, experimental, demo-only.
- Integration smoke tests and documentation per connector.

### WS-F: Operator experience

Owns clarity and safe workflows.

Deliverables:
- Workspace status banners for empty/demo/simulated data.
- Governance queue UI with reason, evidence, approver, TTL, and execution outcome.
- World/Triune explainability panels for assessment, plan, challenge, and final action.

## Priority sequence

1. Stabilize contracts and docs.
2. Make governance durable.
3. Clarify run modes.
4. Verify deployment truth.
5. Measure detection quality.

## Gate framework

| Gate | Required evidence |
|---|---|
| G0 contract truth | Route inventory and schema snapshots pass in CI. |
| G1 governance durability | Pending/approved/executed actions survive restart and are traceable. |
| G2 run-mode clarity | UI/API distinguish live, degraded, demo, simulated, and unavailable. |
| G3 deployment truth | Completed deployments include install evidence and heartbeat verification. |
| G4 detection quality | Replay harness publishes trend metrics for priority threat classes. |

## Expected outcome

Seraph should be able to credibly claim governed adaptive defense when its strongest architecture - world model, Triune cognition, and governed dispatch - is backed by durable state, contract assurance, explicit run modes, and measured detection quality.
