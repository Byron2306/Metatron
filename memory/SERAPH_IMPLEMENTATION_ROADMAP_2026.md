# Seraph AI Defender - Implementation Roadmap (Code-Aligned Refresh, April 2026)

## Purpose

This roadmap replaces timeline-heavy planning language with code-aligned implementation tracks based on the current repository state.

## Current baseline

- Backend app: `backend/server.py` (FastAPI)
- Backend routers: `backend/routers/*.py` (62 modules)
- Backend services: `backend/services/*.py` (33 modules)
- Frontend shell/routes: `frontend/src/App.js` + `frontend/src/pages/*`
- Unified agent runtime: `unified_agent/core/agent.py`
- Optional local agent API/UI: `unified_agent/server_api.py`, `unified_agent/ui/web/app.py`
- Governance execution chain:
  - `backend/services/outbound_gate.py`
  - `backend/services/governed_dispatch.py`
  - `backend/services/governance_authority.py`
  - `backend/services/governance_executor.py`

## Workstream A - Contract integrity

### A1. Frontend-to-backend route contract

Implement and enforce:

1. Static extraction of frontend `/api/...` call-sites.
2. Static extraction of mounted backend routes.
3. Contract fail in CI on new unresolved call-sites.

Targets:

- `frontend/src/pages/*`
- `backend/server.py`
- `backend/routers/*`

### A2. Namespace normalization

Converge legacy call patterns on canonical APIs:

- `/api/data` -> explicit domain routes
- `/api/login` -> `/api/auth/login`
- `/api/admin/users` -> `/api/users`

## Workstream B - Runtime reliability

### B1. Startup dependency behavior

Harden startup behavior in `backend/server.py` for services initialized in `startup()`:

- CCE worker
- network discovery
- deployment service
- AATL/AATR
- integrations scheduler
- governance executor

Focus:

- deterministic startup state records
- explicit degraded-mode signaling
- reduced hidden partial failures

### B2. Storage path consistency

Standardize all file-backed runtime artifacts to use `backend/runtime_paths.py` (`ensure_data_dir`) rather than scattered path assumptions.

## Workstream C - Governance hardening

### C1. Full action coverage through outbound gating

Ensure high-impact operational actions across routers route through governed dispatch:

- agent commands
- swarm operations
- integration runtime actions
- cross-domain response actions

### C2. Decision/audit cohesion

Strengthen ties between:

- triune decisions
- outbound queue entries
- command delivery queue
- tamper-evident audit records
- world events

## Workstream D - Detection quality engineering

### D1. Evaluatable detection surfaces

Build repeatable evaluation harnesses for:

- email protection/gateway pipelines
- MDM device action outcomes
- correlation + threat intel ingestion quality
- unified agent telemetry projection to world model

### D2. False-positive governance

Add structured suppress/allow workflows with measurable side effects, not just ad-hoc threshold tuning.

## Workstream E - Integration rationalization

### E1. Tool adapter contract

For each tool in `SUPPORTED_RUNTIME_TOOLS` (`backend/integrations_manager.py`), require:

- input schema contract
- output/result schema contract
- error code normalization
- ingestion guarantees

### E2. Runtime-target parity

Keep parity between:

- server runtime (`runtime_target=server`)
- unified agent runtime (`runtime_target=agent`)

for job state, command IDs, queue IDs, and decision IDs.

## Workstream F - Platform experience

### F1. Workspace consistency

Continue consolidating page-level legacy routes into workspace tabs while preserving compatibility redirects.

### F2. Operator clarity

Expose run mode, degraded dependencies, and governance queue state directly in UI workflows.

## Acceptance gates (technical, not calendar)

### Gate G1 - Contract integrity

- No unresolved frontend `/api/...` call-sites in CI.
- Route aliases documented and intentional.

### Gate G2 - Runtime determinism

- Startup components report explicit healthy/degraded state.
- Background initialization failures are actionable.

### Gate G3 - Governance chain integrity

- High-impact actions create decision + queue + execution traces.
- Denied actions do not leak into execution queues.

### Gate G4 - Detection evidence quality

- Reproducible tests for core detection pipelines with stored evidence artifacts.

### Gate G5 - Operator UX coherence

- Workspace navigation reflects current route contract.
- Run-mode and governance-state visibility are first-class.

## Implementation notes for maintainers

1. Treat this roadmap as code-first: update references whenever key modules move.
2. Do not reintroduce aspirational version labels without code evidence.
3. Keep all roadmap tasks tied to explicit repository paths and enforceable checks.
