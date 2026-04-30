# Seraph AI Defender - Technical Implementation Roadmap

**Updated:** 2026-04-30  
**Goal:** Convert broad implemented capability into reliable, contract-assured, governance-safe operations.

---

## 1) Program Charter

Deliver a governed adaptive defense platform with:

- deterministic API/client contracts,
- explicit runtime health for optional integrations,
- durable governance and command execution semantics,
- measurable detection and response quality,
- documentation that reflects current code paths.

## 2) Current Baseline

| Component | Current code reality |
|---|---|
| Backend | `backend/server.py` FastAPI v3 app, 65 router registrations, MongoDB-backed services, startup workers. |
| Frontend | React/Craco app with protected routes, consolidated workspaces, and external agent UI link to port 5000. |
| Agent | `unified_agent/core/agent.py` v2.0 with broad monitors and backend `/api/unified/...` integration. |
| Governance | Gated dispatch, pending decisions, approval/denial APIs, executor service, audit/world event hooks. |
| Cognition | CCE worker, AATL/AATR services, world model, and Triune orchestrator. |
| Testing | Backend contract/durability suites, unified-agent tests, static governance guardrail script, CI workflow. |

## 3) Workstreams

### WS-A: Contract Integrity

- Generate or audit route inventories from `backend/server.py` and `backend/routers/`.
- Validate frontend API calls in `frontend/src/` against active backend paths.
- Keep compatibility redirects intentional and documented.
- Add contract snapshots for high-risk request/response models.

### WS-B: Governance Assurance

- Keep all high-impact queue writes inside `GovernedDispatchService`.
- Add denial-path, replay-prevention, TTL, duplicate-execution, and restart/scale tests.
- Expand audit evidence around approval, denial, executor release, and domain operation outcomes.
- Ensure governance state transitions are queryable and monotonic.

### WS-C: Runtime Health and Degraded Modes

- Add a standard health schema: `connected`, `degraded`, `unavailable`, `not_configured`.
- Apply the schema to email gateway, MDM, CSPM, model services, scanners, VPN, SIEM, sandbox, and deployment adapters.
- Surface this state in frontend workspaces and API health endpoints.

### WS-D: Startup and Lifecycle Simplification

- Move large startup blocks from `backend/server.py` into registered lifecycle modules.
- Make optional service startup fail-closed or fail-degraded according to explicit policy.
- Add preflight checks for required production variables such as JWT secret, integration keys, CORS origins, and admin/setup controls.

### WS-E: Agent and Deployment Truth

- Require deployment completion to include target evidence such as install log, service status, or post-install heartbeat.
- Keep monitor taxonomy synchronized between `unified_agent/core/agent.py` and `backend/routers/unified_agent.py`.
- Expand unified-agent regression tests for new monitors and command delivery paths.

### WS-F: Documentation and Evidence

- Keep root README practical and code-accurate.
- Keep `memory/` review docs focused on current evidence instead of stale percentages.
- Note integration prerequisites wherever features depend on credentials, external services, or host privileges.

## 4) Candidate Epics

| Epic | Key deliverables |
|---|---|
| API contract registry | Route inventory, response schema snapshots, frontend call audit, compatibility map. |
| Governance durability | Restart/scale tests, replay-prevention, executor idempotency, audit export. |
| Integration health | Standard status model, backend health aggregation, UI degraded-state indicators. |
| Startup modularization | Service lifecycle registry, production preflight command, optional dependency policy. |
| Agent verification | Monitor parity tests, command queue delivery tests, deployment evidence model. |
| Documentation automation | Generated route summary, test evidence index, release documentation checklist. |

## 5) Gate Framework

| Gate | Required evidence |
|---|---|
| G0: Contract truth | No known frontend/script/API mismatches for critical workflows. |
| G1: Governance safety | High-impact commands are governed, denial-tested, and audit-visible. |
| G2: Runtime clarity | Optional integrations expose standard live/degraded/not-configured state. |
| G3: Deployment truth | Agent deployment success requires machine-verifiable evidence. |
| G4: Documentation accuracy | README and memory review docs match active code paths and tests. |

## 6) Immediate Engineering Focus

1. Normalize stale references to legacy backend names.
2. Extend governance guardrails to any newly high-risk router files.
3. Add runtime health models for integration-heavy domains.
4. Broaden contract tests for governance, unified-agent, deployment, and domain-operation flows.
5. Keep README and memory docs short enough to maintain, and update them as part of release hygiene.

## 7) Roadmap Bottom Line

The highest-leverage work is convergence: contract integrity, governance safety, runtime clarity, lifecycle simplification, and evidence-led documentation. The codebase already has substantial feature breadth; enterprise credibility now depends on making those paths deterministic, observable, and continuously validated.
