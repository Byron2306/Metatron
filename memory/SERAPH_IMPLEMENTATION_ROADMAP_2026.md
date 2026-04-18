# Seraph AI Defender - Implementation Roadmap (Rebaselined)

Date: 2026-04-18  
Scope: Technical convergence roadmap grounded in current repository reality

---

## 1) Program Objective

Drive the platform from "broad and working" to "broad, deterministic, and enterprise-assurable" without sacrificing composability and adaptive defense speed.

---

## 2) Starting Point (Current Reality)

- API surface is extensive (`backend/server.py` includes 65 router registrations).
- Router module count is high (62 files under `backend/routers/`).
- Route coverage is broad (~694 route decorators across routers).
- Unified endpoint agent is feature-rich (27 instantiated monitors in `unified_agent/core/agent.py`).
- Governance and triune gating are operational in enterprise/cspm/token/tool paths.
- Remaining depth gaps are mostly **consistency and integration parity**, not missing foundational architecture.

---

## 3) Priority Workstreams

### WS-A: Documentation/Contract Accuracy
- Keep `/memory`, root `README.md`, and deployment docs synchronized with actual behavior.
- Add explicit distinction between:
  - API/platform metadata support
  - fully implemented provider connector logic

### WS-B: MDM Connector Parity
- Current concrete connectors: Intune + JAMF.
- Next target: implement Workspace ONE and Google Workspace connector classes in `backend/mdm_connectors.py` to match platform metadata and router expectations.

### WS-C: Deployment Determinism
- Preserve real SSH/WinRM execution as primary path.
- Keep simulation explicitly opt-in (`ALLOW_SIMULATED_DEPLOYMENTS=true`), with unmistakable flags in status views and responses.
- Tighten post-deploy verification evidence semantics.

### WS-D: Browser Isolation Depth
- Existing session/analyze/sanitize/blocklist capability is useful but partial.
- Prioritize hardened remote rendering and stronger policy controls to close "partial" maturity classification.

### WS-E: Governance/Test Assurance
- Expand negative-path and denial-path tests for gated operations (policy, token, tool, cspm provider mutations).
- Ensure state-transition durability behavior remains resilient under concurrent updates.

---

## 4) Implementation Phases

### Phase 1 - Truth Alignment (Immediate)
1. Complete memory/docs rebaseline (this update).
2. Align root-level README to current code and runtime contracts.
3. Introduce a recurring docs validation checklist tied to:
   - router inventory
   - provider implementation parity
   - deployment mode semantics

### Phase 2 - Integration Parity (Near-term)
1. Add Workspace ONE connector implementation.
2. Add Google Workspace connector implementation.
3. Add tests proving end-to-end connector behavior, not only endpoint schema visibility.

### Phase 3 - Assurance Expansion
1. Extend targeted regression for governance-heavy flows.
2. Strengthen deployment verification and failure-mode observability.
3. Add clearer maturity markers in docs and runtime status surfaces.

---

## 5) Acceptance Signals

- MDM platform claims in docs exactly match implemented connector classes.
- Deployment status semantics clearly differentiate real execution vs explicit simulation mode.
- No critical documentation drift between memory reports and route/service behavior.
- Governance-critical paths maintain deterministic transition logs and conflict handling under concurrent updates.

---

## 6) Immediate Next Actions

1. Finalize remaining major memory document rewrites.
2. Replace root `README.md` with code-accurate architecture/runtime guidance.
3. Commit and push this documentation rebaseline as a dedicated update.

