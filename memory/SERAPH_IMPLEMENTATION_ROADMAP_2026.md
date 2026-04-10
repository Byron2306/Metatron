# Seraph Implementation Roadmap 2026 (Rebased)

**Date:** 2026-04-10  
**Purpose:** Implementation roadmap aligned to current code reality and critical parity gaps.

---

## 1) Current-State Baseline

### High-confidence implemented foundations
- Unified-agent control plane (register, heartbeat, command polling, monitor payloads).
- EDM governance and rollout mechanisms in backend unified-agent router.
- Broad backend API composition and workspace-driven frontend operations model.
- Identity/CSPM/email/mobile/router-level domain coverage.

### Domains requiring explicit completion work
- Email gateway runtime completeness (SMTP listener/relay operation path).
- MDM platform parity (Workspace ONE / Google support beyond enum-level definitions).
- Browser isolation service/router proxy endpoint alignment.
- Telemetry contract consistency and denial-path assurance depth.

---

## 2) Implementation Streams

### Stream A: Runtime Parity

#### A1. Email Gateway Runtime Completion
- **Current reality:** `backend/email_gateway.py` provides processing and policy logic; runtime SMTP server start/listen behavior is not clearly implemented in repo runtime wiring.
- **Target outcome:** production-capable SMTP runtime mode with explicit startup path and deployment instructions.
- **Deliverables:**
  - Runtime bootstrap module and configuration schema.
  - End-to-end tests for accept/reject/quarantine flow with realistic SMTP interactions.
  - Operations guide for certs, upstream routing, and fail-safe behavior.

#### A2. MDM Connector Parity
- **Current reality:** `MDMConnectorManager.add_connector(...)` instantiates Intune/JAMF only.
- **Target outcome:** implement Workspace ONE and Google Workspace connector classes, plus manager integration and tests.
- **Deliverables:**
  - Connector classes with auth/session/sync support.
  - Manager wiring parity for all platform enum values.
  - UI/API behavior aligned for unsupported vs supported states.

### Stream B: Contract and Assurance Hardening

#### B1. Agent/Backend Telemetry Contract Normalization
- Align monitor payload schema between `unified_agent/core/agent.py` and `backend/routers/unified_agent.py`.
- Add strict validation paths (or explicit pass-through schemas) with CI checks.
- Ensure EDM hit telemetry captures expected volume without tail-window blind spots.

#### B2. Denial-Path and Invariant Testing
- Expand tests for:
  - permission failures,
  - invalid transitions,
  - degraded integration behavior,
  - rollback triggers and guarded operations.
- Build contract tests for high-traffic routes used by workspaces.

### Stream C: Interface Integrity and UX Truthfulness

#### C1. Browser Isolation Parity
- Resolve mismatch between generated proxy URL paths in service and actual router routes.
- Either implement missing proxy routes or adjust service output to existing endpoints.

#### C2. Documentation Governance
- Replace static maturity overclaims with evidence-tagged status language.
- Add per-domain readiness caveats in docs.
- Adopt "source of truth" references for route and capability verification.

---

## 3) Prioritized Backlog (Technical)

| Priority | Item | Why It Matters |
|---|---|---|
| P0 | Email gateway runtime completion | Critical for honest "gateway mode" production claim |
| P0 | MDM parity for remaining platforms | Eliminates major claim/reality gap |
| P0 | Browser isolation proxy route parity | Prevents broken path expectations |
| P1 | Telemetry schema contract CI | Reduces silent breakage across agent/backend/frontend |
| P1 | EDM hit completeness improvements | Improves governance signal quality |
| P1 | High-risk denial-path tests | Improves security assurance confidence |
| P2 | Legacy compatibility consolidation | Reduces maintenance drift and technical debt |
| P2 | Domain readiness checklists | Improves deployment predictability |

---

## 4) Definition of Done (Per Domain)

Any domain should only be marked "fully mature" when all are true:
1. Runtime path exists and is deployable.
2. API contracts are validated in CI.
3. Failure/denial paths are tested.
4. External dependency prerequisites are documented.
5. Frontend behavior reflects backend support state.
6. Documentation claims map directly to evidence.

---

## 5) Outcome Target

Shift from "breadth-first" to "parity-and-assurance-first":
- Preserve innovation velocity where strategic,
- while completing runtime parity and contract integrity in high-visibility domains.

This roadmap supersedes prior 2026 roadmap statements where they conflict with current implementation evidence.
