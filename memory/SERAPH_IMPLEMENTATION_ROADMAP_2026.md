# Seraph Technical Roadmap (Rebased to Current Code)

**Last revalidated:** 2026-04-21  
**Purpose:** Align roadmap priorities to what is already implemented versus what still needs engineering hardening.

---

## 1) Program Objective

Evolve the platform from broad feature capability into **consistent enterprise-grade operation** through:

1. Contract integrity
2. Durable state and reliable execution semantics
3. Unified authorization model
4. Verifiable governance and assurance workflows

---

## 2) Current Baseline (Code-Verified)

### Already implemented

- Modular FastAPI router composition (`backend/server.py`, `backend/routers/*`)
- Unified agent register/heartbeat/command loops
- EDM dataset lifecycle APIs (versioning/publish/rollout/rollback)
- Deployment service with SSH/WinRM execution and retry/state transition logs
- CSPM scan/finding durability and transition logs
- Email/mobile/gateway/MDM API surfaces

### Still inconsistent / partial

- Permission check model consistency (`check_permission("admin")` usage vs permission map)
- Service-level durability in email/mobile/gateway modules (in-memory state)
- CSPM demo-seed fallback versus production evidence semantics
- MDM connector scope mismatch (enum advertises four platforms; manager currently instantiates Intune and JAMF)

---

## 3) Workstreams

## WS-A: Contract and Interface Integrity

- Build route/payload contract tests for high-change surfaces:
  - `/api/unified/*`
  - `/api/v1/cspm/*`
  - email/mobile/mdm domains
- Add drift gates between frontend expectations and backend response shapes.

## WS-B: Authorization and Access Model Normalization

- Replace ambiguous permission checks with explicit role or permission checks consistently.
- Document and test remote-admin-only behavior and machine-token paths.

## WS-C: Durability and Runtime Reliability

- Persist currently in-memory operational state where required (gateway queues, mobile threat/device state, selected email security state).
- Standardize state transition logs for all critical workflow objects.

## WS-D: Governance and Assurance

- Extend policy/decision evidence checks for high-risk operations.
- Enforce explicit labeling and controls for demo/simulated workflows.

## WS-E: Integration Reality Alignment

- Align MDM docs and runtime support with actual connectors implemented.
- Add explicit support tier labels for integrations (production-ready vs conditional vs demo).

---

## 4) Delivery Phases (Technical)

## Phase 0: Correctness and Transparency

- Fix permission semantic inconsistencies.
- Mark and segment demo-mode responses/events.
- Publish compatibility contracts for top API paths.

## Phase 1: Persistence and Determinism

- Introduce persistence for in-memory security modules where required by operations.
- Add restart/scaling behavior tests for key stateful features.

## Phase 2: Assurance Expansion

- Add denial-path, bypass-resistance, and transition-conflict test coverage.
- Add stronger CI gates for contract and security invariants.

## Phase 3: Integration Maturity

- Expand MDM connector implementation to match advertised platform matrix or reduce advertised matrix.
- Define and enforce integration support tiers.

---

## 5) Acceptance Gates

- **Gate A:** No unresolved permission-model inconsistencies in security-critical routes.
- **Gate B:** Critical stateful services have defined durability semantics and tests.
- **Gate C:** Demo/simulated modes are explicit and excluded from production assurance metrics.
- **Gate D:** Integration claims in docs exactly match implemented runtime behavior.

---

## 6) Final Guidance

Feature breadth is no longer the primary constraint.  
The roadmap priority is to make existing capability **predictable, durable, and auditable** across all major domains.
