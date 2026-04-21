# Seraph Technical Implementation Roadmap (Code-Reality Aligned)

Date: 2026-04-21  
Horizon: Rolling technical roadmap  
Purpose: Prioritize implementation work based on current code truth, not prior overclaims

---

## Program Objective

Maintain innovation breadth while increasing deterministic behavior, governance durability, and evidence-backed enterprise readiness.

---

## Workstreams

1. Contract Integrity
- Keep docs/UI/API behavior synchronized
- Add regression tests for high-risk router contracts

2. Runtime Reliability
- Improve deterministic startup/runtime behavior in optional dependency scenarios
- Strengthen deployment and degraded-mode semantics

3. Governance Hardening
- Expand high-impact action policy and denial-path coverage
- Improve durable governance state transitions and evidence

4. Detection Quality Engineering
- Expand measurable precision/recall and false-positive governance loops
- Strengthen quality telemetry in fast-changing detection surfaces

5. Integration Completion
- Implement missing MDM connectors declared by platform contract
- Raise integration maturity for external dependencies (SMTP, MDM creds, sandbox tooling)

---

## Phased Plan

### Phase 0: Truth Alignment

Goals:
- Remove documentation/code mismatches
- Lock key control-plane contracts

Key actions:
- Maintain corrected MDM scope statement (Intune/JAMF implemented)
- Add docs/tests preventing platform-claim drift
- Validate critical auth/governance route guarantees in CI

Exit criteria:
- No known high-impact doc-to-code mismatches in security-core domains

### Phase 1: Deterministic Runtime

Goals:
- Improve production predictability
- Reduce ambiguous fallback behavior in critical flows

Key actions:
- Strengthen startup preflight checks for required integrations
- Normalize optional dependency health signaling
- Improve runtime observability for failing integration paths

Exit criteria:
- Operator-visible and predictable behavior for major degraded states

### Phase 2: Governance Assurance Depth

Goals:
- Increase confidence in controlled execution and approval semantics

Key actions:
- Expand denial-path tests around triune decision lifecycle
- Broaden policy assurance and audit evidence coverage
- Harden replay/idempotency handling in execution chains

Exit criteria:
- High-impact governance actions produce consistent decision-to-execution evidence trails

### Phase 3: Integration Completion and Competitive Stability

Goals:
- Close remaining implementation gaps without sacrificing platform control quality

Key actions:
- Implement Workspace One and Google Workspace connectors (or explicitly keep roadmap-only)
- Deepen production SMTP/MDM deployment guidance and validation
- Raise browser isolation maturity beyond current partial mode

Exit criteria:
- Platform claims are fully evidence-backed for declared integration surface

---

## KPI Signals

- Contract break count per release (target: near zero on control-plane routes)
- Governance integrity rate for high-impact actions
- Detection quality trend visibility by threat class
- Integration readiness score for operationally required dependencies
- Documentation accuracy drift rate

---

## Immediate Backlog Starters

1. Add MDM platform contract test:
   - Fail when `/api/mdm/platforms` advertises connector without class implementation.
2. Add governance denial-path regression suite for triune + executor state transitions.
3. Add startup/preflight checks for production-mode required env/credential assumptions.
4. Expand browser isolation roadmap into concrete implementation milestones.

---

## Bottom Line

The roadmap should preserve Seraph's adaptive architecture while enforcing strict reality discipline.  
The next major unlock is not feature count; it is reliable, evidence-backed completion of already declared contracts.
