# Feature Reality Report (Code-Verified Refresh)

**Last revalidated:** 2026-04-21  
**Scope:** Runtime implementation reality vs legacy claims

---

## Executive Verdict

Seraph has broad implemented functionality, but several historical "fully complete" claims overstate current depth. The platform should be described as **high-capability with mixed operational maturity**, not uniformly enterprise-complete.

---

## Reality by Domain

## 1) Unified Agent Control Plane

**Status:** Mature core path

- Agent registration and heartbeat are implemented in `backend/routers/unified_agent.py`.
- Registration supports enrollment key (`SERAPH_AGENT_SECRET`) and issues per-agent auth tokens.
- Heartbeats include monitor telemetry and EDM hit loop-back.
- Agent runtime (`unified_agent/core/agent.py`) runs many monitor modules and periodic heartbeat.

**Constraints**
- Contract breadth is large; stronger schema regression gating is still needed.

## 2) EDM / DLP Governance

**Status:** Strong, actively implemented

- EDM dataset versioning, publish, rollout, readiness, rollback, and telemetry endpoints are present.
- Agent DLP monitor supports signed dataset updates, version checks, candidate filtering, and hit reporting.

**Constraints**
- Governance state durability is uneven by module; some supporting logic remains file/local-state dependent.

## 3) Deployment Realism

**Status:** Operational with explicit conditional behavior

- Real deployment methods exist for SSH and WinRM (`backend/services/agent_deployment.py`).
- Simulation mode is explicit and gated by `ALLOW_SIMULATED_DEPLOYMENTS`.
- Deployment tasks and mirrored device deployment status use transition logs and state versions.

**Constraints**
- Success still depends on environment credentials/connectivity and remote prerequisites.

## 4) CSPM

**Status:** Operational with governance queueing + demo fallback

- CSPM scan/finding records persist with transition history.
- Provider configure/remove and scan start paths use triune gating metadata (`queue_id`, `decision_id`).
- When no providers are configured, scan path can return seeded local demo data.

**Constraints**
- Demo fallback must not be treated as equivalent to live cloud scan assurance.

## 5) Email Protection

**Status:** Implemented and functionally rich

- SPF/DKIM/DMARC checks, URL/attachment analysis, impersonation and DLP analysis are implemented.
- Assessment scoring and auto-quarantine behavior are present.

**Constraints**
- Service state is primarily in-memory; persistence/durability semantics are limited by default.

## 6) Email Gateway

**Status:** Implemented

- Gateway processing, policy updates, blocklist/allowlist, quarantine operations, and stats APIs are present.
- Integrates with email protection scoring.

**Constraints**
- Runtime queues/lists are in-memory service state.

## 7) Mobile Security

**Status:** Implemented

- Device registration/status, app analysis, compliance checks, threat lifecycle, and dashboard aggregation are present.

**Constraints**
- Primarily in-memory service state; durable multi-node behavior is limited.

## 8) MDM Connectors

**Status:** Partial relative to previous claims

- Router and enum surface includes Intune, JAMF, Workspace ONE, Google Workspace.
- Current connector manager implementation actually instantiates **Intune and JAMF** only.

**Constraints**
- Prior docs claiming all four connectors as fully implemented are inaccurate for current manager logic.

---

## Corrected "What Works" Summary

### Materially real and currently usable

- Unified agent registration/heartbeat/control flows
- EDM dataset governance + agent EDM loop-back
- Deployment worker with real SSH/WinRM branches
- CSPM durable scan/finding APIs with governance queue metadata
- Email protection and email gateway route/service logic
- Mobile security route/service logic

### Real but conditional/partial

- CSPM live posture quality (provider credentials and environment required; demo mode exists)
- MDM breadth (platform enum/router wider than manager implementation)
- Enterprise durability consistency across restart/scale conditions

---

## Priority Accuracy Corrections Applied in This Refresh

1. Removed "all domain gaps closed" phrasing.
2. Corrected MDM connector implementation reality (2 currently wired in manager).
3. Marked CSPM demo-seed behavior as demo fallback, not live parity.
4. Reframed email/mobile/gateway state handling as implemented but mostly in-memory.

---

## Final Reality Statement

Seraph should be described as a **high-breadth, actively hardened security platform with strong core control-plane implementation and uneven maturity across module durability and governance consistency**. It is production-capable in key paths, but not uniformly enterprise-complete across all claimed surfaces.
