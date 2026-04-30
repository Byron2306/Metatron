# Metatron Security Features Analysis

**Updated:** 2026-04-30  
**Classification:** Code-evidence rebaseline  
**Scope:** Current security feature inventory and implementation reality.

---

## Overview

Metatron / Seraph implements a wide security feature set across endpoint detection, SOC operations, AI-agent defense, governance, deception, identity, cloud posture, email, mobile, and operational tooling. This analysis distinguishes always-wired runtime paths from integration frameworks that require external configuration.

## Implemented Security Feature Inventory

| Security domain | Current evidence | Reality |
|---|---|---|
| Endpoint detection and response | `unified_agent/core/agent.py`, `backend/routers/unified_agent.py`, `backend/edr_service.py` | Broad local monitors plus backend registration, telemetry, and command/control surfaces. |
| Process/network/DNS/registry monitoring | Agent monitor modules and `MONITOR_TELEMETRY_KEYS` in unified-agent router | Monitor summaries are accepted and projected into backend state. |
| DLP / EDM | `unified_agent/core/agent.py`, `backend/routers/unified_agent.py`, `backend/enhanced_dlp.py` | Dataset, fingerprint, telemetry, and rollout/governance concepts are implemented. |
| CLI cognition / AI-agent detection | `backend/services/cce_worker.py`, `backend/services/cognition_engine.py`, `backend/routers/cli_events.py` | Worker analyzes command sessions and can feed SOAR/world events. |
| AATL/AATR | `backend/services/aatl.py`, `backend/services/aatr.py`, `backend/routers/ai_threats.py` | Startup-initialized services and router surfaces exist. |
| Governance and approval | `backend/services/governed_dispatch.py`, `backend/services/outbound_gate.py`, `backend/routers/governance.py`, `backend/services/governance_executor.py` | High-impact automation can be gated, approved/denied, audited, and executed. |
| Tamper-evident telemetry | `backend/services/telemetry_chain.py`, unified-agent/governance usage | Audit hooks are used around unified-agent and governance events where configured. |
| Threat intel and correlation | `backend/threat_intel.py`, `backend/threat_correlation.py`, routers | Feed/enrichment/correlation code paths are present. |
| Response/SOAR/quarantine | `backend/soar_engine.py`, `backend/quarantine.py`, `backend/threat_response.py`, routers | Response and state-transition flows exist and are included in contract/durability tests. |
| Deception/honey tokens | `backend/deception_engine.py`, `backend/honey_tokens.py`, routers | Deception routes are mounted under `/api` and `/api/v1`; integration hooks are initialized in server startup. |
| Network security/VPN | `backend/vpn_integration.py`, `backend/services/network_discovery.py`, routers | VPN and network discovery services exist; runtime depends on host/network setup. |
| Container and cloud posture | `backend/container_security.py`, `backend/cspm_engine.py`, CSPM router | Frameworks exist; production findings depend on scanners/credentials. |
| Identity and zero trust | `backend/identity_protection.py`, `backend/zero_trust.py`, `backend/services/identity.py`, routers | Identity/zero-trust control surfaces exist; enterprise integration depth is environment-dependent. |
| Browser isolation | `backend/browser_isolation.py` | URL filtering/sanitization is present; full remote browser isolation remains partial. |
| Email protection | `backend/email_protection.py`, router, frontend workspace routes | Authentication/phishing/DLP style logic exists; live value depends on DNS/config/feed setup. |
| Email gateway | `backend/email_gateway.py`, router | Gateway/quarantine/policy framework exists; production SMTP deployment must be configured. |
| Mobile security | `backend/mobile_security.py`, router | Device lifecycle/threat/compliance framework exists. |
| MDM connectors | `backend/mdm_connectors.py`, router | Connector implementations exist for major MDM platforms; live sync requires credentials. |
| Kernel/secure boot | `backend/secure_boot_verification.py`, kernel sensor services/routers | Host capability and privilege dependent. |
| Multi-tenant and enterprise controls | `backend/services/multi_tenant.py`, `backend/routers/enterprise.py` | Tenant, policy, token, tool, telemetry control surfaces exist. |

## Security Control Plane Details

### Governed Command Path

- `GovernedDispatchService.queue_gated_agent_command()` writes commands with `gated_pending_approval`, `decision_id`, `queue_id`, state version, transition log, authority context, and gate metadata.
- `/api/governance/decisions/pending` lists pending decisions.
- `/api/governance/decisions/{decision_id}/approve` marks decisions approved and can run the executor immediately.
- `/api/governance/decisions/{decision_id}/deny` marks decisions denied and rejects pending agent commands tied to the decision.
- `GovernanceExecutorService` processes approved decisions into command queues or supported domain operations and records audit/world events.

### Static Security Guardrails

`backend/scripts/governance_guardrails.py` checks:

1. Scoped mutating endpoints include write/admin/delete/manage-user or machine-token-style dependencies.
2. Backend code avoids broad shell execution patterns outside explicit allowlists.
3. Direct command queue writes do not bypass `backend/services/governed_dispatch.py`.

### Runtime Boundary Controls

- `backend/server.py` rejects wildcard CORS origins in production/strict mode.
- Production requires `INTEGRATION_API_KEY` for internal ingestion/workers.
- Agent WebSocket access verifies machine tokens with environment-backed token names.
- Docker Compose defaults bind key service ports to localhost unless overridden.

## Residual Security Gaps

| Gap | Why it matters | Direction |
|---|---|---|
| Uniform auth on every legacy/compatibility route | Large router surface increases drift risk. | Keep guardrails current and broaden route-scope checks. |
| Governance HA/replay semantics | Approval/execution must remain safe across restart/scale. | Add stronger durability and exactly-once/replay-prevention tests. |
| Integration degraded states | Operators need to know when a feature is framework-only vs live. | Add explicit health state schemas and UI indicators. |
| Browser isolation depth | Current implementation should not imply full remote browsing. | Document as partial unless/until pixel-streamed isolation lands. |
| Agent anti-tamper and kernel depth | Host-level controls vary by OS and privileges. | Tie claims to platform-specific evidence and tests. |
| Documentation drift | Stale claims can overstate security posture. | Keep review docs path-based and date-stamped. |

## Summary Metrics

| Metric | Current code-evidence reading |
|---|---|
| Backend router files | 62 |
| Active router registrations in `server.py` | 65 |
| Router decorator endpoints, rough static count | 697 |
| Frontend page components | 69 |
| React route declarations | 66 |
| Backend test files | 63 |
| Unified-agent test files | 4 |
| Docker Compose service keys, rough static count | 38 |

## Final Assessment

The security feature set is broad and real at the framework/control-plane level. The strongest current differentiator is the combination of unified endpoint telemetry, world-state projection, AI/cognition services, and governance-gated automation. The most important remaining work is not adding more feature names; it is making each feature's live/degraded state explicit, strengthening policy and denial-path tests, and keeping all high-impact actions inside the governed dispatch path.
