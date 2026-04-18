# Feature Reality Report

Generated: 2026-04-18  
Scope: Code-evidence rebaseline of major platform feature reality

---

## Executive Verdict

The platform remains broad and operationally rich, but the current state is best described as **production-capable with explicit integration and assurance constraints**, not universal full-depth parity across every security domain.

Core control planes (Unified Agent, EDM governance, Enterprise policy/token/tool paths, identity ingestion, and CSPM durability flows) are materially implemented. Email and mobile capabilities are real and usable; however, specific claims from earlier documents required correction (notably MDM connector depth and some maturity assumptions).

---

## Current Domain Snapshot (Reality-Aligned)

| Domain | Status | Reality Summary |
|---|---|---|
| Unified Agent Control Plane | PASS | Real registration/heartbeat/command/deployment/installer/monitor telemetry APIs under `/api/unified/*`. |
| EDM Governance & Rollouts | PASS | Versioned datasets, publish gates, rollout staging/readiness, rollback and telemetry loops implemented in `backend/routers/unified_agent.py`. |
| DLP & EDM Endpoint Detection | PASS | Agent-side DLP monitor and EDM hit telemetry loopback are present and wired. |
| Email Protection | PASS | SPF/DKIM/DMARC checks, URL/attachment analysis, impersonation and DLP paths in `backend/email_protection.py`. |
| Email Gateway | PASS | Inline processing/allowlist/blocklist/quarantine/policy endpoints in `backend/email_gateway.py` + router. |
| Mobile Security | PASS | Device lifecycle, threat detection, app analysis, compliance scoring and dashboard endpoints in `backend/mobile_security.py` + router. |
| MDM Connectors | PARTIAL PASS | Router advertises Intune/JAMF/Workspace ONE/Google Workspace; service implementation currently provides concrete connectors for **Intune and JAMF**, with other platform enum values not yet backed by connector classes. |
| Identity Protection | PASS/PARTIAL | Durable incident state machine and provider-event ingestion (Entra/Okta/M365 OAuth consent paths) are implemented; depth depends on incoming provider telemetry quality. |
| CSPM | PASS/PARTIAL | `/api/v1/cspm/scan` requires auth; scan/finding durability, status transitions, and provider config persistence are implemented; provider configure/remove operations are triune-gated. |
| Enterprise Governance Plane | PASS | Outbound-gated high-impact actions, policy evaluation, telemetry chain endpoints, and governance decision pathways are implemented. |
| Browser Isolation | PARTIAL | URL analysis/session/sanitization/blocklist endpoints are real; full remote browser isolation at enterprise depth remains limited. |
| Deployment Realism | PASS/PARTIAL | Real SSH/WinRM deployment paths exist with durable transition logs; simulation is controlled by `ALLOW_SIMULATED_DEPLOYMENTS` and disabled by default. |

---

## Important Corrections vs Earlier Narratives

### 1) MDM connector depth was overstated
- **Accurate now:** `backend/mdm_connectors.py` implements concrete connectors for Intune and JAMF.
- **Not yet concrete in service layer:** Workspace ONE and Google Workspace connector classes.
- **Implication:** platform list and API schema support broader MDM scope, but implementation depth is presently two fully realized connectors.

### 2) CSPM posture is stronger on control/assurance than older summaries indicated
- Scan endpoint auth is enforced (`Depends(get_current_user)` on `POST /api/v1/cspm/scan`).
- Scan/finding state transition logs and versioned updates are implemented in router durability logic.
- Provider write operations are governed via outbound gate + triune decision flow.

### 3) Deployment semantics are conditional by environment policy
- Real deployment exists.
- Simulation can still occur if explicitly enabled by `ALLOW_SIMULATED_DEPLOYMENTS=true`; docs should treat this as controlled demo mode, not default behavior.

---

## What Is Materially Real Today

- Backend API composition is extensive (62 router files, ~694 route decorators, 65 router registrations in `backend/server.py`).
- Unified agent monitor framework is broad (27 monitor modules instantiated in `unified_agent/core/agent.py`).
- Advanced and enterprise planes are live (MCP/vector memory/VNS/quantum/AI + identity/policy/token/tool/telemetry APIs).
- Email and mobile security are not placeholders; they expose meaningful detection and management logic with actionable endpoints.
- Governance and telemetry chains provide auditable lifecycle metadata across critical operations.

---

## What Remains Conditional or Limited

1. **MDM breadth:** Workspace ONE / Google Workspace remain partially represented at API/platform metadata level without concrete connector class parity.
2. **Browser isolation depth:** session and sanitization tooling exists, but fully hardened remote isolation remains an open depth area.
3. **Operational assurance:** breadth still exceeds exhaustive denial-path and adversarial regression coverage in some fast-moving areas.
4. **Integration realism:** external provider credentials and environment-specific dependencies still determine true end-to-end depth for several enterprise features.

---

## Bottom Line

Platform reality remains strong and improving, but the correct framing is:

- **Implemented:** broad multi-domain security control fabric with real operational paths.
- **Partially mature:** certain integrations and advanced isolation surfaces.
- **Priority for documentation accuracy:** distinguish implemented API surface from fully realized provider-depth behavior (especially MDM connector breadth claims).
