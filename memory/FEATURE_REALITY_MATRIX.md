# Metatron Feature Reality Matrix

Generated: 2026-04-18  
Scope: Quantitative/qualitative feature reality snapshot revalidated against current repository code.

## Legend
- `PASS`: Real logic executes in normal configured environments.
- `PARTIAL`: Real logic exists, but depth depends on optional integrations, provider coverage, or assurance maturity.
- `LIMITED`: Compatibility shell or reduced-depth implementation.

---

## Maturity Score Table (Current Rebaseline)

| Domain | Score (0-10) | Status | Notes |
|---|---:|---|---|
| Unified Agent Control Plane | 9.5 | PASS | Rich `/api/unified/*` control, telemetry, installers, commands, rollouts, and monitor-state endpoints. |
| EDM Governance & Rollouts | 9.5 | PASS | Dataset versioning, publish gates, staged rollout/readiness checks, manual + auto rollback pathways. |
| DLP & Endpoint EDM Detection | 9.0 | PASS | Agent-side DLP monitor and EDM hit loopback present. |
| Email Protection | 9.0 | PASS | SPF/DKIM/DMARC, URL/attachment, impersonation, DLP, quarantine logic implemented. |
| Email Gateway | 8.5 | PASS | Process/quarantine/list management/policy endpoints and decision engine are implemented. |
| Mobile Security | 8.5 | PASS | Device registration/lifecycle, threating, app analysis, compliance and dashboard coverage. |
| MDM Connectors | 7.0 | PARTIAL | Intune/JAMF concrete connectors implemented; Workspace ONE/Google Workspace currently enumerated but not concretely implemented connector classes. |
| Identity Protection | 8.5 | PASS/PARTIAL | Durable incident transitions + provider event ingestion; depth tied to inbound telemetry quality and policy use. |
| CSPM Capability Plane | 8.5 | PASS/PARTIAL | Durable scan/finding transitions + provider persistence + triune gating; operational quality depends on configured cloud creds/provider readiness. |
| Enterprise Governance Plane | 9.0 | PASS | Identity, policy, token, tool execution gating, telemetry chain, governance decisions are live. |
| Deployment Realism | 8.0 | PASS/PARTIAL | SSH/WinRM paths real; simulation available only when explicitly enabled by env flag. |
| Browser Isolation | 6.5 | PARTIAL | URL analysis/session/sanitize/blocklist paths present; full remote isolation depth remains limited. |

---

## Current Reality Matrix

| Domain | Status | Code Evidence | Practical Notes |
|---|---|---|---|
| Backend route wiring | PASS | `backend/server.py` | 65 `include_router` registrations; broad API surface. |
| Router coverage breadth | PASS | `backend/routers/*.py` | 62 router modules and ~694 route decorators currently present. |
| Unified agent lifecycle and command plane | PASS | `backend/routers/unified_agent.py` | Registration, heartbeat, commands, deploy, installers, monitor introspection are implemented. |
| Unified agent monitor breadth | PASS | `unified_agent/core/agent.py` | 27 monitor modules instantiated (platform-conditional WebView2/AMSI included). |
| EDM rollout governance | PASS | `backend/routers/unified_agent.py` | Stage progression, readiness computation, conflict-safe transitions, rollback flows. |
| Email protection backend | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | DNS auth checks + phishing/attachment/DLP/impersonation and management endpoints. |
| Email gateway backend | PASS | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Message parse/process, policy thresholds, quarantine and list controls. |
| Mobile security backend | PASS | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Threat categories, compliance checks, app analysis and dashboard endpoints. |
| MDM connector service depth | PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | API includes broader platform metadata; service concretely wires Intune/JAMF connectors. |
| CSPM authentication + durability | PASS/PARTIAL | `backend/routers/cspm.py` | Auth required for scan, scan/finding state transition logs, provider config persistence and gating. |
| Identity durability and ingest | PASS/PARTIAL | `backend/routers/identity.py` | Incident status transitions and provider event ingest implemented (Entra/Okta/M365 OAuth consent). |
| Governance API plane | PASS | `backend/routers/governance.py`, `backend/routers/enterprise.py` | Decision approval/deny + executor + outbound-gated critical enterprise actions. |
| Browser isolation controls | PARTIAL | `backend/routers/browser_isolation.py`, `backend/browser_isolation.py` | Useful controls exist; still not full remote-browser isolation parity with dedicated RBI products. |
| Deployment safety semantics | PASS/PARTIAL | `backend/services/agent_deployment.py` | Real deployment methods with retries; simulation is explicit and env-gated. |

---

## Acceptance Snapshot (Documentation Rebaseline Context)

- This matrix reflects current repository code paths (not prior release claims).
- Previous claims of full 4-platform MDM connector implementation were adjusted to match actual connector class depth.
- API breadth is substantial; maturity scoring emphasizes durable execution and integration depth, not route count alone.

---

## Remaining High-Value Gaps

1. Complete Workspace ONE and Google Workspace concrete connector implementations to match current API/platform metadata.
2. Expand browser isolation from policy/sanitization/session controls toward stronger remote-isolation guarantees.
3. Increase adversarial and denial-path automated test depth for high-impact control planes.
4. Continue tightening deployment success semantics with stronger install-verification evidence in heterogeneous environments.

---

## Bottom Line

Metatron remains a high-capability security platform with real control-plane depth and broad domain implementation.  
The most important documentation correction is to separate:

- **API and framework presence**, from
- **fully realized provider/integration depth**.

This matrix reflects that distinction directly.
