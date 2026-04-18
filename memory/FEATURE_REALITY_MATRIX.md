# Metatron Feature Reality Matrix (Revalidated)

**Updated:** 2026-04-18  
**Method:** direct repository code-path validation  
**Purpose:** quantitative PASS/PARTIAL/LIMITED snapshot with corrected platform claims

---

## Legend

- `PASS`: implemented path exists and executes in normal configured environments.
- `PARTIAL`: implemented but materially constrained by missing runtime support, environment, or integration depth.
- `LIMITED`: present mostly as metadata/placeholder/compatibility veneer.

---

## Domain Scorecard

| Domain | Score (0-10) | Status | Notes |
|---|---:|---|---|
| Unified Agent Control Plane | 9.5 | PASS | Register/heartbeat/commands, monitors, installers, command state transitions. |
| EDM Governance Lifecycle | 9.5 | PASS | Versioning, publish gates, signatures, staged rollout, readiness, rollback. |
| Email Protection | 9.0 | PASS | SPF/DKIM/DMARC + phishing + attachment + DLP analysis implemented. |
| Email Gateway | 8.5 | PASS/PARTIAL | Gateway decisioning + block/allow/quarantine APIs; relay production integration is conditional. |
| Mobile Security | 8.5 | PASS | Device lifecycle, app analysis, threat/compliance and dashboard flows present. |
| MDM Connectors | 7.0 | PARTIAL | Intune/JAMF runtime support implemented; Workspace ONE/Google exposed in metadata but not manager instantiation. |
| CSPM | 8.5 | PASS/PARTIAL | Durable state + auth gate + scanners; real provider outcomes depend on credentials/runtime. |
| Governance Queue + Executor | 8.8 | PASS | Outbound gate + triune queue + executor loop + approve/deny APIs wired. |
| Security Hardening | 8.5 | PASS | JWT secret policy, CORS strict behavior, remote admin gating, machine-token helpers. |
| Browser Isolation | 6.5 | PARTIAL | URL filtering/analysis path exists; full remote isolation still limited. |

---

## Reality Matrix (Corrected)

| Capability | Status | Evidence | Practical Reality |
|---|---|---|---|
| Unified agent register + heartbeat + command | PASS | `backend/routers/unified_agent.py` | Core endpoint and state workflows are implemented. |
| Command governance state transitions | PASS | `backend/routers/unified_agent.py`, `backend/services/governed_dispatch.py` | High-impact commands can be queued with decision context and transition logs. |
| EDM dataset versioning + publishing | PASS | `backend/routers/unified_agent.py` | Quality gates, checksums/signatures, publish + rollback are active paths. |
| EDM rollout readiness/advance/rollback | PASS | `backend/routers/unified_agent.py` | Canary staging and anomaly-triggered rollback logic present. |
| Email protection analysis | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | Multi-component analysis pipeline is implemented and routable. |
| Email gateway operations | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Decisioning and controls exist; production SMTP deployment specifics remain conditional. |
| Mobile security backend | PASS | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device, threat, policy, analysis and dashboard flows implemented. |
| MDM connector manager coverage | PARTIAL | `backend/mdm_connectors.py` | Manager instantiates Intune/JAMF only; other enum platforms not instantiated. |
| MDM API platform catalog | LIMITED/PASS | `backend/routers/mdm_connectors.py` | `/platforms` documents 4 platforms; runtime parity is incomplete. |
| CSPM scan auth gate | PASS | `backend/routers/cspm.py` | `start_scan` now depends on authenticated user context. |
| Governance decision APIs | PASS | `backend/routers/governance.py` | Pending/approve/deny/executor-run endpoints are wired. |
| Governance executor startup wiring | PASS | `backend/server.py`, `backend/services/governance_executor.py` | Background executor starts on app startup and processes approved decisions. |

---

## MDM Platform Reality (Explicit)

| Platform | Router Metadata | Connector Enum | Manager Instantiation | Effective Runtime |
|---|---|---|---|---|
| Intune | Yes | Yes | Yes | PASS |
| JAMF | Yes | Yes | Yes | PASS |
| Workspace ONE | Yes | Yes | No | PARTIAL/LIMITED |
| Google Workspace | Yes | Yes | No | PARTIAL/LIMITED |

---

## Current Gaps

1. Close MDM platform parity gap between exposed API catalog and actual connector-manager support.
2. Strengthen contract/integration tests for high-churn router + frontend page pairs.
3. Continue hardening browser isolation depth if positioned as enterprise isolation.
4. Keep memory docs and README synchronized with actual runtime paths.

---

## Bottom Line

The platform is materially real and robust in core control-plane, security, and telemetry pathways.  
The biggest correction from earlier memory documents is not capability collapse; it is **precision**: a few integration claims need tighter alignment to what code currently executes end-to-end.
