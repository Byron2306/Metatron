# Metatron / Seraph System-Wide Evaluation (Rebaselined)

**Original file date:** March 2026  
**Rebaseline date:** 2026-04-16  
**Scope:** End-to-end feature reality and code-level maturity across major domains.

---

## Executive Summary (Updated)

The platform has broad domain coverage and substantial live logic, but maturity is uneven. Unified agent, EDM governance, deployment orchestration, and core auth controls are among the strongest areas. Email/mobile/MDM capabilities are real but should be described with tighter precision than earlier snapshots.

### Headline corrections from earlier March summary

- Email Gateway is implemented as an API/service processing layer with quarantine and policy controls; full production SMTP relay operation is not automatically active by default runtime path.
- MDM route surface lists four platforms, but manager-level connector implementation currently instantiates **Intune** and **JAMF**.
- CSPM scan operations are authenticated; provider-list endpoint is still less strict.
- Several domain modules maintain important runtime state in memory.

---

## 1) Domain Status Rebaseline

| Domain | Current Status | Notes |
|---|---|---|
| Unified Agent Control Plane | Strong | Registration, heartbeat, commands, monitor telemetry, deployment endpoints are active. |
| EDM Governance and Rollouts | Strong | Dataset versioning, signatures, rollout stages, readiness checks, rollback. |
| Core Auth and RBAC | Strong | JWT hardening, permission gates, remote-admin enforcement, machine-token dependencies. |
| Deployment Service | Strong / Conditional | Real SSH/WinRM with retries and transition logs; simulation is explicit and env-gated. |
| CSPM | Strong / Mixed auth coverage | Scan/start path requires auth; not all supporting endpoints are equally strict. |
| Identity Protection | Strong | Incident durability/state transitions and response action APIs are implemented. |
| Email Protection | Strong (analysis plane) | SPF/DKIM/DMARC, phishing, URL/attachment and DLP analysis implemented. |
| Email Gateway | Moderate-High | API processing, block/allow list, quarantine, policy update implemented; runtime SMTP integration claims must remain conservative. |
| Mobile Security | Moderate-High | Device/threat/compliance/app-analysis logic is implemented with broad API surface. |
| MDM Connectors | Moderate | Control plane and routes exist; manager currently supports Intune + JAMF connector instantiation. |

---

## 2) What Is Materially Real

### Unified Agent + EDM

- `/api/unified/agents/register`, `/heartbeat`, command delivery/result loops.
- Command dispatch includes authority/decision context and triune queue flow for high-impact operations.
- EDM supports registry, publish, fanout updates, staged rollouts, readiness checks, rollback.

### Deployment

- `backend/services/agent_deployment.py` executes real SSH/WinRM paths with retries.
- Transition durability fields (`state_version`, `state_transition_log`) are maintained for deployment tasks and mirrored device deployment state.

### Security controls

- Production/strict JWT and CORS enforcement in startup/dependencies.
- Remote admin gate defaults to restrictive mode.
- Websocket/internal token checks exist for machine flows.

---

## 3) Corrected Interpretation of Email, Mobile, and MDM

### Email Protection

Implemented analysis capabilities are substantial (auth checks, risk scoring, URL/attachment analysis, DLP patterns, protected-user handling, quarantine release path).

### Email Gateway

Implemented:

- Message parse/process APIs
- Threat-score based accept/tag/reject/quarantine/defer decisions
- Blocklist/allowlist APIs
- Policy read/update APIs

Constraint:

- Operational queue/state is in memory and production relay posture depends on deployment integration details outside the router alone.

### Mobile Security

Implemented:

- Device registration/status updates
- Threat lifecycle and resolution
- App security analysis and compliance checks
- Dashboard/stats APIs

Constraint:

- Core service state is in memory by default.

### MDM Connectors

Implemented:

- Connector management APIs and device action APIs
- Intune and JAMF connector classes with sync/action methods

Constraint:

- Workspace ONE / Google Workspace are listed but not currently instantiated in manager logic.

---

## 4) Updated Risk Summary

1. Documentation-to-code drift (high)
2. Uneven auth normalization across all routes (high)
3. In-memory state for selected security domains (medium-high)
4. Published connector breadth > implemented adapters (medium-high)
5. Startup/wiring centralization in `server.py` (medium)

---

## 5) Recommended Program Focus

1. Close route-level auth normalization gaps.
2. Persist selected in-memory operational state to durable collections.
3. Align MDM product contract to implemented connectors or complete remaining adapters.
4. Continue extending contract/durability tests from unified-agent/EDM patterns to email/mobile/MDM.

---

## Conclusion

Metatron remains a comprehensive security platform with meaningful depth in critical control-plane areas. Enterprise confidence will increase most by reducing consistency debt: auth normalization, durability parity, and documentation accuracy.
