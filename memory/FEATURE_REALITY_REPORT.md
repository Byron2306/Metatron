# Feature Reality Report

Generated: 2026-04-21  
Scope: Qualitative implementation narrative (feature depth, durability, governance, and operational realism)

---

## Executive Verdict

The platform is broad and technically advanced, with strong implementation across endpoint, cloud, email, mobile, and governance planes. Core claims are now mostly code-backed, but some prior documentation overstated maturity in specific areas.

### Most important correction

`backend/mdm_connectors.py` currently implements **two concrete MDM connectors**:
- `IntuneConnector`
- `JAMFConnector`

`WORKSPACE_ONE` and `GOOGLE_WORKSPACE` are present in enums/UI metadata, but no concrete connector classes are implemented yet. Any claim of four fully implemented connectors is inaccurate against current code.

---

## Maturity Table (Code-Backed)

| Domain | Score (0-10) | Status | Reality Summary |
|---|---:|---|---|
| Unified Agent Control Plane | 9.0 | PASS | Large telemetry and command surface with governed dispatch integration |
| EDM Governance and Telemetry | 9.0 | PASS | Dataset lifecycle, rollout, rollback, and telemetry loops are implemented |
| Email Protection | 9.0 | PASS | SPF/DKIM/DMARC, phishing, attachment, impersonation, DLP checks are in code |
| Email Gateway | 8.5 | PASS | Inline processing, quarantine, block/allow lists, policy updates, stats |
| Mobile Security | 8.3 | PASS | Device lifecycle, app analysis, compliance, network threat checks |
| MDM Connectors | 6.8 | PARTIAL | Intune + JAMF concrete connectors; Workspace One/Google listed but not implemented |
| CSPM | 8.5 | PASS | Authenticated scan endpoint and scan persistence/workflow present |
| Governance / Outbound Gate | 8.8 | PASS | High-impact actions routed to triune queue and executor pipeline |
| Zero Trust | 7.8 | PARTIAL | Trust scoring and policy evaluation present; long-tail durability still maturing |
| Browser Isolation | 6.8 | PARTIAL | URL and content controls implemented; full remote pixel-stream isolation absent |

---

## Domain Reality

### 1) Email Gateway

**Evidence:** `backend/email_gateway.py`, `backend/routers/email_gateway.py`

Implemented now:
- `SMTPGateway` with inline processing and decisioning
- `MilterGateway` class for milter integration path
- Gateway stats, quarantine list/release/delete, policy update endpoints
- Sender/domain/IP blocklist and allowlist management
- Integration with email protection scoring logic

Still conditional:
- Production SMTP deployment and hardening are environment-dependent
- External reputation feed integration is limited

### 2) Email Protection

**Evidence:** `backend/email_protection.py`, `backend/routers/email_protection.py`

Implemented now:
- DNS-based SPF/DKIM/DMARC checks
- URL analysis (shorteners, suspicious patterns, IP URLs)
- Attachment entropy and extension/signature checks
- Impersonation checks and protected-user workflows
- DLP scanning and quarantine support

### 3) Mobile Security

**Evidence:** `backend/mobile_security.py`, `backend/routers/mobile_security.py`

Implemented now:
- Device registration and lifecycle operations
- Jailbreak/root and risky app/security posture analysis
- OWASP-oriented application checks
- Compliance scoring and policy checks
- Network security signals (rogue Wi-Fi/MITM-style indicators)

### 4) MDM Connectors

**Evidence:** `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py`

Implemented now:
- Intune connector with Graph API flows (including mock fallback path)
- JAMF connector with JAMF API flows (including mock fallback path)
- Connector manager for connect/sync/action orchestration
- API routes for connector lifecycle, device actions, sync, and compliance views

Corrected interpretation:
- `/api/mdm/platforms` advertises Intune, JAMF, Workspace One, and Google Workspace
- Service-level `add_connector(...)` only accepts Intune and JAMF
- Workspace One and Google Workspace are roadmap/contract placeholders today

### 5) CSPM and Security Hardening

**Evidence:** `backend/routers/cspm.py`, `backend/server.py`, `backend/routers/dependencies.py`

Implemented now:
- `/api/v1/cspm/scan` requires authenticated user dependency
- CORS origin hardening for production/strict mode in server startup
- JWT secret policy enforcement in production/strict mode

### 6) Governance and Controlled Execution

**Evidence:** `backend/services/outbound_gate.py`, `backend/services/governance_authority.py`, `backend/services/governance_executor.py`, `backend/services/governed_dispatch.py`

Implemented now:
- Mandatory high-impact action classes are triune-gated by outbound gate
- Decision authority supports approve/deny transitions
- Executor processes approved decisions and dispatches domain operations/tool/command/token actions
- Governance endpoints allow pending decision retrieval and executor run-once

Important nuance:
- Mandatory action set is explicit and strong, but still finite (policy intent broader than hardcoded set)

---

## Corrected "What Works" Statement

### Materially real now
- Unified agent registration/heartbeat/telemetry and command scaffolding
- EDM dataset lifecycle and governance mechanics
- Email protection and email gateway operational surfaces
- Mobile security pipeline and partial MDM integration
- CSPM scan workflow with required authentication
- Triune-style governance queue + decision + execution chain

### Works with constraints
- Production-grade SMTP and MDM operations depend on real credentials/infrastructure
- Some advanced integrations rely on optional dependencies and fallback behavior
- Browser isolation depth is limited compared with full remote browser streaming models

### Not yet fully realized
- Workspace One and Google Workspace connector implementations
- Full remote browser isolation model
- Broader evidence automation/compliance packaging depth

---

## Reality-Driven Priority Actions

1. Implement Workspace One and Google Workspace connector classes to match declared platform contract.
2. Add connector contract tests that fail if a platform appears in API metadata without concrete implementation.
3. Harden production deployment playbooks for SMTP relay and live MDM credentials.
4. Continue governance durability and denial-path test expansion.
5. Extend browser isolation from sanitization/filtering into full remote isolation modes.

---

## Final Reality Statement

The platform is enterprise-capable across many domains and clearly beyond prototype stage.  
The primary documentation risk was overstatement, not absence of implementation.

Current truth:
- Email protection/gateway, mobile security, CSPM auth hardening, and governance pathways are materially implemented.
- MDM is **partially implemented** (Intune + JAMF complete; Workspace One + Google Workspace pending concrete connectors).

This report should be treated as the current baseline for planning, validation, and external claims.
