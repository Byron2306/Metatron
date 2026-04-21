# Security Features Analysis (Code-Evidence Rebaseline)

Generated: 2026-04-21  
Classification: Code-evidence based capability map

---

## Overview

This analysis reflects current implementation state from backend services/routers, unified agent logic, and frontend workspace wiring.

Primary correction from earlier versions: MDM support was overstated. Only Intune and JAMF connectors are implemented in `backend/mdm_connectors.py`.

---

## Feature Coverage by Domain

| Domain | Reality | Status |
|---|---|---|
| Endpoint Detection and Response | Multi-monitor agent telemetry, command pathways, and backend ingest surfaces are implemented | Implemented |
| Threat Intelligence and Correlation | Threat intel + correlation service modules exist and are routed | Implemented |
| Response and Remediation | SOAR/quarantine/response planes are present with governance pathways | Implemented |
| Deception and AI defense | Deception engine and related routes/services exist and are wired | Implemented |
| Data Protection (DLP/EDM) | EDM dataset governance and DLP patterns exist in backend + unified agent | Implemented |
| Identity and enterprise controls | Identity attestation/policy/token/tool control surfaces are implemented | Implemented |
| CSPM | Multi-cloud CSPM engine and router with authenticated scan start | Implemented |
| Email Protection | SPF/DKIM/DMARC, phishing, URL, attachment, impersonation, DLP checks | Implemented |
| Email Gateway | SMTP-style processing, quarantine, policies, block/allow lists | Implemented |
| Mobile Security | Device risk/compliance/app/network workflows | Implemented |
| MDM Connectors | Intune and JAMF are implemented; Workspace One and Google are placeholders | Partial |
| Zero Trust | Device registration, trust scoring, policy eval, access logs | Implemented/Partial |
| Browser Isolation | URL and content sanitization controls are real | Partial |
| Quantum/VNS/Vector/AI advanced plane | Exposed through advanced router with governance wrapping on sensitive actions | Implemented/Conditional |

---

## Notable Security Controls Confirmed

### Auth and startup hardening

- `backend/routers/dependencies.py` enforces stronger JWT secret requirements in strict production mode.
- `backend/server.py` enforces explicit CORS origin behavior in strict production mode.

### CSPM authentication control

- `backend/routers/cspm.py` requires authenticated user context for `/api/v1/cspm/scan`.

### Governance for sensitive actions

- `backend/services/outbound_gate.py` contains explicit `MANDATORY_HIGH_IMPACT_ACTIONS`.
- `backend/services/governance_authority.py` manages decision transitions.
- `backend/services/governance_executor.py` executes approved actions and records execution outcomes.

---

## Email Security Details

### Email protection (`backend/email_protection.py`)

Implemented:
- SPF check (`check_spf`)
- DKIM check (`check_dkim`)
- DMARC check (`check_dmarc`)
- URL analysis (`analyze_url`)
- Attachment analysis (`analyze_attachment`)
- DLP scan (`analyze_dlp`)

### Email gateway (`backend/email_gateway.py`, `backend/routers/email_gateway.py`)

Implemented:
- Message processing decision pipeline
- Quarantine management endpoints
- Block/allow list management endpoints
- Policy read/update endpoints
- Stats endpoint

---

## Mobile and MDM Details

### Mobile security (`backend/mobile_security.py`)

Implemented:
- Device registration/lifecycle
- App analysis and risk checks
- Compliance checks
- Threat categorization

### MDM connectors (`backend/mdm_connectors.py`)

Implemented:
- `IntuneConnector`
- `JAMFConnector`

Declared but not implemented as concrete classes:
- Workspace One connector
- Google Workspace connector

Operational implication:
- API metadata advertises 4 platforms, but runtime manager supports 2.

---

## Remaining Gaps (Security-Relevant)

1. MDM connector completeness mismatch (docs/API metadata vs runtime implementations).
2. Browser isolation depth remains partial relative to full remote isolation models.
3. Production deployment depth still depends on external infrastructure and credentials for several modules.
4. Verification depth on denial-path/hardening scenarios should continue to expand.

---

## Final Assessment

The platform security implementation is substantial and materially real across most major domains.  
Its key current truth gap is not feature absence but **feature maturity consistency and claim accuracy**, especially for MDM connector coverage.

