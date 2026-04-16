# Metatron Security Features Analysis (Rebaseline)

**Generated:** 2026-04-16  
**Classification:** Code-evidence assessment

---

## Overview

This update re-evaluates security features against current repository logic and corrects previously overstated claims. Security functionality is broad and real, with strongest maturity in control-plane governance, auth hardening, and durability-aware workflows.

---

## 1) Implemented Security Features (Current Reality)

### A) Authentication, Authorization, and Access Control

| Capability | Evidence | Status |
|---|---|---|
| JWT token creation/validation | `backend/routers/dependencies.py` | Implemented |
| Production/strict JWT hardening | `backend/routers/dependencies.py` | Implemented |
| Role-based permission checks | `check_permission`, `ROLES` model | Implemented |
| Remote admin gating | `get_current_user` (`REMOTE_ADMIN_ONLY`) | Implemented |
| Setup-token protected bootstrap admin endpoint | `backend/routers/auth.py` (`/auth/setup`) | Implemented |
| Machine-token dependencies for service flows | dependencies + multiple routers | Implemented |

### B) Unified Agent Governance and Security

| Capability | Evidence | Status |
|---|---|---|
| Authenticated register/heartbeat loop | `backend/routers/unified_agent.py` | Implemented |
| HMAC-based agent token validation | `verify_agent_auth` path | Implemented |
| Governed high-impact command queueing | governed dispatch usage in unified router | Implemented |
| Command authority/decision context contract | unified command serialization and dispatch | Implemented |
| Command/deployment state transition logs | unified router + deployment service | Implemented |

### C) Data Protection and EDM

| Capability | Evidence | Status |
|---|---|---|
| EDM dataset versioning and signing metadata | unified router EDM endpoints | Implemented |
| Publish gates and quality thresholds | `_enforce_edm_publish_gates` usage | Implemented |
| Progressive rollout and rollback | EDM rollout endpoints | Implemented |
| Agent EDM telemetry ingestion | heartbeat EDM hit processing | Implemented |

### D) Cloud and Identity Security

| Capability | Evidence | Status |
|---|---|---|
| CSPM scan/finding/resource routes | `backend/routers/cspm.py` | Implemented |
| CSPM scan auth enforcement | `Depends(get_current_user)` on scan | Implemented |
| Identity incident lifecycle and response | `backend/routers/identity.py` | Implemented |
| Identity incident state-version transitions | identity router state transition helpers | Implemented |

### E) Email and Mobile Security

| Capability | Evidence | Status |
|---|---|---|
| SPF/DKIM/DMARC checks | `backend/email_protection.py` | Implemented |
| Phishing, URL, attachment, DLP analysis | `backend/email_protection.py` | Implemented |
| Email gateway policy/list/quarantine API surface | `backend/routers/email_gateway.py` | Implemented |
| Mobile device/threat/compliance/app-analysis APIs | `backend/routers/mobile_security.py` | Implemented |
| MDM connector management APIs | `backend/routers/mdm_connectors.py` | Implemented |
| Intune + JAMF connector implementations | `backend/mdm_connectors.py` | Implemented |

---

## 2) Important Corrections and Limits

### 2.1 MDM connector breadth

- Workspace ONE and Google Workspace are listed as platforms in API metadata/enums.
- Manager-level connector creation currently supports Intune and JAMF instantiation paths.
- Classification: **partial breadth implementation**.

### 2.2 Email/Mobile durability model

- Email protection, email gateway queues/lists, and mobile security service structures are primarily in-memory.
- Classification: **implemented logic with persistence limitations**.

### 2.3 CSPM auth normalization

- Scan route is authenticated.
- Some supporting routes are less strict than scan/write paths.
- Classification: **strong but not fully normalized auth posture**.

### 2.4 Secret fallback behavior

- Agent secret has a development fallback if env is unset.
- Requires strict environment management in production.

---

## 3) Updated Security Maturity Snapshot

| Domain | Maturity |
|---|---|
| Auth and access controls | High |
| Unified command governance | High |
| EDM governance lifecycle | High |
| Identity durability | Medium-High |
| CSPM operational security | Medium-High |
| Email security (analysis plane) | Medium-High |
| Mobile and MDM security | Medium |
| Persistence consistency across all security domains | Medium |

---

## 4) Priority Security Hardening Actions

1. Normalize auth dependencies across all CSPM-related endpoints.
2. Remove or strictly guard development secret fallback behaviors in production paths.
3. Persist currently in-memory security state where forensic/audit durability matters.
4. Align MDM documentation and platform claims to implemented connector depth.
5. Extend durability and denial-path tests for email/mobile/MDM surfaces.

---

## Final Assessment

The platform implements a substantial set of real security controls and workflows. The next maturity step is consistency hardening: auth normalization, persistence parity, and contract accuracy across all documented capability claims.
