# Metatron Security Features Analysis (Code-Accurate Rebaseline)
**Updated:** 2026-04-18  
**Method:** source-level verification of active backend/agent code paths

---

## Overview

This document supersedes earlier broad-claim snapshots and records what is directly supported by current implementation logic.

---

## Feature Analysis by Security Domain

### 1) Authentication and Access Control

| Capability | Evidence | Status |
|---|---|---|
| JWT auth with expiration | `backend/routers/dependencies.py` | Implemented |
| Production/strict JWT secret enforcement | `backend/routers/dependencies.py` | Implemented |
| Role-based permission checks (`read/write/admin/...`) | `backend/routers/dependencies.py` | Implemented |
| Remote admin-only gate for non-local requests | `backend/routers/dependencies.py` | Implemented |
| Initial admin setup with optional setup token | `backend/routers/auth.py` | Implemented |

### 2) Governance and High-Impact Action Control

| Capability | Evidence | Status |
|---|---|---|
| Mandatory triune queueing for high-impact actions | `backend/services/outbound_gate.py` | Implemented |
| Governed command persistence with decision context | `backend/services/governed_dispatch.py` | Implemented |
| Governance decision approve/deny API | `backend/routers/governance.py` | Implemented |
| Executor processing of approved decisions | `backend/services/governance_executor.py` | Implemented |
| Governance loop started on backend startup | `backend/server.py` | Implemented |

### 3) CSPM (Cloud Security Posture Management)

| Capability | Evidence | Status |
|---|---|---|
| Scan state machine and durable transitions | `backend/routers/cspm.py` | Implemented |
| Finding state transitions with conflict checks | `backend/routers/cspm.py` | Implemented |
| Provider secret encryption-at-rest pattern | `backend/routers/cspm.py` | Implemented |
| Auth on `/api/v1/cspm/scan` | `backend/routers/cspm.py` | Implemented |
| Demo fallback when no providers configured | `backend/routers/cspm.py` | Implemented |

### 4) Unified Agent Security Plane

| Capability | Evidence | Status |
|---|---|---|
| Agent register/heartbeat/auth token checks | `backend/routers/unified_agent.py` | Implemented |
| Command queueing and status transition logging | `backend/routers/unified_agent.py` | Implemented |
| Endpoint monitor aggregation and monitor alert APIs | `backend/routers/unified_agent.py` | Implemented |
| Agent installer/download endpoints | `backend/routers/unified_agent.py` | Implemented |
| Websocket machine token validation for agent channel | `backend/server.py`, `backend/routers/dependencies.py` | Implemented |

### 5) EDM and Data Protection

| Capability | Evidence | Status |
|---|---|---|
| EDM fingerprint engine with canonicalization | `unified_agent/core/agent.py` | Implemented |
| EDM metadata verification (version/checksum/signature) | `unified_agent/core/agent.py` | Implemented |
| Dataset versioning and publish gates | `backend/routers/unified_agent.py` | Implemented |
| Progressive rollout readiness and rollback controls | `backend/routers/unified_agent.py` | Implemented |
| EDM telemetry summary endpoints | `backend/routers/unified_agent.py` | Implemented |

### 6) Email Security

| Capability | Evidence | Status |
|---|---|---|
| SPF/DKIM/DMARC checks | `backend/email_protection.py` | Implemented |
| URL, attachment, impersonation, DLP analysis | `backend/email_protection.py` | Implemented |
| Email protection management APIs | `backend/routers/email_protection.py` | Implemented |
| SMTP gateway processing + decisioning | `backend/email_gateway.py` | Implemented |
| Gateway quarantine/blocklist/allowlist/policy APIs | `backend/routers/email_gateway.py` | Implemented |

### 7) Mobile and MDM

| Capability | Evidence | Status |
|---|---|---|
| Mobile device registration/status/compliance/threat APIs | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Implemented |
| App security analysis and policy update flows | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Implemented |
| Intune connector | `backend/mdm_connectors.py` | Implemented |
| JAMF connector | `backend/mdm_connectors.py` | Implemented |
| Workspace ONE / Google Workspace full connector runtime | `backend/mdm_connectors.py` | **Not implemented in manager instantiation path** |

### 8) Telemetry and Audit

| Capability | Evidence | Status |
|---|---|---|
| Tamper-evident telemetry recording primitives | `backend/services/telemetry_chain.py` | Implemented |
| World event emission across major routers/services | multiple `backend/routers/*`, `backend/services/*` | Implemented |
| Governance execution completion + audit linkage | `backend/services/governance_executor.py` | Implemented |

---

## Key Corrections from Prior Versions

1. MDM support is currently **2 implemented connectors (Intune, JAMF)**, not 4 fully implemented connectors.
2. Security governance is not merely conceptual; high-impact actions are queued through triune decision flow.
3. CSPM scan endpoint is authenticated and backed by explicit state transition controls.
4. EDM governance includes publish quality gates and staged rollout logic rather than simple dataset push semantics.

---

## Practical Security Posture Summary

- **Strongest areas:** governance gating architecture, EDM lifecycle controls, email analysis depth, broad API security controls.
- **Most important residual gaps:** MDM platform parity, browser isolation depth, and broader contract/assurance automation across fast-moving surfaces.

**Overall assessment:** security implementation is substantial and real, with a few high-visibility consistency gaps that should be addressed before claiming complete parity across all documented platform integrations.
