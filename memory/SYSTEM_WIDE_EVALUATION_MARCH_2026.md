# Metatron / Seraph AI Defense Platform
## System-Wide Evaluation (Code Rebaseline)

**Rebaseline date:** 2026-04-24  
**Evidence scope:** live repository code in `/workspace`  
**Method:** direct source inspection (routers, services, agent core, frontend routes, compose topology)

---

## Executive Summary

This document replaces the earlier March snapshot with a code-verified April 2026 system view.

### Verified platform footprint

- **Backend router files:** 62 (`backend/routers/*.py`)
- **FastAPI router definitions:** 65 (`APIRouter(...)`)
- **Endpoint decorators:** 694 (`@router.get/post/put/delete/patch`)
- **Router includes in main server:** 65 (`backend/server.py` `include_router(...)`)
- **Frontend pages:** 68 (`frontend/src/pages/*.jsx`)
- **Docker services in root compose:** 21 (`docker-compose.yml`)

### Current overall position

- The platform remains **very broad** and **operationally feature-dense**.
- Core SOC workflows (threats, alerts, hunting, response, SOAR, timelines, quarantine) are implemented with active API and UI surfaces.
- Security hardening is materially present in core auth and server wiring.
- Key documentation drift existed in prior memory docs and is now corrected below.

---

## Architecture Reality (Current Code)

## 1) Backend composition

- `backend/server.py` mounts routers across SOC, advanced services, governance, identity/CSPM, unified agent, email/mobile, deception, and websocket flows.
- Core service startup also initializes:
  - CCE worker (`services/cce_worker.py`)
  - network discovery (`services/network_discovery.py`)
  - deployment service (`services/agent_deployment.py`)
  - AATL/AATR (`services/aatl.py`, `services/aatr.py`)
  - governance executor (`services/governance_executor.py`)

## 2) Frontend composition

- `frontend/src/App.js` is workspace-oriented and routes users into:
  - command workspace
  - investigation workspace
  - email security workspace
  - endpoint & mobility workspace
  - detection engineering workspace
- Legacy route aliases still exist, but many now redirect to workspace tabs.

## 3) Agent composition

- `unified_agent/core/agent.py` contains 27 unique monitor assignments in `self.monitors[...]`, including:
  - process/network/registry/process-tree/LOLBin/code-signing/DNS/memory
  - whitelist/DLP/vulnerability/YARA/AMSI
  - ransomware/rootkit/kernel/self-protection/identity
  - firewall/CLI telemetry/hidden-file/alias-rename/privilege-escalation
  - email protection/mobile security
  - auto-throttle (+ WebView2 on Windows)

---

## Domain-by-Domain Evaluation

## 1) Core SOC Operations — **PASS**

Implemented and wired:
- threats, alerts, hunting, correlation, timeline/timelines
- audit logging
- quarantine and threat-response
- SOAR playbooks and execution routes

Primary evidence:
- `backend/routers/threats.py`
- `backend/routers/alerts.py`
- `backend/routers/hunting.py`
- `backend/routers/correlation.py`
- `backend/routers/timeline.py`
- `backend/routers/quarantine.py`
- `backend/routers/response.py`
- `backend/routers/soar.py`

## 2) Unified Agent + EDM Governance — **PASS**

Implemented:
- registration/heartbeat/control/deployment flows
- EDM dataset governance and rollout endpoints
- monitor telemetry condensation and state projection hooks

Primary evidence:
- `backend/routers/unified_agent.py`
- `unified_agent/core/agent.py`

## 3) Security Hardening Baseline — **PASS (with consistency debt)**

Implemented:
- strict JWT secret policy (prod/strict mode rejects weak or missing secret)
- CORS strictness in prod/strict mode (wildcard disallowed)
- remote-admin gating for non-local requests
- machine token validation helpers for internal/agent paths
- CSPM scan route requires authenticated user

Primary evidence:
- `backend/routers/dependencies.py`
- `backend/server.py`
- `backend/routers/cspm.py`

## 4) Email Security — **PASS**

### Email Protection

Implemented:
- SPF/DKIM/DMARC checks
- phishing and suspicious URL heuristics
- attachment analysis (entropy/extension/signatures)
- impersonation and DLP checks
- quarantine/protected users/blocked senders/trusted domains

Evidence:
- `backend/email_protection.py`
- `backend/routers/email_protection.py`

### Email Gateway

Implemented:
- inline message parsing and policy scoring
- sender/domain/IP allowlist + blocklist checks
- quarantine release/delete flows
- policy update and stats endpoints

Evidence:
- `backend/email_gateway.py`
- `backend/routers/email_gateway.py`

Important correction:
- API supports **add/list allowlist**, but there is **no allowlist delete endpoint** in `backend/routers/email_gateway.py`.

## 5) Mobile Security — **PASS**

Implemented:
- device registration/status/compliance/threat tracking
- app analysis and policy update surfaces

Evidence:
- `backend/mobile_security.py`
- `backend/routers/mobile_security.py`

## 6) MDM Connectors — **PARTIAL (documentation corrected)**

Implemented in service layer:
- **Intune connector**
- **JAMF connector**

Not implemented in connector manager (despite enum/docs references):
- Workspace ONE connector class
- Google Workspace connector class

Evidence:
- `backend/mdm_connectors.py`
  - `MDMPlatform` includes `WORKSPACE_ONE` and `GOOGLE_WORKSPACE`
  - `MDMConnectorManager.add_connector(...)` currently handles only INTUNE and JAMF
- `backend/routers/mdm_connectors.py`
  - exposes platform metadata for 4 vendors, but runtime connector creation is 2-vendor today

## 7) Advanced Security Services — **PASS/PARTIAL**

Implemented route surfaces:
- MCP tools
- vector memory
- VNS flow + DNS ingestion
- quantum crypto operations
- AI reasoning endpoints with safe/fallback wrappers

Evidence:
- `backend/routers/advanced.py`
- `backend/services/mcp_server.py`
- `backend/services/vector_memory.py`
- `backend/services/vns.py`
- `backend/services/quantum_security.py`
- `backend/services/ai_reasoning.py`

## 8) Governance + Triune Gate — **PASS**

Implemented:
- pending decision listing
- approve/deny
- executor run-once

Evidence:
- `backend/routers/governance.py`
- `backend/services/governance_authority.py`
- `backend/services/governance_executor.py`
- `backend/services/governed_dispatch.py`

---

## Corrective Findings vs Prior Memory Docs

1. **MDM overstatement corrected**  
   Prior docs labeled all 4 major MDM connectors as implemented; current code executes Intune + JAMF only.

2. **Email gateway endpoint claims corrected**  
   Prior docs listed allowlist delete endpoints; current router does not implement delete for allowlist.

3. **Version labeling mismatch corrected**  
   Prior docs used broad "v6.7.0 current" framing, while runtime API metadata in `server.py` still identifies version `3.0.0`.

4. **Counts refreshed from live code**  
   Router/page/endpoint/service counts in earlier docs were stale and inconsistent with current repository state.

---

## Current Risk Register

## High

- **Contract drift between docs/UI/backend** on fast-moving routes and payloads.
- **MDM capability mismatch** between platform marketing metadata and actual connector manager implementation.

## Medium

- Hardening consistency across legacy/alternate code paths remains uneven.
- Governance and control-plane persistence semantics still depend heavily on runtime state assumptions.
- Optional integration variability (degraded-mode behavior) remains non-uniform by domain.

## Low

- Residual naming/version inconsistencies in docs and comments.

---

## Recommended Next Moves

1. Align MDM documentation/UI claims to actual connector support (or implement Workspace ONE and Google Workspace connectors in manager).
2. Add explicit allowlist removal endpoint in email gateway router if UI/operations need parity with blocklist.
3. Add CI-backed contract checks for high-traffic routers (unified, email, mobile, mdm, advanced).
4. Normalize production/degraded behavior docs to run-mode reality in `docker-compose.yml`.

---

## Final Evaluation

Metatron/Seraph is a mature, broad security platform with strong implementation depth across core SOC, endpoint telemetry, email/mobile security, and governed automation.  
The most important remaining gap is **capability/contract consistency**, not raw feature absence.
