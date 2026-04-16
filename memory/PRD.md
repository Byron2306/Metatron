# Seraph / Metatron Product Requirements Snapshot (Current-State PRD)

**Last updated:** 2026-04-16  
**Purpose:** Replace historical release-log inflation with current, code-grounded product requirements snapshot

---

## 1) Product Definition

Seraph/Metatron is a unified security platform that combines:

- a FastAPI backend control plane,
- a React workspace-oriented SOC frontend,
- a cross-platform unified endpoint agent,
- optional security integrations (SIEM, sandbox, network sensors, LLM assist, governance gates).

The product goal is integrated detection, investigation, response, and governance across endpoint, cloud, email, and mobility domains.

---

## 2) Current System Requirements (Functional)

## 2.1 Core platform requirements

1. Backend must expose a modular API surface (current `backend/server.py` wiring: 65 router includes).
2. Frontend must support workspace-based operations for command, investigation, response, platform, and engineering tasks.
3. Authentication must support JWT bearer tokens and role-based authorization.
4. Platform must run with MongoDB and support local/containerized deployment via Docker Compose.

## 2.2 Security control requirements

1. JWT secret quality must be enforced in strict/production mode.
2. Role-based permission checks must guard privileged operations.
3. Remote-admin-only access policy must be enforceable for non-local requests.
4. CORS must be explicit and strict-mode protected.
5. Machine-to-machine token validation helpers must be available for internal APIs.

## 2.3 Domain requirements

### Unified endpoint and agent control

- Support agent registration, heartbeat, command dispatch, telemetry collection.
- Expose EDM dataset/rollout lifecycle operations (create version, publish, rollback, rollout control).

### Email security

- Provide mailbox-level email protection operations (analysis, auth checks, DLP, quarantine).
- Provide gateway-level email handling operations (processing, policy, quarantine, allow/block controls).

### Endpoint mobility

- Provide mobile security lifecycle operations (device posture/threat/compliance/app-analysis flows).
- Provide MDM connector management and remote device action APIs.

### Cloud posture

- Provide CSPM provider management, scan workflows, findings/compliance/dashboard access.
- Gate high-impact CSPM actions through governance control.

---

## 3) Current Non-Functional Requirements

1. **Traceability:** key actions should emit auditable events.
2. **Resilience:** optional integrations should degrade without collapsing core SOC workflows.
3. **Extensibility:** new security domains should be attachable via additional routers/services.
4. **Operational clarity:** runtime modes (core vs optional profiles) must be explicit in docs and compose configs.

---

## 4) Product Surface Inventory (Code-Verified Highlights)

- Backend API framework: FastAPI (`backend/server.py`)
- Auth and RBAC: `backend/routers/dependencies.py`, `backend/routers/auth.py`
- Unified control plane: `backend/routers/unified_agent.py`
- Endpoint agent runtime: `unified_agent/core/agent.py`
- Email protection/gateway: `backend/email_protection.py`, `backend/email_gateway.py`
- Mobile and MDM: `backend/mobile_security.py`, `backend/mdm_connectors.py`
- CSPM: `backend/routers/cspm.py`
- Frontend app and workspace routing: `frontend/src/App.js`
- Frontend navigation: `frontend/src/components/Layout.jsx`
- Runtime stack: `docker-compose.yml`

---

## 5) Corrected Product Truths (Important)

1. MDM enum and API support reference 4 platforms, but current concrete connector implementations are present for:
   - Intune
   - JAMF
2. Workspace One and Google Workspace are not currently implemented as concrete connector classes in `backend/mdm_connectors.py`.
3. Historical version-history narratives in prior PRD revisions mixed roadmap, partial implementation, and fully shipped behavior; this file now tracks present-state requirements only.

---

## 6) Acceptance Criteria for Current Product Baseline

Product baseline is satisfied when:

1. Core services are up (backend/frontend/mongodb minimum).
2. Auth works for register/login/me and permissioned routes.
3. Workspace routing works for:
   - `/email-security` (+ tab redirects),
   - `/endpoint-mobility` (+ tab redirects),
   - `/cspm`,
   - `/unified-agent`.
4. Domain APIs respond for:
   - email protection/gateway,
   - mobile security,
   - mdm connectors,
   - unified agent,
   - cspm.

---

## 7) Product Risks to Track

1. Documentation drift from implementation reality.
2. API contract drift between frontend workspaces and backend payloads.
3. Governance durability and restart behavior for high-impact workflows.
4. Optional integration inconsistency in degraded-mode user experience.

---

## 8) PRD Maintenance Rule

This PRD should be updated by **implemented code evidence**, not by roadmap intent.  
When in doubt, include:

- exact file path,
- concrete route/class evidence,
- explicit "implemented vs partial vs planned" status.

