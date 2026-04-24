# Feature Reality Report (Code-Evidence Refresh)

**Reviewed:** 2026-04-24  
**Scope:** Implementation reality narrative based on current repository code  
**Evidence set:** `backend/server.py`, `backend/routers/*`, `backend/*_service.py`, `frontend/src/App.js`, `unified_agent/*`

---

## Executive Verdict

Metatron is a broad, operational security platform with a dense FastAPI router mesh, workspace-driven React UI, and a unified agent control plane. The strongest present reality is in API breadth, endpoint orchestration, and SOC workflow coverage. The main constraints are consistency and assurance depth: some domains include demo/mock fallback behavior and should not be described as universally live-integrated by default.

---

## Current Reality by Domain

### 1) Core platform architecture
**Status:** Implemented, active

- Main backend entrypoint: `backend/server.py`
- Router model: large `/api/*` surface plus mounted `/api/v1/*` routers (e.g., CSPM, identity, kernel/secure-boot/attack paths)
- Frontend routing: consolidated workspace model in `frontend/src/App.js` with compatibility redirects

**Reality note:** The platform is actively modularized but still centrally wired in `server.py`, which remains a coupling hotspot.

---

### 2) Authentication and authorization
**Status:** Implemented with meaningful hardening controls

- JWT auth and role model (`admin`, `analyst`, `viewer`) in `backend/routers/dependencies.py`
- Production/strict mode secret enforcement (`JWT_SECRET` strength checks)
- Remote admin gating for non-local requests (`REMOTE_ADMIN_ONLY`, optional `REMOTE_ADMIN_EMAILS`)
- Machine-token helpers for service and websocket paths

**Reality note:** Core auth controls are real and wired; consistency across every legacy path still depends on ongoing normalization.

---

### 3) Unified agent control plane
**Status:** Strong implementation

- Router: `backend/routers/unified_agent.py` (mounted at `/api/unified/*`)
- Capabilities include:
  - agent registration and heartbeat
  - command dispatch/result lifecycle
  - monitor and alert surfaces
  - installer/bootstrap endpoints
  - EDM dataset versioning/rollout/rollback controls
- Agent auth supports enrollment key and per-agent token verification

**Reality note:** This is one of the most substantial and actively exercised subsystems in the repository.

---

### 4) Email protection and email gateway
**Status:** Implemented APIs with operational local logic

- Email protection service: `backend/email_protection.py`
  - SPF/DKIM/DMARC checks
  - phishing/URL/attachment/DLP analysis
  - quarantine and protected user management APIs
- Router: `backend/routers/email_protection.py` (`/api/email-protection/*`)
- Gateway service: `backend/email_gateway.py`
- Router: `backend/routers/email_gateway.py` (`/api/email-gateway/*`)
  - processing endpoint
  - quarantine management
  - policy + block/allow list operations

**Reality note:** The framework and scoring logic are real. Production SMTP relay operations still require environment-specific integration and deployment setup.

---

### 5) Mobile security and MDM connectors
**Status:** Implemented with important integration caveats

- Mobile security service/router:
  - `backend/mobile_security.py`
  - `backend/routers/mobile_security.py` (`/api/mobile-security/*`)
- MDM connectors/router:
  - `backend/mdm_connectors.py`
  - `backend/routers/mdm_connectors.py` (`/api/mdm/*`)

**Reality note (critical):**
- `MDMPlatform` enum includes `workspace_one` and `google_workspace`, but connector manager instantiation currently implements Intune and JAMF branches while unsupported branches warn and return failure.
- Intune/JAMF code paths include mock fallback behavior (e.g., mock token/response when dependencies are unavailable).
- Correct summary: strong connector framework + partial live-provider depth unless full credentials/dependencies are present.

---

### 6) CSPM
**Status:** Implemented and authenticated

- Router: `backend/routers/cspm.py` (`/api/v1/cspm/*`)
- `POST /scan` requires authenticated user (`Depends(get_current_user)`)
- Includes provider config management, findings/resource/compliance APIs, and dashboard/stat endpoints

**Reality note:** When no providers are configured, scan flow can seed/return demo data for UX continuity. This should be described explicitly as a demo usability path, not live cloud telemetry.

---

### 7) Local unified agent sidecar API
**Status:** Present, optional, non-authoritative

- File: `unified_agent/server_api.py`
- Provides a local FastAPI endpoint set with in-memory stores and proxy behavior to backend URL

**Reality note:** Useful for local workflows and gateway behavior, but this is not the canonical persisted control plane used by the main backend stack.

---

## Corrected interpretation of "what works"

### Materially real right now
- Large-scale API and router wiring across domains
- JWT/role-based auth and hardened secret handling
- Unified agent registration/heartbeat/command/monitor APIs
- Email/mobile/CSPM/identity operational route surfaces
- Workspace-driven frontend architecture aligned with backend route consolidation

### Real but conditional
- Live cloud posture scans (depends on configured providers/credentials)
- Live MDM synchronization depth (depends on connector implementation + real credentials + runtime dependencies)
- Production-grade SMTP relay deployment path (environment and transport configuration dependent)

### Requires caution in external claims
- "All integrations fully live out-of-the-box"
- "Uniform enterprise maturity across every domain"
- Exact architecture counts copied from older docs without recalculation

---

## Final reality statement

Metatron is a high-breadth security platform with real, code-backed implementations across endpoint control, response workflows, identity/auth, CSPM, email, and mobile domains. The strongest current truth is architectural scope and operational API depth. The main maturity limiter is uneven production integration depth across optional/external dependencies, not absence of platform capability scaffolding.
