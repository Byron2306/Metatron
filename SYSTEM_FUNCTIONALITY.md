# Seraph / Metatron System Functionality (Current Code Baseline)

**Last updated:** 2026-04-16  
**Source scope:** Backend routers/services, unified agent core, frontend route wiring, docker-compose topology

---

## 1) Platform Summary

Seraph/Metatron is a modular FastAPI + React security platform with:

- broad backend API segmentation (65 router includes),
- a cross-platform unified endpoint agent,
- domain workspaces for command/intelligence/response/platform operations,
- optional security and sandbox runtime services through Docker Compose profiles.

---

## 2) Backend Functionality

## 2.1 API Composition

Main app: `backend/server.py`

- FastAPI server with centralized wiring.
- Routers are mounted primarily under `/api`.
- Some routers are mounted with explicit `/api/v1/...` prefixes (for compatibility and domain-specific versioning).

Key validated route-domain sizes:

- `backend/routers/unified_agent.py`: 51 handlers
- `backend/routers/cspm.py`: 18 handlers
- `backend/routers/mobile_security.py`: 17 handlers
- `backend/routers/email_protection.py`: 17 handlers
- `backend/routers/mdm_connectors.py`: 18 handlers
- `backend/routers/email_gateway.py`: 12 handlers

## 2.2 Security and identity controls

Primary auth dependencies: `backend/routers/dependencies.py`

- JWT bearer auth and token creation
- role-based permissions (`admin`, `analyst`, `viewer`)
- production/strict JWT secret enforcement
- remote admin-only gate for non-local requests
- machine-token dependencies for service-to-service trust
- CORS origin strictness in server boot logic

Auth router: `backend/routers/auth.py`

- register/login/me routes
- one-time admin setup route with optional setup token
- user role management endpoints under `/users`

---

## 3) Security Domain Functionality

## 3.1 Unified Agent + EDM

Backend control plane: `backend/routers/unified_agent.py`

- agent registration and heartbeat
- command dispatch/management
- stats/alert APIs
- EDM dataset versioning and publish/rollback
- EDM rollout lifecycle and readiness endpoints

Endpoint implementation: `unified_agent/core/agent.py`

- monitor initialization for:
  - process/network
  - registry/process tree/LOLBin/code signing/DNS
  - memory/DLP/vulnerability/YARA
  - ransomware/rootkit/kernel/self-protection/identity
  - firewall/CLI telemetry/hidden-file/alias-rename/priv-escalation
  - email protection + mobile security

## 3.2 Email Security

Email Gateway:

- Service: `backend/email_gateway.py`
- Router: `backend/routers/email_gateway.py`
- Includes processing, quarantine, policy, blocklist/allowlist, and stats endpoints.

Email Protection:

- Service: `backend/email_protection.py`
- Router: `backend/routers/email_protection.py`
- Includes full email analysis, URL/attachment checks, SPF/DKIM/DMARC, DLP, and quarantine operations.

## 3.3 Endpoint Mobility

Mobile Security:

- Service: `backend/mobile_security.py`
- Router: `backend/routers/mobile_security.py`
- Includes device registration/lifecycle, compliance, threat handling, app analysis, and policy operations.

MDM Connectors:

- Service: `backend/mdm_connectors.py`
- Router: `backend/routers/mdm_connectors.py`
- Includes connector management, sync, device actions, and platform listing.
- Concrete connector classes currently implemented:
  - `IntuneConnector`
  - `JAMFConnector`
- Note: enum includes `workspace_one` and `google_workspace` platform values, but concrete classes for those are not present.

## 3.4 Cloud Security (CSPM)

Router: `backend/routers/cspm.py` (prefix `/api/v1/cspm`)

- provider configure/list/remove
- scan start/history/details
- findings and compliance reporting
- dashboard statistics
- governance gating (`OutboundGateService`, `requires_triune=True`) for high-impact actions
- authenticated scan start dependency
- demo-data fallback when no providers are configured

---

## 4) Frontend Functionality

Main routes: `frontend/src/App.js`

- Auth-protected root layout
- Workspace-centric route model:
  - `CommandWorkspacePage`
  - `AIActivityWorkspacePage`
  - `InvestigationWorkspacePage`
  - `ResponseOperationsPage`
  - `DetectionEngineeringWorkspacePage`
  - `EmailSecurityWorkspacePage`
  - `EndpointMobilityWorkspacePage`

Consolidated redirects:

- `/email-protection` -> `/email-security?tab=protection`
- `/email-gateway` -> `/email-security?tab=gateway`
- `/mobile-security` -> `/endpoint-mobility?tab=mobile`
- `/mdm` -> `/endpoint-mobility?tab=mdm`

Navigation: `frontend/src/components/Layout.jsx`

- sectioned navigation model (Command, Intelligence, Response, Platform, Engineering, Admin, More Tools)
- workspace entries aligned to backend domain organization

---

## 5) Runtime / Deployment Functionality

Deployment file: `docker-compose.yml`

Core services:

- `mongodb`, `redis`, `backend`, `frontend`
- `celery-worker`, `celery-beat`

Observability/analysis services:

- `elasticsearch`, `kibana`, `ollama`, `ollama-pull`

Security profile services:

- `trivy`, `falco`, `suricata`, `zeek`, `volatility`

Sandbox profile services:

- `cuckoo-mongo`, `cuckoo`, `cuckoo-web`

Additional:

- `wireguard`, `nginx`, `admin-bootstrap`

Profiles:

- `security`
- `sandbox`
- `bootstrap`

---

## 6) Current-State Caveats

1. Documentation has historically overstated some implemented depth (especially MDM platform coverage).
2. CSPM and other governance-heavy workflows include gating and demo fallbacks; operational behavior depends on environment and provider credentials.
3. Large API breadth requires ongoing contract and regression validation to avoid backend/frontend drift.

---

## 7) Practical Conclusion

The system is a feature-rich, modular security platform with substantial real implementation in endpoint, email, mobile, and cloud security domains.  
The main quality objective is now consistency: documentation fidelity, contract assurance, and production-operational hardening.

