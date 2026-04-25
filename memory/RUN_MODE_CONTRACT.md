# Metatron Run-Mode Contract (Source of Truth)

## 2026-04-25 Code Logic Refresh

The required runtime contract is unchanged, but the active code surface is broader than
the older March notes:

- `backend/server.py` is the composition authority for the central API. It mounts
  the `/api/*` router mesh, selected native `/api/v1/*` routers, WebSockets,
  world/agent ingest, governance, Triune, email, mobile, MDM, swarm, unified-agent,
  and advanced-service endpoints.
- The current frontend routing model is workspace-oriented. `/command`,
  `/world`, `/ai-activity`, `/response-operations`, `/investigation`,
  `/detection-engineering`, `/email-security`, and `/endpoint-mobility` are the
  primary operator workspaces. Legacy paths such as `/dashboard`, `/alerts`,
  `/threats`, `/agents`, `/soar`, `/swarm`, `/email-gateway`, and `/mdm` redirect
  into those workspaces.
- High-impact runtime actions should be considered governed when they pass through
  `OutboundGateService`, `triune_decisions`, governance approval APIs,
  `GovernanceExecutorService`, dispatch primitives, capability-token checks, and
  tamper/world-event audit linkage.
- `unified_agent/` is not a single surface: it includes the endpoint agent runtime,
  local Flask dashboard on port 5000, desktop core, integration client, and a
  standalone FastAPI agent server. The React product UI uses the central backend's
  `/api/unified/*` and `/api/swarm/*` routes.

## Goal
Define what is **required** vs **optional** so operators can run the platform predictably and understand why some dashboard features may be unavailable.

## 1) Required Core (must be up)
- `mongodb`
- `backend`
- `frontend`

If any of these are down, the dashboard is not considered healthy.

## 2) Default Optional Integrations (degraded mode if down)
- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`

Behavior contract:
- UI should remain usable when optional services are down.
- Related pages/features may show degraded status, warnings, or partial data.

## 3) Profile-Based Optional Integrations
These are intentionally profile-gated and not required for baseline operation.

### security profile
- `trivy`
- `falco`
- `suricata`

### sandbox profile
- `cuckoo`
- `cuckoo-web`

## 4) Runtime Launch Modes
### Minimal reliable mode
`docker compose up -d mongodb backend frontend`

### Recommended local full mode
`docker compose up -d mongodb backend frontend wireguard elasticsearch kibana ollama`

### Extended security mode
`docker compose --profile security up -d`

### Sandbox mode
`docker compose --profile sandbox up -d`

## 5) API Routing Contract
- Frontend should call backend via same-origin `/api/...` or a configured backend
  origin plus `/api/...`.
- In production behind reverse proxy, same-origin `/api` routing should be preferred.
- Most backend routers are mounted under `/api` in `backend/server.py`; selected
  routers keep native `/api/v1/...` prefixes and are included without an additional
  `/api` prefix.
- Some frontend files still use mixed API-base construction. Treat this as a
  contract-risk area and keep route/API compatibility under tests.

## 6) Health Validation Sequence
1. `docker compose ps`
2. `curl -fsS http://localhost:8000/health`
3. `curl -fsS http://localhost:3000` (or deployed frontend URL)
4. Validate central backend API health through `/api/health` when exposed directly
   on the backend port or through the reverse proxy.
5. If optional integrations are enabled, validate each dependent page from UI and API endpoints.

## 7) Known Wiring Risks (from latest static audit)
- Route/page counts in older memory docs use different definitions. Current
  `frontend/src/App.js` should be treated as authoritative: workspace pages are
  real routes, while many legacy routes are redirects.
- Email and MDM direct paths are compatibility redirects:
  - `/email-gateway` -> `/email-security?tab=gateway`
  - `/email-protection` -> `/email-security?tab=protection`
  - `/mobile-security` -> `/endpoint-mobility?tab=mobile`
  - `/mdm` -> `/endpoint-mobility?tab=mdm`
- Mixed API base strategies remain a monitoring risk (`/api` relative helper vs
  host-prefixed construction in some pages).
- Script/default URL drift across `localhost:8001`, `localhost:8002`, local agent
  port `5000`, and reverse-proxied deployments should be tested before release.

## 8) Acceptance Criteria for "Working"
- Core services up and healthy.
- Login works and main dashboard loads without fatal errors.
- At least one page each from: Threats, Alerts, Agents, Settings can load data successfully.
- Optional integration pages degrade gracefully if their service is not enabled.

## 9) Consolidated Reality Conditions (updated 2026-04-25)

These conditions align run-mode expectations with the critical evaluation and feature reality artifacts.

### 9.1 Must-pass operational contracts
- Swarm group/tag/device assignment flows should be available end-to-end.
- Threats/Alerts/Timeline/Zero-Trust pages should load and execute their core read paths.
- Threat response routes should remain functional even when optional providers (Twilio/OpenClaw) are unavailable.
- Governance approval and executor release flows should preserve queue-backed
  decisions, terminal status, audit linkage, and world-event feedback.
- Email security and endpoint mobility workspaces should load their tabbed
  experiences while legacy direct routes redirect correctly.

### 9.2 Known degraded/conditional contracts
- Unified deployment may be queued, simulated, or real depending on configured
  deployment plumbing and credentials; success states should distinguish verified
  execution from queued intent.
- WinRM auto-deployment is conditional on:
  - valid credentials (password-based auth),
  - `pywinrm` installed,
  - remote endpoint availability (port/protocol/security policy).
- OpenClaw integration is optional and should never block core SOC operation.
- Email gateway and MDM connector depth depends on production SMTP/MDM credentials
  and external provider availability.
- Ollama/LLM-assisted reasoning is optional; rule-based fallbacks should keep the
  platform usable when model services are unavailable.

### 9.3 Contract integrity risks to monitor
- Mixed frontend API base strategy (`REACT_APP_BACKEND_URL` hard dependency in some pages vs `/api` fallback in others).
- Script ecosystem endpoint drift (`/api/agent/*` legacy paths vs active `/api/swarm` and `/api/unified` contracts).
- Script/default URL drift across `localhost:8001`, `localhost:8002`, and legacy cloud defaults.
- Validation script mismatch risk (`/api/zero-trust/overview` probe not aligned to active router paths).
- Governance bypass risk if any new high-impact execution path writes commands
  directly instead of using outbound gate/executor release.
- Audit completeness risk if new mutating endpoints emit state changes without
  policy/decision/token/execution identifiers.

### 9.4 Updated "Working" interpretation
System is considered **working** when:
1. Core required services are healthy.
2. Core SOC workflows (threats, alerts, timeline, zero-trust read/evaluate) execute successfully.
3. Optional integrations fail gracefully with explicit status and no cascading core failure.
4. Deployment success states correspond to verified execution, not simulation-only completion.
5. High-impact actions preserve governed execution and audit traceability.

## 10) Acceptance Changelog (2026-03-04)

- Added writable runtime data-path fallback behavior for backend services to prevent startup failure in restricted environments.
- Aligned backend integration tests to current API contracts (response shapes, permissions, and agent-download artifact behavior).
- Removed test warning sources from VPN/browser integration tests (no non-`None` test returns).
- Final targeted acceptance subset result:
  - `backend/tests/test_audit_timeline_openclaw.py`
  - `backend/tests/test_unified_agent_hunting.py`
  - `backend/tests/test_vpn_zerotrust_browser.py`
  - `backend/tests/test_agent_download.py`
  - outcome: **94 passed, 5 skipped, 0 failed**
