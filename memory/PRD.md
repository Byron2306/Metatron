# Seraph AI Defense System - Product Requirements Summary

**Updated:** 2026-05-01
**Scope:** Current product requirements aligned to the repository implementation.

## 1) Product overview

Metatron/Seraph is a governed adaptive cyber-defense platform. It combines:

- a central FastAPI backend in `backend/server.py`;
- a React SOC dashboard in `frontend/src`;
- a cross-platform unified endpoint agent in `unified_agent/core/agent.py`;
- local agent APIs/UIs, deployment helpers, integrations, and validation scripts.

The product is designed for endpoint/XDR operations, AI-agentic threat detection, response orchestration, email/mobile protection, cloud posture management, deception, governance, and optional SIEM/security-tool integrations.

## 2) Current product goals

1. Provide a unified SOC dashboard for threat, alert, investigation, response, email, mobile, endpoint, cloud, and governance workflows.
2. Operate a canonical agent control plane under `/api/unified/*`.
3. Support endpoint telemetry, command dispatch, installer delivery, EDM governance, and local agent operation.
4. Keep optional services explicit and degradable rather than blocking core SOC use.
5. Preserve AI-native and governance differentiation while improving production assurance.

## 3) User groups

| User | Needs |
| --- | --- |
| SOC analyst | View alerts/threats, investigate timelines/correlation, use hunting and reports. |
| Security engineer | Configure detections, Sigma/Zeek/osquery/atomic validation, integrations, and response logic. |
| Endpoint operator | Deploy agents, inspect fleet status, issue commands, manage updates and telemetry. |
| Cloud/security architect | Review CSPM, identity, zero-trust, attack paths, kernel/secure boot, and governance state. |
| Email/mobile administrator | Manage email protection/gateway, mobile devices, MDM connectors, and policy actions. |

## 4) Primary functional requirements

### 4.1 Backend API and data plane

- Mount primary product APIs under `/api`.
- Support selected `/api/v1` routers where routers carry native versioned prefixes.
- Use MongoDB as the primary state store.
- Configure services and routers through `backend/server.py`.
- Provide health/readiness endpoints for compose and validation.
- Start background/workflow services where configured.

### 4.2 Frontend dashboard

- Use protected React routes through `frontend/src/App.js`.
- Default the root route to `/command`.
- Use consolidated workspace routes for major operator workflows:
  - `/command`
  - `/investigation`
  - `/detection-engineering`
  - `/response-operations`
  - `/email-security`
  - `/endpoint-mobility`
  - `/ai-activity`
- Redirect legacy routes such as `/agents`, `/swarm`, `/agent-commands*`, `/email-gateway`, `/email-protection`, `/mobile-security`, and `/mdm` to canonical workspace pages.
- Resolve API roots with `frontend/src/lib/api.js`: configured `REACT_APP_BACKEND_URL/api` or same-origin `/api`.

### 4.3 Unified agent and fleet management

- Provide agent registration, heartbeat, telemetry, commands, alerts, dashboard stats, deployment records, and WebSocket support in `backend/routers/unified_agent.py`.
- Serve agent packages/installers through backend routes.
- Maintain monitor summary compatibility using the canonical monitor key list in the unified-agent router.
- Support local agent runtime features through `unified_agent/core/agent.py`.
- Support local operator UI/API surfaces through `unified_agent/server_api.py` and `unified_agent/ui/`.

### 4.4 EDM and DLP

- Manage EDM datasets, versioning, rollout, rollback, readiness, signatures, and telemetry through `/api/unified/*`.
- Run endpoint-side EDM matching and DLP telemetry in the unified agent.
- Provide enhanced DLP logic in `backend/enhanced_dlp.py`.

### 4.5 Email and mobile

- Provide email protection APIs and backend service logic in `backend/routers/email_protection.py` and `backend/email_protection.py`.
- Provide gateway processing, quarantine, blocklist/allowlist, policy, and stats APIs in `backend/routers/email_gateway.py` and `backend/email_gateway.py`.
- Provide mobile security lifecycle, risk, app, compliance, network, and device APIs in `backend/mobile_security.py` and `backend/routers/mobile_security.py`.
- Provide MDM connector management, sync, devices, policies, actions, and platform metadata in `backend/mdm_connectors.py` and `backend/routers/mdm_connectors.py`.

### 4.6 AI-agentic defense and governance

- Detect and classify machine-paced/agentic behavior through AATL/AATR and cognition services.
- Route high-impact actions through governance, policy, token, tool gateway, and audit/telemetry services where available.
- Preserve Triune intelligence surfaces for Metatron, Michael, and Loki.
- Avoid treating optional AI/model integrations as required for core operation.

### 4.7 Cloud, network, and advanced security

- Provide CSPM across AWS/Azure/GCP scanners and authenticated router surfaces.
- Support VPN, browser isolation, deception, honeypots/honey tokens, container security, osquery, Zeek, Sigma, MITRE, atomic validation, sandbox, Kibana, and advanced AI/security APIs through existing backend modules.
- Preserve explicit degraded mode for optional services.

## 5) Non-functional requirements

| Requirement | Product expectation |
| --- | --- |
| Security | Authenticated APIs for sensitive operations, explicit production CORS, machine-token checks on machine paths, and permission checks on write/admin actions. |
| Operability | Docker Compose core stack should bring up MongoDB, Redis, backend, and frontend with backend health on port 8001. |
| Degraded mode | Optional services should expose status and partial functionality instead of failing core workflows. |
| Contract integrity | Frontend, backend, scripts, and docs should remain aligned to canonical route contracts. |
| Auditability | High-risk actions should produce traceable evidence through audit and telemetry-chain paths. |
| Testability | Backend, frontend, unified-agent, smoke, and E2E validation paths should cover critical contracts. |

## 6) Current acceptance criteria

Core acceptance:

1. `mongodb`, `redis`, `backend`, and `frontend` start in compose.
2. `GET http://localhost:8001/api/health` succeeds.
3. Frontend loads at `http://localhost:3000`.
4. Authentication and protected layout function.
5. Command, investigation, response, unified-agent, email, endpoint-mobility, CSPM, and settings workflows load without fatal API-base errors.
6. Optional integrations report unavailable/degraded status without blocking unrelated workflows.

Documentation acceptance:

1. Root README describes current backend/frontend/agent/runtime structure.
2. `memory/` review docs summarize current code evidence.
3. README and memory docs agree on ports, route roots, canonical agent page, and optional-service semantics.

## 7) Current limitations and risks

- `backend/server.py` remains a dense composition point.
- There are many router/page contracts, making drift likely without generated inventories or CI contract checks.
- Governance-sensitive state and optional integration status need stronger durability and assurance.
- Browser isolation exists but is not equivalent to a fully hardened remote browser isolation product.
- MDM and email gateway frameworks are implemented, but live production value depends on real credentials, mail routing, and environment-specific integration setup.

## 8) Product positioning

The product should be positioned as a governed adaptive defense platform: broader and more customizable than a single EDR module, but still requiring disciplined hardening, verification, and integration governance before claims of incumbent-grade enterprise parity.
