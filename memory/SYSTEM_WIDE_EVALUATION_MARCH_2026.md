# Metatron / Seraph System-Wide Evaluation (Code-State Rebaseline)

**Last Updated:** 2026-04-14  
**Scope:** Current repository behavior (backend API, unified agent, frontend wiring, runtime topology)  
**Method:** Code-path verification (not roadmap scoring)

---

## Executive Summary

The platform is a broad, integrated security stack with active logic in endpoint telemetry, response orchestration, identity/CSPM workflows, email/mobile surfaces, and governance-gated operations.  

Compared to older March narratives, the biggest correction is that the system should be described as **implemented-by-domain with mixed operational prerequisites**, not as an abstract maturity scorecard. Most domains have concrete routers and service logic; the limiting factors are production credentials/integrations, consistency across legacy paths, and assurance depth.

---

## 1) Verified Current Architecture

### Backend application composition

- Main app: `backend/server.py`
- Routers are wired with `app.include_router(...)` calls in one composition layer.
- `server.py` currently includes **65 router registrations** (some are compatibility aliases or duplicate-prefix registrations).
- Dedicated prefixes include:
  - `/api/*` (majority of routes)
  - `/api/v1/cspm/*`
  - `/api/v1/identity/*`
  - websocket endpoints at `/ws/threats` and `/ws/agent/{agent_id}`

### Frontend composition

- Main router app: `frontend/src/App.js`
- Uses `react-router-dom` with authenticated route wrapping via `ProtectedRoute`.
- The app routes include direct pages and redirect-style workspace routes (for command, investigation, response operations, email security, endpoint mobility, etc.).
- Current frontend architecture is **workspace/tab-oriented**, not one-page-per-capability.

### Runtime topology

- Compose file: `docker-compose.yml`
- Includes database + API + UI + search/observability + background jobs:
  - MongoDB, Redis
  - Backend, Frontend
  - Celery worker, Celery beat
  - Elasticsearch, Kibana
  - Ollama (+ optional bootstrap pull)
  - Trivy, Falco, Suricata, WireGuard
  - Additional helper containers (e.g., volatility, zeek in compose sections)

---

## 2) Security and Access Controls (Verified)

### JWT and auth hardening behavior

From `backend/routers/dependencies.py`:

- `JWT_SECRET` is resolved at startup via `_resolve_jwt_secret()`.
- In production/strict mode:
  - missing JWT secret => hard failure
  - weak secret (<32 chars or known weak defaults) => hard failure
- Non-prod fallback uses ephemeral process-local JWT secret with warning.

### Remote access restrictions

From `get_current_user(...)`:

- Remote requests are constrained by `REMOTE_ADMIN_ONLY` (default true behavior).
- Non-local requests require:
  - explicit allowlist in `REMOTE_ADMIN_EMAILS`, or
  - user role `admin`.

### CORS behavior

From `backend/server.py`:

- CORS origins come from `CORS_ORIGINS`.
- In production/strict mode, wildcard is explicitly rejected.
- Credentials are disabled when wildcard would otherwise be present.

### Machine token support

Dependency helpers provide:

- required machine token dependency (`require_machine_token`)
- optional machine token (`optional_machine_token`)
- websocket machine token verification (`verify_websocket_machine_token`)

These are actively used in several ingest/control paths (advanced routes, websocket agent channel, identity ingest).

---

## 3) Major Domain State (Current Logic)

## 3.1 Unified Agent + Control Plane

### Backend

- Router: `backend/routers/unified_agent.py`
- Supports registration, heartbeat, telemetry ingestion, command/control, rollout/EDM operations, and world-state projection.
- Includes tamper-evident audit recording hooks and world event emission.

### Endpoint agent

- Core: `unified_agent/core/agent.py`
- Unified monitor registration currently instantiates a broad set of monitors (conditionally and platform-specifically).
- The monitor map in active initialization includes at least:
  - `process`, `network`, `registry`, `process_tree`, `lolbin`, `code_signing`, `dns`
  - `memory`, `whitelist`, `dlp`, `vulnerability`, `yara`, optional `amsi`
  - `ransomware`, `rootkit`, `kernel_security`, `self_protection`, `identity`
  - `auto_throttle`, `firewall`, optional `webview2`
  - `cli_telemetry`, `hidden_file`, `alias_rename`, `priv_escalation`
  - `email_protection`, `mobile_security`

## 3.2 Email Protection + Email Gateway

### Email protection

- Service: `backend/email_protection.py`
- Router: `backend/routers/email_protection.py`
- Provides analysis pipeline for sender/authentication/content/URL/attachment/DLP checks, quarantine workflows, and list management.

### Email gateway

- Service: `backend/email_gateway.py` (`SMTPGateway`)
- Router: `backend/routers/email_gateway.py` (**12 route handlers**)
- Supports API-driven message processing, quarantine release/delete, blocklist/allowlist ops, policy updates, and stats.

Practical note: gateway framework is implemented; production SMTP relay operations still depend on environment-specific server integration and credentials.

## 3.3 Mobile Security + MDM Connectors

### Mobile security

- Service: `backend/mobile_security.py`
- Router: `backend/routers/mobile_security.py`
- Supports device registration/status/compliance/threat lifecycle/app analysis/policy dashboard flows.

### MDM connectors

- Service: `backend/mdm_connectors.py`
- Router: `backend/routers/mdm_connectors.py` (**18 route handlers**)
- Supports connector management, connect/disconnect, sync operations, device actions, policy/platform views.
- Connector classes exist for Intune, JAMF, Workspace ONE, and Google Workspace.

Practical note: production value depends on real platform credential configuration.

## 3.4 CSPM and Identity

### CSPM

- Router prefix: `/api/v1/cspm`
- Scan start currently requires authenticated user.
- Provider writes use permission checks and outbound-governance gating.
- Includes demo seed path (`/demo-seed`) and dashboard/export/check-management APIs.
- State includes DB-backed scan/finding collections plus in-memory coordination structures.

### Identity

- Router prefix: `/api/v1/identity`
- Supports incident lifecycle, provider event ingestion, and response actions.
- Includes machine token ingest gate for identity provider event pathways.
- Uses transition logs and state versioning semantics for incident status transitions.

---

## 4) Governance and Execution Paths

Governance execution service (`backend/services/governance_executor.py`) is active in startup and handles approved queue decisions into operational actions.

Dispatch coverage includes:

- agent/swarm command types
- response operations (block/unblock IP)
- quarantine operations (restore/delete/agent quarantine)
- VPN lifecycle and peer operations
- cross-sector hardening type operations

This means governance is not only analytical; it is wired to execution pathways.

---

## 5) Startup/Background Service Behavior

From `backend/server.py` startup:

- Admin bootstrap (env-driven) if no admin exists
- Starts CCE worker
- Starts network discovery service
- Starts deployment service
- Initializes AATL and AATR components
- Wires Falco callback into persisted alerts when available
- Triggers integrations scheduler
- Triggers governance executor loop

Shutdown path includes stopping CCE, network discovery, deployment service, and governance executor.

---

## 6) Key Corrections vs Older Documentation

1. **Do not rely on static maturity scores as source of truth.**  
   Current code contains concrete implementations across major domains; readiness varies by environment dependencies and integration credentials.

2. **Route and feature counts in older docs are stale.**  
   Current router registrations and endpoint surfaces differ materially from older fixed numbers.

3. **Security hardening claims should be stated as concrete behavior.**  
   JWT/CORS/remote admin gating and machine token gates are codified and should be documented as active controls.

4. **Frontend is now workspace-centric.**  
   Several former standalone pages are represented as routed workspace tabs via redirects.

5. **Governance is execution-linked.**  
   Approved decisions can directly flow into command/response/VPN/quarantine operations.

---

## 7) Current Risk/Constraint Register

1. **Integration prerequisites**  
   Production SMTP and production MDM credentials are external dependencies for full real-world coverage.

2. **Mixed in-memory and DB state**  
   Some services still keep operational state in memory alongside DB-backed durability, creating potential restart/scale semantics complexity.

3. **Contract consistency pressure**  
   High route volume and compatibility aliases increase drift risk without strict contract testing gates.

4. **Legacy compatibility wiring complexity**  
   Duplicate/compat prefixes and optional imports improve UX compatibility but increase maintenance surface.

---

## 8) Actionable Documentation Policy Going Forward

For future memory review updates:

- Document **code-backed behavior** first (file + function + route shape).
- Separate **implemented logic** from **environment-dependent runtime outcomes**.
- Avoid fixed score inflation; prefer deterministic status labels:
  - Implemented in code
  - Implemented, environment-dependent
  - Partial (limited depth)
  - Planned/not implemented

---

## Final Evaluation Statement

The current repository represents a broad, operationally capable security platform with substantial implemented logic across endpoint, email, mobile, identity, CSPM, and governance-driven response domains.  
Its primary limitations are no longer raw feature absence; they are production integration dependencies, consistency enforcement, and hardening/verification uniformity across a very large and rapidly evolving surface area.
