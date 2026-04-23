# Metatron / Seraph AI Defense Platform

Code-evidence aligned overview (updated 2026-04-23).

## What this repository is

Metatron/Seraph is a large modular security platform with:
- A FastAPI backend (`backend/server.py`) composed from many router modules.
- A React frontend (`frontend/src`) organized around operator workspaces.
- A cross-platform unified endpoint agent (`unified_agent/core/agent.py`) with broad monitor coverage.
- Governance and control-plane services for policy, tokenized actions, and triune/outbound gating.

Current codebase scale indicators:
- **62** backend router modules in `backend/routers`.
- **697** route handlers across those router files.
- **65** router registrations in `backend/server.py`.
- **69** frontend page components in `frontend/src/pages`.

---

## High-level architecture

### Backend API layer
- Entry: `backend/server.py`.
- Router composition includes classic SOC surfaces (alerts, threats, timeline, reports), endpoint control, governance, CSPM, enterprise controls, email/mobile/MDM, deception, and advanced services.
- Most routes are mounted under `/api`; several modules use explicit versioned prefixes (for example `/api/v1/*` paths in CSPM and some governance-aligned modules).

### Frontend layer
- Entry: `frontend/src/App.js`.
- Route model uses protected layout and workspace-centric navigation (`/command`, `/investigation`, `/response-operations`, `/detection-engineering`, `/email-security`, `/endpoint-mobility`, etc.).
- Legacy paths are preserved with redirects to workspace tabs to reduce route breakage.

### Agent layer
- Entry: `unified_agent/core/agent.py`.
- Includes broad local monitors and telemetry/reporting loops.
- Talks to backend unified-agent endpoints for registration, heartbeat, command polling/result reporting, EDM dataset sync, and monitor telemetry upload.

### Governance/control layer
- Outbound action gating: `backend/services/outbound_gate.py`.
- Command dispatch bridge: `backend/services/governed_dispatch.py`.
- Approved-decision execution loop: `backend/services/governance_executor.py`.
- Decision authority transitions: `backend/services/governance_authority.py`.
- Policy/identity/token/tool/telemetry primitives:
  - `backend/services/policy_engine.py`
  - `backend/services/identity.py`
  - `backend/services/token_broker.py`
  - `backend/services/tool_gateway.py`
  - `backend/services/telemetry_chain.py`

---

## Core implemented capability areas

This section reflects active code paths, not historical roadmap claims.

### 1) Unified endpoint control plane
- Router: `backend/routers/unified_agent.py` (largest backend router).
- Key capabilities:
  - Agent enrollment and authenticated heartbeat.
  - Command queueing and delivery contract (authority + decision context).
  - Command result ingestion with boundary/outcome handling.
  - Deployment tracking and dashboard/status APIs.
  - Monitor telemetry ingest and fleet posture reporting.
  - Agent package download and installer script endpoints.

### 2) Endpoint monitor depth (agent)
- Agent core: `unified_agent/core/agent.py`.
- Monitor classes include process/network/registry lineage plus deeper monitors for:
  - DLP + EDM
  - Rootkit + kernel security
  - Email protection
  - Mobile security
  - Firewall, ransomware, privilege escalation, CLI telemetry, and more.
- Unified router’s monitor summary keys are aligned to 24 monitor telemetry channels.

### 3) Data protection (DLP + EDM governance)
- Agent side:
  - EDM matching and telemetry loop-back in `DLPMonitor`.
  - Signed EDM update and reload command handling.
- Backend side (`backend/routers/unified_agent.py`):
  - EDM dataset versioning and publish/rollback APIs.
  - Rollout lifecycle and readiness/advance/rollback flows.
  - EDM telemetry summary and rollout inspection endpoints.

### 4) Email security
- Email Protection:
  - Service: `backend/email_protection.py`
  - API: `backend/routers/email_protection.py`
  - Includes analyze/auth-check/url/attachment/DLP/quarantine/protected-user controls.
- Email Gateway:
  - Service: `backend/email_gateway.py`
  - API: `backend/routers/email_gateway.py`
  - Includes process/policy/quarantine/blocklist/allowlist/stats flows.

### 5) Mobile security + MDM
- Mobile security:
  - Service: `backend/mobile_security.py`
  - API: `backend/routers/mobile_security.py`
  - Device registration/status/compliance/threat/app-analysis/dashboard paths.
- MDM connectors:
  - Service: `backend/mdm_connectors.py`
  - API: `backend/routers/mdm_connectors.py`
  - Connector lifecycle, sync, and device actions (lock/wipe/retire/sync).

### 6) Cloud security posture (CSPM)
- Router: `backend/routers/cspm.py`.
- Includes:
  - Provider configuration and listing/removal.
  - Scan creation and scan history/detail retrieval.
  - Findings list/detail/status transition with durable state semantics.
  - Compliance report, checks toggle/list, export, dashboard, and stats.
- Uses explicit state transition/version handling for scans/findings.

### 7) Enterprise governance substrate
- Identity attestation/trust-state logic: `backend/services/identity.py`.
- Policy decision + approval tiers/rate controls: `backend/services/policy_engine.py`.
- Scoped capability tokens and secret handling: `backend/services/token_broker.py`.
- Tool execution gating: `backend/services/tool_gateway.py`.
- Tamper-evident telemetry/audit chain: `backend/services/telemetry_chain.py`.

---

## Runtime/deployment model

Primary orchestration file: `docker-compose.yml`.

### Core services
- `mongodb`
- `redis`
- `backend`
- `frontend`

### Included optional/adjacent services
- `elasticsearch`, `kibana`
- `ollama` (+ optional model pull bootstrap service)
- `wireguard`
- security-profile services: `trivy`, `falco`, `suricata`, `zeek`, `volatility`
- sandbox-profile services: `cuckoo`, `cuckoo-web`, `cuckoo-mongo`
- `nginx`

Many features run with graceful degradation if optional dependencies are unavailable; however behavior quality and depth depend on correct service/runtime configuration.

---

## Quick start (local)

### 1) Clone and configure
```bash
git clone <repo-url>
cd <repo-dir>
cp .env.example .env
```

### 2) Start stack
```bash
docker compose up -d
```

### 3) Access services
- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8001/api/health`

### 4) Optional profiles
```bash
docker compose --profile security up -d
docker compose --profile sandbox up -d
```

---

## Security model summary

### Authentication and authorization
- JWT-based auth in router dependencies.
- Role/permission checks via `check_permission(...)`.
- Optional remote-admin-only gating for non-local requests.
- Machine-token dependencies for agent and websocket machine paths.

### Governance and high-impact controls
- High-impact action types are normalized and queued via outbound gate.
- Triune decision records and outbound queue entries are created before execution release.
- Governance executor processes approved decisions and writes execution outcome back to authoritative collections.

### Audit/eventing
- World event emission is used across routers/services for canonical event flow.
- Tamper-evident telemetry service maintains hash-chain style audit/event records.

---

## Repository layout

```text
backend/
  server.py
  routers/
  services/
  *.py (security engines and domain services)

frontend/
  src/
    App.js
    pages/
    components/

unified_agent/
  core/
    agent.py
  ui/
  integrations/

memory/
  *.md (analysis and review docs refreshed to match current code)
```

---

## Testing and validation (recommended workflow)

Because the platform is large and integration-heavy, validate in layers:

1. **API health and auth**  
   - Confirm backend and DB reachability.
   - Validate auth setup/login and token-protected routes.

2. **Unified agent loop**  
   - Register agent, send heartbeat, poll commands, report results.

3. **Domain slices**  
   - Email protection/gateway.
   - Mobile/MDM.
   - CSPM.
   - Governance decision queue and execution.

4. **Optional integrations**  
   - Enable only required profiles and confirm degraded-mode behavior where integrations are intentionally absent.

---

## Current engineering reality (important)

This repository contains substantial implemented logic across domains, but also has known structural realities:
- `backend/server.py` is still a dense composition point.
- Integration depth varies by runtime credentials/services.
- Some capability classes are strong in framework and API design but depend on operational discipline and environment hardening for production consistency.

The memory documents in `memory/` were updated alongside this README to reflect that current code-evidence perspective.

