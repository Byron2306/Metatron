# Metatron / Seraph AI Defense Platform

Enterprise security platform with unified endpoint, cloud, identity, email, mobile, and governance control planes.

This README is a code-accurate baseline aligned to current backend/frontend/runtime behavior.

---

## What This Repository Implements

### Core backend stack
- FastAPI application with modular router registration in `backend/server.py`
- MongoDB-backed persistence (`motor`) with optional mock DB path for tests/dev
- JWT auth + RBAC dependencies in `backend/routers/dependencies.py`
- Governance queue/approval/execution services for high-impact actions

### Core frontend stack
- React + React Router application (`frontend/src/App.js`)
- Workspace-oriented navigation (`frontend/src/components/Layout.jsx`)
- Dedicated workspaces for command, investigation, detection engineering, email security, and endpoint mobility

### Runtime/deployment stack
- Docker Compose includes backend, frontend, MongoDB, Redis, Celery, Elasticsearch/Kibana, Ollama, security tooling (Falco/Suricata/Zeek/Trivy), Cuckoo, WireGuard, and Nginx.
- Service definitions are in `docker-compose.yml`.

---

## Key Platform Domains (Current State)

| Domain | State | Notes |
|---|---|---|
| Unified Agent | Implemented | Registration, heartbeat, command routing, telemetry ingestion, EDM endpoints |
| Email Protection | Implemented | SPF/DKIM/DMARC, phishing/link/attachment checks, impersonation, DLP |
| Email Gateway | Implemented | Inline gateway processing, quarantine, block/allow list, policy endpoints |
| Mobile Security | Implemented | Device lifecycle, app analysis, compliance, network threat checks |
| MDM Connectors | Partially implemented | Intune + JAMF concrete connectors; Workspace One/Google Workspace not yet concrete |
| CSPM | Implemented | Authenticated scan initiation (`/api/v1/cspm/scan`) and persisted scan workflows |
| Governance / Triune flow | Implemented | Outbound gate + decision authority + executor + governed dispatch |
| Zero Trust | Implemented/partial | Trust scoring, policy evaluation, access logs, block flow |
| Browser Isolation | Partial | URL and content controls; full remote browser isolation still limited |

---

## Important Reality Notes

1. **MDM support is currently 2 concrete platforms, not 4.**  
   The service implements `IntuneConnector` and `JAMFConnector` in `backend/mdm_connectors.py`.  
   `WORKSPACE_ONE` and `GOOGLE_WORKSPACE` currently exist as declared platform identifiers/UI metadata, not full connector classes.

2. **CSPM scan endpoint is authenticated.**  
   `backend/routers/cspm.py` uses `Depends(get_current_user)` on `/scan`.

3. **Security startup controls are stricter in production/strict mode.**  
   - JWT secret requirements: `backend/routers/dependencies.py`
   - CORS origin validation: `backend/server.py`

4. **High-impact operations are governance-gated.**  
   `backend/services/outbound_gate.py` enforces triune queueing for mandatory high-impact action types.

---

## Repository Structure (High-Level)

```text
backend/
  server.py                    # FastAPI app bootstrap and router wiring
  routers/                     # API routers by domain
  services/                    # Governance, identity, cognition, outbound control, etc.
  *.py                         # Domain engines (email, mobile, cspm, zero_trust, ...)

frontend/
  src/App.js                   # Route map and protected routes
  src/components/Layout.jsx    # Sidebar/navigation structure
  src/pages/*                  # Workspace and domain pages

unified_agent/
  core/agent.py               # Endpoint monitor/runtime logic

memory/
  *.md                        # Strategy/reality/evaluation docs (updated)
```

---

## Quick Start (Docker Compose)

```bash
docker compose up -d
```

Recommended follow-up checks:

```bash
python3 smoke_test.py
```

If running frontend/backend locally outside compose, use their respective dependency/install scripts in repository workflows.

---

## Authentication and Roles

- User auth is JWT-based.
- Permission gating is role/permission-driven through dependency helpers.
- Example protected router paths use:
  - `Depends(get_current_user)` for authenticated access
  - `Depends(check_permission("write"))` or `Depends(check_permission("admin"))` for privileged actions

---

## Governance Model (Operational)

High-impact actions are routed through:

1. `OutboundGateService` queueing (`triune_outbound_queue`, `triune_decisions`)
2. `GovernanceDecisionAuthority` approval/denial state transitions
3. `GovernanceExecutorService` execution of approved decisions
4. `GovernedDispatchService` for command/tool dispatch requiring governance context

This model is used for command execution, response actions, quarantine actions, and other sensitive operations.

---

## Frontend Workspace Map

Primary workspace routes include:
- `/command`
- `/investigation`
- `/ai-activity`
- `/response-operations`
- `/detection-engineering`
- `/email-security`
- `/endpoint-mobility`
- `/unified-agent`
- `/cspm`
- `/zero-trust`

See `frontend/src/App.js` and `frontend/src/components/Layout.jsx` for current route and nav truth.

---

## Current Gaps / Next Engineering Priorities

1. Implement Workspace One and Google Workspace MDM connector classes.
2. Add stronger connector contract tests to prevent metadata-vs-runtime drift.
3. Continue governance denial-path and reliability regression expansion.
4. Advance browser isolation to full remote isolation modes where required.
5. Harden production integration guides for SMTP relay, cloud creds, and MDM credentials.

---

## Documentation Alignment

Major reality and strategy documents were refreshed to align with current code:

- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/SERAPH_BOARD_BRIEF_2026.md`
- `memory/SERAPH_IMPLEMENTATION_ROADMAP_2026.md`
- `memory/SERAPH_COMPETITIVE_WHITEPAPER_2026.md`

Use these files as the current baseline for planning and external/internal claims.
