# Seraph AI Defense System - Product Requirements Document

## Current Code-Logic Snapshot (updated 2026-04-28)

Backend API is FastAPI version `3.0.0` in `backend/server.py`, served on `8001` with health at `/api/health`. The repository has 61 backend router modules plus package init, 32 backend service modules plus package init, 68 JSX frontend pages plus `GraphWorld.tsx`, 68 `<Route` occurrences in `frontend/src/App.js`, unified agent version `2.0.0`, and 63 backend test files. The authenticated frontend hub is `/command`. Root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack health test.


## Product Overview

Seraph AI Defense System is an AI-native security platform for SOC operations, endpoint-agent control, governed response, deception, identity, cloud posture, email, mobile, MDM, and optional security-tool integrations. The product is currently implemented as a FastAPI backend, React/Craco frontend, MongoDB/Redis data layer, and unified endpoint-agent subsystem.

## Current Product Surface

| Product area | Current implementation | Notes |
|---|---|---|
| Command console | `/command` workspace | Authenticated landing route; dashboard/alerts/threats redirect here. |
| Investigation | `/investigation` workspace | Threat intel, correlation, and attack-path workflows. |
| Response operations | `/response-operations` workspace | Quarantine, response automation, SOAR, and EDR workflows. |
| Detection engineering | `/detection-engineering` workspace | Sigma, Atomic validation, MITRE, Zeek, and osquery-adjacent workflows. |
| Unified agent | `/unified-agent`, `/api/unified/...`, `unified_agent/core/agent.py` | Agent version 2.0.0 with central and local control surfaces. |
| Email security | `/email-security` workspace plus email protection/gateway routers | Production gateway value requires SMTP relay configuration. |
| Endpoint mobility | `/endpoint-mobility` workspace plus mobile/MDM routers | Live MDM value requires platform credentials and sync/webhook setup. |
| Identity and zero trust | identity and zero-trust route/service families | Production depth depends on configured identity sources and policies. |
| CSPM/cloud posture | CSPM router/engine | Requires cloud credentials and scoped permissions. |
| Deception/ransomware | deception, honeypot, honey-token, ransomware modules/routes | Code-backed capability with compatibility mounts for deception routes. |
| AI/Triune/world model | Metatron/Michael/Loki, triune orchestrator, world model services | Model-backed quality depends on configured model services. |
| Integrations | integrations router and `unified_agent/integrations/` runners | Tool execution depends on local services, binaries, privileges, and credentials. |

## Functional Requirements

### Core platform

1. Backend exposes health at `GET /api/health` on port `8001`.
2. Frontend loads on port `3000` in local development and routes authenticated users to `/command`.
3. MongoDB persists platform state using database `seraph_ai_defense` by default.
4. Redis supports queue/cache/Celery-backed workflows where enabled.
5. Optional integrations degrade explicitly without blocking core SOC operation.

### Operator experience

1. Operators can navigate primary workspaces from the React app.
2. Legacy paths redirect into current workspace tabs rather than breaking.
3. Workspaces should show configured, degraded, unavailable, and error states clearly.
4. Feature pages should avoid silent success when required external credentials or services are missing.

### Agent control

1. Agents can register, heartbeat, receive commands/configuration, and return telemetry through `/api/unified/...`.
2. Agent WebSocket connections use machine-token verification.
3. Local agent dashboard and helper API remain separate from the central backend.

### Security and governance

1. Production mode requires configured secrets and integration keys.
2. CORS origins must be explicit in strict/production mode.
3. High-risk response/governance actions should produce principal, policy, trace, and outcome evidence.
4. Denial paths, replay controls, and audit-chain behavior should be covered by regression tests.

## Non-Functional Requirements

- Source-derived route and count documentation should be used for release notes.
- Runtime validation should use `/api/health`, targeted pytest suites, and feature-specific checks.
- Optional-service failures should be deterministic and visible to operators.
- Production claims for SMTP, MDM, CSPM, AI, sandbox, SIEM, and kernel sensors require environment proof.
- README and memory docs should be updated whenever route hubs, ports, or validation flows change.

## Validation Requirements

Core validation commands:

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
python -m pytest -q backend/tests
python -m pytest -q unified_agent/tests/test_monitor_scan_regression.py
```

Frontend validation uses `yarn test` or `craco test` from `frontend/`.

## Product Reality Statement

Seraph is a feature-rich, code-backed adaptive security platform. Its product requirements should distinguish between implemented surfaces and production-enabled capability. External credentials, optional services, host privileges, and regression assurance are the gating factors for many advanced domains.
