# Feature Reality Report

Generated: 2026-04-27
Scope: Code-evidence narrative review of implemented platform logic, feature maturity, and operational limits.

## Executive Verdict

Metatron / Seraph is a broad FastAPI + React + unified-agent security platform with real code paths across SOC operations, endpoint control, AI-agentic detection, Triune cognition, deception, email, mobile, cloud posture, and optional network/sandbox integrations.

The current repository is best described as a **governed adaptive defense platform in active hardening**:

- Core application stack is real: `backend/server.py`, MongoDB, React frontend, unified agent, Docker Compose, Redis/Celery worker surfaces, and Nginx routing assets exist.
- Router breadth is substantial: 61 router modules and about 701 route decorators across `backend/server.py` and `backend/routers`.
- Frontend breadth is substantial: 68 React page components, with newer workspace pages consolidating older page routes by redirect.
- Endpoint logic is materially implemented: `unified_agent/core/agent.py` plus local web/desktop/mobile shells and installer scripts.
- Newer intelligence logic is real: world model ingestion, Triune services, cognition fabric, AATL/AATR/CCE, ML, AI reasoning, and world-event emissions are wired.
- Production readiness remains conditional in areas that require real infrastructure credentials, calibrated detectors, or durable state guarantees.

## Current Feature Maturity Table

| Domain | Status | Current code reality |
|---|---|---|
| Core backend/API mesh | PASS | `backend/server.py` wires auth, SOC, response, agent, advanced, Triune, email, mobile, MDM, governance, and deception routers. |
| Frontend operations UI | PASS/PARTIAL | React Router v7 app with protected layout and workspace pages; many legacy routes redirect into consolidated workspaces. |
| Unified agent control plane | PASS | Registration, heartbeat, command, installer, EDM, deployment, and telemetry paths exist in `backend/routers/unified_agent.py` and agent code. |
| Swarm/deployment operations | PARTIAL | SSH/WinRM/deployment services exist; success semantics still depend on reachable hosts, credentials, and verification depth. |
| AI-agentic detection | PASS/PARTIAL | AATL, AATR, CCE, CLI ingestion, and threat-intelligence UI exist; detection quality depends on representative telemetry and tuning. |
| Triune cognition | PASS | Metatron, Michael, Loki, cognition fabric, world model, and world event ingestion are wired into backend and docs. |
| SOAR/response/quarantine | PASS/PARTIAL | Engines and APIs exist with audit/durability improvements; high-risk action assurance is still a maturity focus. |
| DLP/EDM | PASS | Agent EDM matching, dataset governance, rollout/rollback, Bloom/fingerprint logic, and enhanced DLP service are present. |
| Email protection/gateway | PASS/PARTIAL | SPF/DKIM/DMARC, phishing/DLP checks, gateway process/quarantine/list/policy APIs exist; production relay depends on SMTP/MTA deployment. |
| Mobile security/MDM | PASS/PARTIAL | Mobile security and MDM connector frameworks exist; live fleet sync/actions depend on platform credentials and API access. |
| CSPM/cloud security | PASS/PARTIAL | AWS/Azure/GCP scanners and authenticated CSPM routes exist; real coverage depends on cloud credentials and account scope. |
| Container/runtime security | PARTIAL | Trivy/Falco/Suricata/Zeek/osquery integrations and profile-gated services exist; runtime signal depth depends on host/container permissions. |
| Browser isolation | PARTIAL | URL analysis, sanitization, sessions, blocked domains, and UI exist; full remote browser isolation/pixel streaming remains limited. |
| Kernel/security posture | PARTIAL | eBPF/kernel/rootkit/secure boot modules and routers exist; production anti-tamper depth is not incumbent-grade. |
| CAS Shield sidecar | PASS/PARTIAL | Separate CAS Shield Sentinel sidecar bundle implements PASS_THROUGH/FRICTION/TRAP_SINK logic; it is adjacent to the main Seraph stack. |

## Major Current Code Updates

### 1. Workspace-oriented frontend navigation

`frontend/src/App.js` now routes the root to `/command`, keeps legacy paths alive through redirects, and groups many workflows into workspace pages:

- `CommandWorkspacePage`
- `AIActivityWorkspacePage`
- `ResponseOperationsPage`
- `InvestigationWorkspacePage`
- `EmailSecurityWorkspacePage`
- `EndpointMobilityWorkspacePage`
- `DetectionEngineeringWorkspacePage`

This means older docs that list each feature as an independent primary page should be read as feature surfaces, not necessarily primary navigation entries.

### 2. Triune + world model integration

The backend now initializes:

- `WorldModelService`
- `MetatronService`
- `MichaelService`
- `LokiService`

and mounts:

- `/api/metatron/*`
- `/api/michael/*`
- `/api/loki/*`
- world ingestion routes

The cognition stack is not only documentation; it is represented by code in `backend/services/cognition_fabric.py`, `backend/services/triune_orchestrator.py`, and `backend/triune/*`.

### 3. Email gateway and MDM are integrated but credential-dependent

Email gateway reality:

- `backend/email_gateway.py` implements parsing, message scoring, blocklist/allowlist checks, quarantine queues, policy configuration, and stats.
- `backend/routers/email_gateway.py` exposes process, stats, quarantine, list, and policy endpoints under `/api/email-gateway`.
- It emits world events for selected actions.
- It is not a complete turnkey production MTA by itself; deployment still requires SMTP/MTA routing and TLS/relay configuration.

MDM connector reality:

- `backend/mdm_connectors.py` defines connectors for Intune, JAMF, Workspace ONE, and Google Workspace.
- `backend/routers/mdm_connectors.py` exposes connector CRUD/connect/sync/device action APIs under `/api/mdm`.
- Some connectors use live APIs when dependencies and credentials exist; fallback/mock paths appear for unavailable libraries or test environments.

### 4. Runtime topology expanded

`docker-compose.yml` now includes:

- Required-ish core services: MongoDB, Redis, backend, frontend.
- Worker plane: Celery worker and Celery beat.
- Optional/default operational services: Elasticsearch, Kibana, Ollama, WireGuard, Nginx.
- Security profile services: Trivy, Falco, Suricata, Zeek, Volatility helper.
- Sandbox profile services: Cuckoo and Cuckoo-specific MongoDB.

Docs that describe only MongoDB/backend/frontend as the system should now mention Redis/Celery when async jobs or scheduled validation are in scope.

## What Works Well

- API composition and feature breadth are high.
- Auth, CORS, setup/admin bootstrap, machine-token websocket verification, and selected permission gates are present.
- SOC workflows have concrete backend and UI surfaces: threats, alerts, hunting, timeline, audit, reports, response, quarantine, SOAR, deception, CSPM, identity, zero trust, email, mobile, MDM, and agent operations.
- Unified agent functionality is materially implemented, not just mocked.
- Optional integrations generally have degraded/fallback behavior rather than hard-failing the entire platform.

## What Remains Conditional

- Production SMTP relay behavior requires external mail routing, certificates, and MTA integration.
- MDM fleet sync/actions require real tenant credentials and platform API permissions.
- CSPM depends on cloud credentials and account/project subscription scope.
- Deployment truth depends on reachable endpoints, SSH/WinRM availability, credentials, and post-install heartbeat verification.
- Detection quality needs replay/evaluation loops, false-positive governance, and representative telemetry.
- Some governance state and connector state still need stronger durable semantics under restart/scale.

## Final Reality Statement

Metatron / Seraph has moved beyond a narrow proof-of-concept and contains real multi-domain security platform logic. The safest current claim is:

> A feature-rich, self-hostable, AI-native security operations and endpoint-defense platform with substantial implemented breadth, strong agent/control-plane foundations, and several production integrations that are framework-complete but environment-dependent.

The main engineering focus should remain contract governance, run-mode clarity, durable state, deployment truth, and detection quality measurement.
