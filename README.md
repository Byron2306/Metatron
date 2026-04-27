# Metatron / Seraph AI Defense Platform

Metatron/Seraph is a broad security platform that combines a FastAPI control plane, a React SOC dashboard, MongoDB-backed operational state, and a cross-platform unified endpoint agent. The current codebase includes SOC workflows, endpoint telemetry, governed response, cloud posture, email and mobile security, MDM connectors, deception, advanced AI/security services, and architecture review documentation.

This README reflects the repository state reviewed on 2026-04-27. Older documents may contain historical product language; the refreshed `memory/` review documents listed below are the source of truth for current implementation reality.

## Current Reality Snapshot

The platform is best understood as a **high-breadth governed adaptive defense system in active hardening**.

What is materially implemented:

- FastAPI router mesh in `backend/server.py` for SOC, endpoint, response, CSPM, advanced services, identity, governance, email, mobile, MDM, deception, and supporting domains.
- React dashboard in `frontend/src/App.js` with workspace-oriented routing and compatibility redirects from older feature URLs.
- MongoDB-backed agent registration, heartbeat telemetry, monitor telemetry, command records, EDM dataset versions, EDM hit telemetry, rollout state, CSPM scans/findings, deployment tasks, and selected governance artifacts.
- Unified endpoint agent in `unified_agent/core/agent.py` with process, network, registry, memory, DLP/EDM, CLI telemetry, ransomware, rootkit/kernel, identity, firewall, auto-throttle, and self-protection logic.
- Advanced service APIs for MCP, vector memory, VNS, quantum security, and AI reasoning under `/api/advanced/*`.
- Email protection/gateway and mobile/MDM services with routers, permission checks, workspace UI wiring, and world-event/audit hooks.

Important caveats:

- Vector memory, VNS, token broker runtime state, Email Gateway queues, and portions of MCP execution history are primarily in-process stores unless mirrored by audit/world-event persistence.
- Email Gateway production value depends on real SMTP/MTA relay configuration.
- MDM connector production value depends on real Intune, JAMF, Workspace ONE, or Google Workspace credentials and provider API availability.
- Optional services such as Elasticsearch, Kibana, WireGuard, Ollama, Trivy, Falco, Suricata, and Cuckoo should degrade gracefully when unavailable.
- Deployment success over SSH/WinRM requires credentials and reachable endpoints. Simulated deployment success is explicit through `ALLOW_SIMULATED_DEPLOYMENTS`.

## Repository Map

| Path | Purpose |
|---|---|
| `backend/` | FastAPI API server, routers, security services, engines, tests, and background worker integration. |
| `backend/routers/` | REST API domains: auth, threats, alerts, unified agent, CSPM, advanced, identity, email, mobile, MDM, governance, response, and more. |
| `backend/services/` | Advanced/governance services: MCP, vector memory, VNS, policy engine, token broker, telemetry chain, cognition, AI reasoning, deployment, SIEM, and related services. |
| `frontend/` | React dashboard and workspace pages. |
| `unified_agent/` | Endpoint agent, local APIs, desktop/web UI, deployment utilities, and integration docs. |
| `memory/` | Current system review, reality matrix, architecture map, run-mode contract, PRD, board/roadmap/whitepaper, and feature analysis documents. |
| `docs/` | Additional architecture and integration notes. |
| `test_reports/` | Validation, parity, coverage, and smoke-test reports. |
| `scripts/` | Operational and validation scripts. |
| `docker-compose.yml` | Local/containerized stack definition. |

## Runtime Architecture

### Core stack

- `mongodb`: required data store.
- `backend`: FastAPI server. Compose maps it to `127.0.0.1:8001` by default.
- `frontend`: React dashboard. Compose maps it to `localhost:3000`.

### Supporting services

- `redis`, `celery-worker`, `celery-beat`: background work and scheduling.
- `elasticsearch`, `kibana`: search/SIEM dashboard support.
- `wireguard`: VPN support.
- `ollama`: local LLM support for optional AI reasoning.
- Security profile services such as Trivy, Falco, Suricata, and sandbox components are optional/profile-gated.

See `memory/RUN_MODE_CONTRACT.md` for the source-of-truth run-mode contract.

## Major Code Paths

### Backend router mesh

`backend/server.py` mounts most routers under `/api` and selected routers with native `/api/v1` prefixes. Major domains include:

- Core platform: auth, users, dashboard, settings, websocket, audit, reports.
- SOC analytics: threats, alerts, threat intel, hunting, correlation, timeline.
- Response: response, quarantine, SOAR, ransomware, honeypots, honey tokens, deception.
- Endpoint: agents, agent commands, swarm, unified agent.
- Enterprise: zero trust, multi-tenant, extension, identity, governance.
- Advanced: MCP, vector memory, VNS, quantum security, AI reasoning, ML, sandbox, EDR, containers, VPN, CSPM.
- Email/mobile: email protection, email gateway, mobile security, MDM connectors.

### Frontend workspaces

The current UI consolidates many historical pages into workspaces:

- `/command`: dashboard, command center, threats, alerts.
- `/investigation`: threat intel, correlation, attack paths.
- `/response-operations`: quarantine, EDR, threat response, SOAR.
- `/email-security`: email protection and email gateway.
- `/endpoint-mobility`: mobile security and MDM connectors.
- `/detection-engineering`: Sigma, Atomic Validation, MITRE coverage.
- `/ai-activity`: AI signals, CLI sessions, AI threat intelligence.

Compatibility redirects keep legacy routes such as `/email-gateway`, `/mdm`, `/agents`, `/alerts`, `/threats`, and `/soar` usable.

### Unified agent

The unified agent handles local endpoint monitoring and control:

- Registration and heartbeat with backend APIs.
- Process, network, registry, memory, DLP/EDM, CLI, ransomware, rootkit, kernel, identity, firewall, and self-protection monitoring.
- EDM dataset loading, signing checks, hot reload, deterministic matching, and hit telemetry.
- Governance-aware command handling for high-impact actions.

Backend persistence for agent state lives mainly in `backend/routers/unified_agent.py`.

### Advanced service plane

`backend/routers/advanced.py` exposes:

- MCP tool catalog, status, history, and governance-queued execution.
- Vector memory store/search/case APIs using `backend/services/vector_memory.py`.
- VNS flow/DNS/TLS/beacon APIs using `backend/services/vns.py`.
- Quantum signing, verification, and hashing APIs.
- AI reasoning APIs with rule/local-LLM fallback behavior.

Current durability note: vector memory and VNS are useful functional primitives but are not external vector DB or packet broker implementations in this codebase.

### Email and mobile plane

- `backend/email_protection.py`: SPF/DKIM/DMARC, phishing, URL, attachment, impersonation, DLP, quarantine-style analysis.
- `backend/email_gateway.py`: API-driven SMTP gateway framework with parsing, policies, block/allow lists, quarantine, and decisions.
- `backend/mobile_security.py`: mobile device, threat, app, compliance, and network checks.
- `backend/mdm_connectors.py`: Intune, JAMF, Workspace ONE, and Google Workspace connector classes and management actions.

Production use requires real mail routing and MDM provider credentials.

## Quick Start

```bash
docker compose up -d mongodb backend frontend
```

Then open:

- Frontend: `http://localhost:3000`
- Backend health: `http://localhost:8001/api/health`

For a fuller local stack:

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend elasticsearch kibana ollama wireguard
```

Optional/profile services may require additional host capabilities and configuration.

## Validation

Useful checks:

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
python3 smoke_test.py
```

Targeted backend tests live under `backend/tests/`. Historical validation reports live under `test_reports/`.

## Configuration Notes

Important environment variables include:

- `MONGO_URL`, `DB_NAME`
- `JWT_SECRET`
- `CORS_ORIGINS`
- `SERAPH_STRICT_SECURITY`
- `MCP_SIGNING_KEY`
- `BROKER_MASTER_KEY`, `BROKER_SIGNING_KEY`
- `ALLOW_SIMULATED_DEPLOYMENTS`
- `OLLAMA_URL`, `OLLAMA_MODEL`, `LOCAL_LLM_ENABLED`
- `ELASTICSEARCH_URL`, `KIBANA_URL`
- `CUCKOO_API_URL`, `CUCKOO_API_TOKEN`
- SMTP/MTA and MDM provider credentials for production email/mobile integrations

In production or strict mode, avoid weak/default signing and JWT secrets and use explicit CORS origins.

## Refreshed Memory Review Documents

The following documents were updated to summarize current code logic and correct older overstatements:

| Document | Role |
|---|---|
| `memory/FEATURE_REALITY_REPORT.md` | Qualitative feature reality and current implementation narrative. |
| `memory/FEATURE_REALITY_MATRIX.md` | Quantitative maturity matrix and evidence map. |
| `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` | System-wide evaluation rebaselined against current code. |
| `memory/SYSTEM_CRITICAL_EVALUATION.md` | Critical architecture, security, operations, and risk evaluation. |
| `memory/SECURITY_FEATURES_ANALYSIS.md` | Security capability inventory and current caveats. |
| `memory/RUN_MODE_CONTRACT.md` | Required vs optional services and degraded-mode expectations. |
| `memory/architecture_diagrams/architecture-map-2026-03-06.md` | Current architecture map and storage/durability split. |
| `memory/PRD.md` | Product history with current-code interpretation guidance. |
| `memory/SERAPH_COMPETITIVE_WHITEPAPER_2026.md` | Competitive strategy with current implementation update. |
| `memory/SERAPH_IMPLEMENTATION_ROADMAP_2026.md` | Roadmap adjusted around durability, contracts, and integration certification. |
| `memory/SERAPH_BOARD_BRIEF_2026.md` | Executive brief updated for current feature-vs-production distinction. |
| `memory/full_pages_wiring_audit.md` | Frontend page/API wiring snapshot and workspace-routing note. |
| `memory/dashboard_static_audit.md` | Static dashboard/API audit snapshot and current routing caveat. |

## Engineering Priorities

The current review points to these highest-value next steps:

1. Externalize or persist advanced-service state for vector memory, VNS, MCP execution history, token broker runtime state, and Email Gateway queues where production durability is required.
2. Maintain contract/schema tests for backend routers, frontend workspaces, scripts, and agent payloads.
3. Certify production integrations for SMTP/MTA, MDM providers, cloud scanners, SIEM, sandbox, and optional AI providers.
4. Expand denial-path and high-risk-action regression tests around governance, token, command, and MCP flows.
5. Keep UI degraded-mode states explicit for optional services.

## License and Use

This repository contains a security platform implementation and documentation set. Review deployment, integration, and legal requirements before using it against real networks, endpoints, mailflows, or tenant environments.
