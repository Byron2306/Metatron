# Metatron / Seraph AI Defense Platform

Metatron/Seraph is an AI-oriented cyber defense platform that combines EDR/XDR workflows, SOAR, deception, zero trust, email and mobile security, cloud posture, advanced AI services, and a unified endpoint agent in one repository.

This README reflects the current repository state as of the May 1, 2026 documentation rebaseline. Counts below are source snapshots, not marketing invariants.

## Current Code Snapshot

| Area | Current repository evidence |
|---|---:|
| Backend API version | FastAPI app `3.0.0` in `backend/server.py` |
| Active backend router modules | 60 files under `backend/routers` excluding helpers |
| Source route declarations | About 700 HTTP/WebSocket decorators across server/router files |
| Backend service modules | 33 files under `backend/services` |
| Frontend page/workspace components | 68 JSX files under `frontend/src/pages` |
| Unified Agent monitor keys | 25 baseline, up to 27 with Windows-only AMSI/WebView2 |
| Docker Compose service definitions | 21, including optional/profile-gated services |

## What the Platform Does

### SOC and XDR workflows
- Threats, alerts, dashboards, reports, audit logs, hunting, correlation, and timeline reconstruction.
- Response operations through quarantine, SOAR, threat response, ransomware workflows, honey tokens, honeypots, and deception.
- Investigation workspaces for threat intelligence, correlation, attack paths, and world graph views.

### Unified endpoint agent
- Main implementation: `unified_agent/core/agent.py`.
- Backend control plane: `backend/routers/unified_agent.py` mounted under `/api/unified`.
- Supports registration, heartbeat, telemetry, commands, deployments, installer downloads, dashboard stats, EDM dataset governance, staged rollouts, and rollback/readiness paths.
- Baseline monitor keys include process, network, registry, process tree, LOLBin, code signing, DNS, memory, whitelist, DLP, vulnerability, YARA, ransomware, rootkit, kernel security, self protection, identity, auto throttle, firewall, CLI telemetry, hidden file, alias/rename, privilege escalation, email protection, and mobile security. Process/network are config-dependent; AMSI and WebView2 are Windows-only additions.

### AI-native defense services
- AATL/AATR services for autonomous AI threat activity.
- Cognition/Correlation Engine worker for CLI/session behavior signals.
- Triune routers and services for Metatron, Michael, and Loki workflows.
- Optional model-backed analysis through Ollama/LLM configuration with rule-based fallbacks in several paths.

### Advanced service plane
- MCP server/tooling, vector memory, VNS and VNS alerts, quantum security, AI reasoning, governance context, policy engine, token broker, tool gateway, telemetry chain, and outbound gates.
- The advanced plane is implemented, but production quality depends on configured dependencies and explicit operational guardrails.

### Email, mobile, and identity
- Email protection: SPF/DKIM/DMARC, phishing, URL, attachment, impersonation, DLP, protected users, and quarantine-oriented flows.
- Email gateway: SMTP relay framework, inline processing, policy, quarantine, blocklist/allowlist, stats, and UI/API surfaces.
- Mobile security: device lifecycle, threat detection, app analysis, compliance, network checks, and agent monitor integration.
- MDM connectors: Microsoft Intune, JAMF Pro, VMware Workspace ONE, and Google Workspace connector frameworks. Live sync/actions require real tenant credentials.
- Identity protection and enterprise routers provide identity, policy, token, tool, telemetry, and multi-tenant surfaces.

### Cloud, container, network, and sandbox integrations
- CSPM, container security, VPN/WireGuard, Zeek, osquery, Sigma, Atomic validation, MITRE coverage, sandboxing, and browser isolation surfaces are present.
- Integrations manager supports tools such as Amass, Arkime, BloodHound, SpiderFoot, Velociraptor, PurpleSharp, Sigma, Atomic Red Team, Falco, YARA, Suricata, Trivy, Cuckoo, osquery, and Zeek.
- Several integrations are optional, profile-gated, credential-gated, or require host tooling.

## Repository Layout

```text
backend/                 FastAPI app, routers, services, engines, workers
frontend/                React dashboard and workspace UI
unified_agent/           Endpoint agent, local UI/API, integrations client, tests
memory/                  Product, architecture, reality, and review documents
docs/                    Focused technical docs and integration notes
test_reports/            Historical validation and runtime reports
scripts/                 Deployment and operational helper scripts
tools/                   Auxiliary containers/tools such as Cuckoo and Volatility
docker-compose.yml       Local/full-stack orchestration
```

## Runtime Architecture

```text
Operators / Dashboard / Agents
            |
            v
Nginx / direct local ports / WebSockets
            |
            v
FastAPI backend (`backend/server.py`)
  |-- MongoDB: platform state, telemetry, cases, control records
  |-- Redis/Celery: async integration, world, triune, and worker jobs
  |-- Services: governance, AI, memory, VNS, deployment, integrations
  |-- Routers: SOC, endpoint, email, mobile, cloud, deception, response
            |
            v
Unified endpoint agents and optional external tools/services
```

## Run Modes

The Compose file defines more services than are needed for the smallest useful stack. Treat the modes below as operational contracts.

### Minimal reliable mode

```bash
docker compose up -d mongodb redis backend frontend
```

Use this for basic API/UI validation.

### Recommended local full mode

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat elasticsearch kibana ollama frontend wireguard nginx
```

Use this for local development with async workers, local SIEM dashboards, LLM service, VPN service, frontend, and reverse proxy.

### Bootstrap helpers

```bash
docker compose --profile bootstrap up ollama-pull admin-bootstrap
```

This can pull the configured Ollama model and run the one-shot admin bootstrap helper.

### Extended security sensors

```bash
docker compose --profile security up -d
```

Adds profile-gated services such as Volatility, Trivy, Falco, Suricata, and Zeek. These may require Linux host capabilities, privileged containers, interfaces, or additional tuning.

### Sandbox mode

```bash
docker compose --profile sandbox up -d
```

Starts Cuckoo sandbox services. This path usually needs lab/VM tuning before production-like malware analysis.

## Configuration Notes

Create and customize your environment before starting services:

```bash
cp .env.example .env
```

Important variables include:

| Variable | Purpose |
|---|---|
| `MONGO_URL`, `DB_NAME` | Backend database connection |
| `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | Queue and async worker configuration |
| `JWT_SECRET` | JWT signing secret; must be strong in production/strict mode |
| `CORS_ORIGINS` | Explicit frontend origins; wildcard is rejected in production/strict mode |
| `INTEGRATION_API_KEY` | Required for production internal ingestion/M2M paths |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME` | Optional startup admin seed values |
| `SETUP_TOKEN` | Optional setup protection for first-admin creation |
| `OLLAMA_URL`, `OLLAMA_MODEL`, `LOCAL_LLM_ENABLED` | Local model-backed analysis configuration |
| `CUCKOO_API_URL`, `CUCKOO_API_TOKEN` | Sandbox integration configuration |
| `TRIVY_ENABLED`, `FALCO_ENABLED`, `FLEET_*`, `OSQUERY_RESULTS_LOG` | Optional sensor/tool configuration |

## Health and Validation

Basic checks after startup:

```bash
docker compose ps
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Important caveat: `/api/health` currently indicates API process health and returns a static `database` field. It should not be treated as a full live dependency probe for MongoDB, Redis, Elasticsearch, Ollama, sensors, or credential-gated integrations.

For code-level validation, run targeted tests for the area you changed. Common starting points:

```bash
# Backend tests, from repository root
pytest backend/tests

# Unified agent tests
pytest unified_agent/tests

# Frontend tests, from frontend/
npm test -- --watchAll=false
```

The repository also contains historical reports in `test_reports/`; those reports are useful context but should not replace fresh validation in your configured environment.

## Key API Surfaces

| Area | Representative paths |
|---|---|
| API root/health | `/api/`, `/api/health` |
| Auth/users | `/api/auth/*`, `/api/users/*` |
| Threat operations | `/api/threats/*`, `/api/alerts/*`, `/api/hunting/*`, `/api/correlation/*`, `/api/timeline/*` |
| Response/SOAR | `/api/response/*`, `/api/quarantine/*`, `/api/soar/*`, `/api/ransomware/*` |
| Unified agent | `/api/unified/*`, `/api/agent-commands/*`, `/api/swarm/*` |
| Advanced services | `/api/advanced/*`, `/api/metatron/*`, `/api/michael/*`, `/api/loki/*` |
| Email/mobile | `/api/email-protection/*`, `/api/email-gateway/*`, `/api/mobile-security/*`, `/api/mdm/*` |
| Enterprise/cloud | `/api/v1/cspm/*`, `/api/v1/identity/*`, `/api/enterprise/*`, `/api/zero-trust/*` |
| WebSockets | `/ws/threats`, `/ws/agent/{agent_id}` |

Some routers have native `/api/v1` prefixes while most are mounted with `/api` in `backend/server.py`.

## Frontend Navigation

The React app uses `frontend/src/App.js` as the route source of truth. `/` redirects to `/command`. Several older paths redirect into workspace hubs:

- `/dashboard`, `/alerts`, and `/threats` route into the command workspace.
- `/agents`, `/agent-commands`, and `/swarm` route into `/unified-agent`.
- `/edr`, `/soar`, `/response`, and `/quarantine` route into response operations.
- `/email-protection` and `/email-gateway` route into the email security workspace.
- `/mobile-security` and `/mdm` route into the endpoint mobility workspace.

## Documentation Map

| Document | Purpose |
|---|---|
| `memory/RUN_MODE_CONTRACT.md` | Required vs optional services and run-mode expectations |
| `memory/FEATURE_REALITY_MATRIX.md` | Current implementation maturity matrix |
| `memory/FEATURE_REALITY_REPORT.md` | Qualitative reality report by domain |
| `memory/SYSTEM_CRITICAL_EVALUATION.md` | Critical architecture/security/operations assessment |
| `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` | System-wide evaluation rebaselined with current source facts |
| `memory/SECURITY_FEATURES_ANALYSIS.md` | Security feature inventory and residual gaps |
| `memory/SERAPH_COMPETITIVE_WHITEPAPER_2026.md` | Competitive positioning and convergence strategy |
| `memory/SERAPH_IMPLEMENTATION_ROADMAP_2026.md` | Technical convergence roadmap |
| `memory/architecture_diagrams/architecture-map-2026-03-06.md` | Text architecture map |
| `docs/AI_TRIUNE_INTEGRATION.md` | Triune AI integration notes |
| `docs/triune_cognition_feature_summary.md` | Cognition/triune feature summary |

## Current Maturity Statement

Seraph has substantial implemented breadth and a sophisticated architecture, but the safest current maturity statement is:

- **Strong:** capability coverage, API breadth, unified-agent control plane, SOC workflow composition, email/mobile frameworks, and advanced governance/AI primitives.
- **Improving:** contract discipline, dependency-aware health semantics, durable governance state, optional integration clarity, and production credential paths.
- **Conditional:** security sensor stack, sandboxing, LLM-backed analysis, live MDM synchronization, production SMTP relay, and full remote browser isolation.

Use generated inventories, targeted tests, and environment-specific validation before making production readiness or parity claims.
