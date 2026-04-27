# Metatron / Seraph AI Defense Platform

Metatron / Seraph is a self-hostable security operations and endpoint-defense platform that combines a FastAPI control plane, React operator UI, unified endpoint agent, AI-agentic detection services, Triune cognition, deception, cloud posture, email security, mobile/MDM management, and optional security-tool integrations.

The repository is feature-rich and broad. Some capabilities are fully local, while others are framework-complete and require real credentials, sensors, or external infrastructure to produce production-grade results.

## Current Code Snapshot

| Area | Current implementation |
|---|---|
| Backend API | FastAPI application in `backend/server.py` with 61 router modules and roughly 701 route decorators |
| Frontend | React 19 / React Router app with 68 page components and workspace-oriented navigation |
| Agent | Cross-platform unified agent in `unified_agent/` with local web/desktop/mobile shells and installer scripts |
| Data store | MongoDB primary store; Redis/Celery for async and scheduled work |
| Optional operations stack | Elasticsearch, Kibana, Ollama, WireGuard, Nginx |
| Security profiles | Trivy, Falco, Suricata, Zeek, Volatility helper |
| Sandbox profile | Cuckoo sandbox plus isolated Cuckoo MongoDB |
| Adjacent bundle | CAS Shield Sentinel sidecar in `cas_shield_sentinel_bundle/` |

## Major Capabilities

- SOC operations: threats, alerts, hunting, timelines, audit, reports, correlation, and dashboards.
- Endpoint operations: unified agent registration, heartbeat, command dispatch, deployment flows, local telemetry, EDM/DLP, and installer downloads.
- Response operations: quarantine, SOAR, ransomware protection, threat response, deception, honey tokens, and command workflows.
- AI-native defense: AATL, AATR, CLI session cognition, ML prediction, AI reasoning, MCP-style tooling, and local/Ollama-capable analysis paths.
- Triune cognition: Metatron, Michael, Loki, world events, cognition fabric, and world model ingestion.
- Cloud and infrastructure security: CSPM for AWS/Azure/GCP, container security, kernel sensors, secure boot checks, osquery, Zeek, Sigma, and atomic validation surfaces.
- Email and mobile security: email protection, SMTP gateway management APIs, mobile security, and MDM connectors for Intune, JAMF, Workspace ONE, and Google Workspace.
- Browser and network security: browser isolation controls, browser extension assets, VPN management, and network topology/discovery flows.

## Repository Layout

```text
backend/                  FastAPI server, routers, engines, services, tests
frontend/                 React operator UI
unified_agent/            Endpoint agent, local UI, installers, integrations
memory/                   Architecture, reality, run-mode, and evaluation docs
docs/                     Focused feature and integration notes
deployment/               Additional deployment units
scripts/                  Installers, validators, security utility scripts
cas_shield_sentinel_bundle/  CAS sidecar reverse-proxy bundle
tools/                    Helper container build contexts
test_reports/             Validation and evidence reports
```

## Runtime Modes

### Minimal platform

Runs the core API and UI. Use this for code review and basic local validation.

```bash
docker compose up -d mongodb redis backend frontend
```

### Operator stack

Adds common local operations services.

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend elasticsearch kibana ollama wireguard nginx
```

### Security profile

Adds host/security tooling where the host supports the needed permissions.

```bash
docker compose --profile security up -d
```

### Sandbox profile

Adds Cuckoo sandbox services.

```bash
docker compose --profile sandbox up -d
```

## Quick Start

1. Create and edit environment configuration.

   ```bash
   cp .env.example .env
   ```

2. Start the core stack.

   ```bash
   docker compose up -d mongodb redis backend frontend
   ```

3. Validate health.

   ```bash
   curl -fsS http://127.0.0.1:8001/api/health
   curl -fsS http://127.0.0.1:3000
   python3 smoke_test.py
   ```

4. Open the UI.

   ```text
   http://localhost:3000
   ```

5. Optional: bootstrap an admin account with the `bootstrap` profile or configure `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and setup-related environment variables according to your deployment policy.

## Important Environment Variables

| Variable | Purpose |
|---|---|
| `MONGO_URL` | MongoDB connection string |
| `DB_NAME` | Database name, default `seraph_ai_defense` |
| `REDIS_URL` | Redis connection for async services |
| `JWT_SECRET` | API authentication signing secret; change for any non-dev deployment |
| `CORS_ORIGINS` | Explicit frontend origins |
| `SERAPH_STRICT_SECURITY` | Enforces stricter production controls when enabled |
| `INTEGRATION_API_KEY` | Internal ingestion and worker authentication |
| `REACT_APP_BACKEND_URL` | Optional frontend backend URL override |
| `OLLAMA_URL`, `OLLAMA_MODEL` | Local LLM endpoint and model |
| `ELASTICSEARCH_URL`, `KIBANA_URL` | SIEM/dashboard integrations |
| `CUCKOO_API_URL` | Sandbox API endpoint |
| `TRIVY_SERVER`, `FALCO_ENABLED` | Container/runtime security integration settings |

## API and UI Routing

- Backend routes are primarily mounted under `/api/*`.
- Some newer or compatibility APIs use native `/api/v1/*` prefixes.
- WebSocket endpoints include `/ws/threats` and `/ws/agent/{agent_id}`.
- The frontend root redirects to `/command`.
- Several legacy frontend routes redirect into newer workspace pages:
  - `/alerts`, `/threats` -> `/command`
  - `/quarantine`, `/response`, `/soar`, `/edr` -> `/response-operations`
  - `/threat-intel`, `/correlation`, `/attack-paths` -> `/investigation`
  - `/email-protection`, `/email-gateway` -> `/email-security`
  - `/mobile-security`, `/mdm` -> `/endpoint-mobility`

## Feature Reality Notes

Use the platform with the following distinctions:

- Core backend/frontend/agent logic is implemented.
- Email gateway APIs and scoring/quarantine/list logic exist, but production relay behavior requires SMTP/MTA deployment, certificates, and routing.
- MDM connectors exist for major platforms, but live sync/actions require tenant credentials and platform API permissions.
- CSPM scanners require cloud credentials and account/project scope.
- Deployment routes need reachable hosts, SSH/WinRM configuration, credentials, and post-install verification to represent real success.
- Optional services should degrade gracefully, but pages tied to disabled integrations may show partial data or status warnings.
- Detection quality and autonomous response safety depend on calibrated telemetry, regression tests, policy gates, and operator review.

## Documentation Map

Start with these current memory documents:

- `memory/FEATURE_REALITY_REPORT.md` - narrative reality review
- `memory/FEATURE_REALITY_MATRIX.md` - feature-by-feature implementation matrix
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md` - system-wide evaluation rebaseline
- `memory/SECURITY_FEATURES_ANALYSIS.md` - security-domain assessment
- `memory/RUN_MODE_CONTRACT.md` - required vs optional runtime contract
- `memory/SYSTEM_CRITICAL_EVALUATION.md` - risks, maturity, and engineering priorities
- `memory/architecture_diagrams/architecture-map-2026-03-06.md` - architecture map

Additional focused docs:

- `docs/triune_cognition_feature_summary.md`
- `docs/AI_TRIUNE_INTEGRATION.md`
- `docs/ATTACK_237_TECHNIQUES_AND_639_ROADMAP.md`
- `DEPLOYMENT.md`
- `SYSTEM_FUNCTIONALITY.md`
- `unified_agent/LOCAL_MACHINE_VALIDATION.md`

## Development and Validation

Backend tests are under `backend/tests/`; unified-agent tests are under `unified_agent/tests/`.

Common validation commands:

```bash
python3 smoke_test.py
pytest backend/tests
pytest unified_agent/tests
```

Frontend validation:

```bash
cd frontend
yarn install
yarn test
yarn build
```

Use targeted tests where possible when changing a specific router, service, or page.

## Security and Operations Guidance

- Change all default secrets before exposing any service.
- Keep backend, MongoDB, Redis, and frontend bound to private interfaces unless intentionally reverse-proxied.
- Prefer Nginx or another TLS-terminating reverse proxy for internet-facing deployments.
- Set explicit `CORS_ORIGINS` in production or strict mode.
- Treat AI/LLM outputs as advisory; policy and approval gates should govern actions.
- Record provenance for high-risk autonomous recommendations and executed commands.
- Do not claim production readiness for credential-dependent integrations until they are validated against real environments.

## Current Engineering Priorities

1. Contract governance between backend, frontend, scripts, and agent payloads.
2. Deployment truth and post-install evidence for SSH/WinRM/unified deployment flows.
3. Durable state for governance, connector, rollout, policy, token, and command records.
4. Detection quality measurement with replay, precision/recall, and false-positive governance.
5. Clear degraded-mode UX for disabled or unhealthy optional integrations.
6. Anti-tamper and hardening depth across agent, kernel, and high-risk action paths.

## License

Proprietary / internal project unless a separate license file states otherwise.
