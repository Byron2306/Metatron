# Metatron / Seraph AI Defense Platform

Metatron/Seraph is an adaptive cybersecurity platform built around a FastAPI control plane, React operator workspaces, MongoDB-backed platform state, optional security-tool integrations, and a large cross-platform unified endpoint agent.

The repository contains real code for SOC workflows, endpoint telemetry, AI-agentic detection, triune/world-model services, governance, deception, response automation, cloud posture, email/mobile security, MDM connector frameworks, and local deployment profiles. Some integrations are conditional on external services, credentials, host privileges, or optional packages; this README calls those out explicitly.

## Current Code Snapshot

| Surface | Current snapshot |
|---|---:|
| Backend router modules | 61 |
| Backend service modules | 32 |
| FastAPI router registrations | 65 |
| Frontend route entries | 67 |
| App-imported frontend pages | 43 |
| Docker Compose services | 21 |
| Unified-agent backend telemetry keys | 24 |
| Unified-agent local monitors | 25+ depending on OS/config |

## Architecture

```text
React operator workspaces
        |
        | /api/*, selected /api/v1/*, /ws/*
        v
FastAPI backend control plane
        |
        | MongoDB, Redis/Celery, optional integrations
        v
SOC data, governance, triune/world services, unified-agent control
        |
        v
Endpoint agents, scanners, email/mobile/MDM/cloud/security tools
```

### Backend

The backend entrypoint is `backend/server.py`. It:

- creates the FastAPI app;
- connects to MongoDB with optional mock mode for development/tests;
- configures CORS;
- registers the router mesh;
- starts background services for cognition/correlation, network discovery, deployment, AATL/AATR, integrations, and governance execution;
- exposes core health at `GET /api/health` on port `8001` in Docker Compose.

Most APIs mount under `/api`. Some routers expose native or compatibility `/api/v1` paths, including CSPM, identity, attack paths, secure boot, kernel sensors, and deception compatibility mounts.

### Frontend

The frontend is a React SPA in `frontend/`. `frontend/src/App.js` is the route source of truth.

The UI is workspace-oriented. The default route redirects to `/command`; many legacy paths redirect into workspace tabs.

Major workspaces include:

- `/command`
- `/ai-activity`
- `/investigation`
- `/detection-engineering`
- `/response-operations`
- `/email-security`
- `/endpoint-mobility`
- `/world`
- `/unified-agent`

### Unified Agent

The endpoint agent lives mainly in `unified_agent/core/agent.py`. It initializes monitor modules for process/network activity, registry persistence, process trees, LOLBins, code signing, DNS, memory, DLP, vulnerabilities, YARA, ransomware, rootkit/kernel/self-protection, identity, firewall, CLI telemetry, hidden files, alias/rename detection, privilege escalation, email protection, and mobile security. AMSI and WebView2 monitors are Windows-specific.

The backend unified-agent API is mounted at `/api/unified/*` and supports registration, heartbeat, telemetry, commands, installer/download artifacts, EDM flows, and governed dispatch hooks for impactful commands.

## Major Capability Areas

| Area | Current code posture |
|---|---|
| Core SOC | Threats, alerts, dashboard, reports, audit, timeline, hunting, and correlation routes/pages exist. |
| Response and SOAR | Response, quarantine, ransomware, SOAR, deception, honeypot, and honey-token surfaces exist. |
| AI-agentic detection | AATL, AATR, cognition/CCE, AI threat, and ML surfaces exist; quality depends on telemetry/model configuration. |
| Triune/world model | Metatron, Michael, Loki, and world-ingest services/routes are initialized. |
| Governance | Governance APIs, governed dispatch, executor, policy/token/tool services, and telemetry-chain hooks exist. |
| Endpoint control | Unified-agent lifecycle, telemetry, commands, installers, and EDM paths exist. |
| Email security | Email protection APIs and an email gateway framework exist. Production gateway use requires SMTP configuration. |
| Mobile and MDM | Mobile security logic and MDM connectors for major platforms exist. Live MDM requires tenant credentials/API access. |
| CSPM | Cloud posture APIs exist and require credentials for meaningful scan results. |
| Containers/network/sandbox | Docker Compose wires Trivy, Falco, Suricata, Zeek, WireGuard, and Cuckoo; runtime depends on host support and enabled services. |
| Browser isolation | URL/session/filtering surfaces exist; full remote browser isolation remains limited. |

## Runtime Modes

### Minimal core

```bash
docker compose up -d mongodb backend frontend
```

### Core plus async workers

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend
```

### Local integration mode

```bash
docker compose up -d mongodb redis backend celery-worker celery-beat frontend elasticsearch kibana ollama wireguard
```

### Full Compose mode

```bash
docker compose up -d
```

Full Compose mode starts all 21 services and is host/environment-sensitive. VPN, packet inspection, sandboxing, and some endpoint/security functions can require extra privileges, credentials, or kernel support.

## Quick Validation

After starting the core stack:

```bash
curl -fsS http://localhost:8001/api/health
curl -fsS http://localhost:3000
```

Then log in through the frontend and verify a protected workspace loads.

If optional integrations are enabled, validate them from their specific status endpoints or pages. Optional integration failures should be treated as degraded feature state, not automatic core platform failure.

## Configuration Notes

Important environment variables include:

- `MONGO_URL`
- `DB_NAME`
- `JWT_SECRET`
- `CORS_ORIGINS`
- `ENVIRONMENT`
- `SERAPH_STRICT_SECURITY`
- `INTEGRATION_API_KEY`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_NAME`
- `REDIS_URL`
- `OLLAMA_URL`
- `ELASTICSEARCH_URL`

In production or strict mode, configure explicit CORS origins and strong secrets. Do not rely on development defaults from Compose.

## Repository Map

| Path | Purpose |
|---|---|
| `backend/server.py` | FastAPI app composition, router registration, startup/shutdown loops. |
| `backend/routers/` | API domains for auth, SOC, response, agent, AI, governance, email, mobile, cloud, and integrations. |
| `backend/services/` | Background services and shared domain services. |
| `frontend/src/App.js` | React route source of truth. |
| `frontend/src/pages/` | Workspace and standalone operator pages. |
| `unified_agent/core/agent.py` | Main endpoint agent and monitor implementations. |
| `docker-compose.yml` | Local multi-service topology. |
| `memory/` | Architecture, reality, evaluation, and run-mode review documents. |
| `test_reports/` | Historical validation and smoke-test artifacts. |

## Current Known Limitations

- Production SMTP relay must be configured and validated before treating email gateway behavior as live production protection.
- MDM connectors require real tenant credentials and permissions for live sync/actions.
- CSPM findings require cloud credentials.
- Sandbox, VPN, container/runtime sensors, and kernel sensors depend on host capabilities and optional services.
- Some tier-1 routers are disabled if optional imports fail.
- Browser isolation is not yet equivalent to full remote browser isolation/pixel streaming.
- Detection efficacy and false-positive control require benchmark/replay evidence before direct parity claims with mature commercial XDR vendors.
- API/frontend/script contracts should be generated and checked to prevent drift.

## Documentation Truth Rule

When updating docs, separate:

1. **Core implemented behavior**: code paths that run with required services.
2. **Conditional integrations**: code paths that need external credentials, services, host privileges, or optional packages.
3. **Strategic direction**: product positioning or roadmap claims that are not yet fully validated by runtime evidence.

This keeps README and memory documents aligned with the actual codebase.
