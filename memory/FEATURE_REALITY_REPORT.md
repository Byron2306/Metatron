# Metatron / Seraph Feature Reality Report

## Current Code-Logic Snapshot (updated 2026-04-28)

Backend API is FastAPI version `3.0.0` in `backend/server.py`, served on `8001` with health at `/api/health`. The repo has 61 backend router modules plus package init, 32 backend service modules plus package init, 68 JSX frontend pages plus `GraphWorld.tsx`, 68 `<Route` occurrences in `frontend/src/App.js`, unified agent version `2.0.0`, and 63 backend test files. The authenticated frontend hub is `/command`. Root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack health test.


## Executive Verdict

Seraph is a broad AI-native security platform with real code across backend APIs, frontend SOC workflows, endpoint-agent control, governance, deception, identity, CSPM, email, mobile, MDM, and integrations. The strongest caveat is that several high-value domains are framework-complete but depend on external services, credentials, host privileges, or additional assurance before enterprise production claims.

## What Works Materially

### Backend platform

`backend/server.py` initializes MongoDB access, validates production integration-key requirements, configures CORS, registers routers, exposes `/api/health`, and wires domain engines/services. Most APIs are mounted under `/api`, while a few route families expose native `/api/v1` prefixes.

### Frontend platform

The React app is routed from `frontend/src/App.js`. Authenticated users land on `/command`; older surfaces redirect into consolidated command, investigation, response, detection, email-security, endpoint-mobility, and unified-agent workspaces.

### Unified agent

`unified_agent/core/agent.py` is the agent core and declares version `2.0.0`. Backend control routes are provided by `backend/routers/unified_agent.py` under `/api/unified/...`. Local operator surfaces include a secondary FastAPI helper and Flask web dashboard.

### Threat, response, and governance flows

Threat, alert, hunting, timeline, correlation, quarantine, SOAR, deception, ransomware, identity, CSPM, and governance modules are represented in backend routers/services. Governance and telemetry-chain concepts exist through `backend/services/governed_dispatch.py`, `telemetry_chain.py`, and adjacent authority/executor/context modules.

### Email, mobile, and MDM domains

Email protection, email gateway, mobile security, and MDM connectors are registered in `backend/server.py` and represented in frontend routes through `/email-security` and `/endpoint-mobility`. These are real surfaces, but production SMTP relay and MDM fleet sync require external configuration.

## What Is Conditional

- AI-augmented analysis quality depends on configured model services such as Ollama or external AI APIs.
- Cuckoo, Trivy, Falco, Suricata, Zeek, osquery, BloodHound, Arkime, SpiderFoot, Amass, and related integrations depend on local service/tool availability.
- Kernel/eBPF and secure-boot features depend on host OS, privileges, and sensor configuration.
- Browser isolation provides URL/filtering style controls; full remote browser isolation is still limited.
- Deployment and response outcomes should be verified by agent heartbeat, command result, or external evidence before being treated as final.

## Corrected Documentation Facts

- Use `http://localhost:8001/api/health` for backend health.
- Do not cite root `smoke_test.py` as a Seraph platform smoke test.
- Use `/command` as the current authenticated landing page.
- Count backend routers as 61 modules plus package init and backend services as 32 modules plus package init.
- Count frontend pages as 68 JSX files plus one TSX page.

## Reality-Driven Priorities

1. Keep API/frontend route contracts generated or checked from source.
2. Add validation around optional-service degraded states.
3. Treat production SMTP, MDM, cloud, and AI credentials as deployment prerequisites for those domains.
4. Expand denial-path, policy, and high-risk-action tests across governance and response routes.
5. Maintain a single README/runbook path that points operators to current ports, routes, and tests.

## Final Reality Statement

Seraph is best described as a feature-rich, code-backed adaptive security platform with a broad central control plane and unified endpoint-agent ecosystem. Its runtime contract is FastAPI on `8001`, React on `3000`, MongoDB/Redis data services, `/command` as the hub, `/api` as the primary REST root, `/api/unified` as the agent control plane, and optional integrations that must degrade explicitly.
