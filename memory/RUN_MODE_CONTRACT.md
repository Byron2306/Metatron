# Metatron Run-Mode Contract

Updated: 2026-04-29
Purpose: define required services, optional dependencies, and how operators should interpret live, degraded, demo, and simulated behavior.

## Required core

These services define a healthy core platform:

- `mongodb`
- `backend`
- `frontend`

Core backend entrypoint: `backend/server.py`.
Core UI entrypoint: `frontend/src/App.js`.

If any required core service is unavailable, the platform is not healthy.

## Optional integrations

Optional services may be enabled for deeper functionality:

- `wireguard` for VPN flows.
- `elasticsearch` and `kibana` for SIEM/search visualization.
- `ollama` for local model-assisted reasoning.
- `trivy`, `falco`, `suricata` for security-tool profiles.
- `cuckoo`/sandbox components for dynamic analysis.
- SMTP, MDM, SIEM, threat-feed, and external tool credentials for live integrations.

Behavior contract:

- Core SOC pages must remain usable when optional services are unavailable.
- Feature pages must show degraded/unavailable state instead of implying live coverage.
- Demo or simulated results must be labeled as such.

## Runtime modes

| Mode | Meaning | Examples |
|---|---|---|
| `live` | Real configured service/tool/credential path executed. | Real MongoDB, real agent heartbeat, real SMTP/MDM/SIEM calls. |
| `degraded` | Feature runs with reduced capability because a dependency is missing. | No Ollama, no external SIEM, unavailable sandbox. |
| `demo` | Seeded or generated sample data for UI/development. | CSPM demo seed, dashboard seed, frontend empty-state demo datasets. |
| `simulated` | Code intentionally fakes execution for safe testing. | `ALLOW_SIMULATED_DEPLOYMENTS`, `MCP_ALLOW_SIMULATED_EXECUTION`. |
| `unavailable` | Dependency missing and no safe fallback exists. | Missing required credentials for a live-only connector. |

## API routing contract

- Backend routers are mounted mainly under `/api` in `backend/server.py`.
- Frontend resolves `REACT_APP_BACKEND_URL` in `frontend/src/context/AuthContext.jsx`.
- If no safe backend URL is configured, frontend uses same-origin `/api`.
- Reverse-proxied production deployments should prefer same-origin `/api`.

## Health validation sequence

1. Start required services.
2. Verify backend: `curl -fsS http://localhost:8001/api/health`.
3. Verify frontend: open `http://localhost:3000` or the deployed URL.
4. Log in and open `/command`, `/world`, `/unified-agent`, `/detection-engineering`, and `/response-operations`.
5. For optional integrations, verify the feature-specific status panel/API and confirm mode is live or explicitly degraded/demo/simulated.

## Source-of-truth flows

| Flow | Source of truth |
|---|---|
| Unified agents | `/api/unified/*`, `unified_agent/core/agent.py` |
| World/Triune state | `/api/metatron/state`, `backend/services/world_events.py`, `triune_orchestrator.py` |
| Governed actions | `outbound_gate.py`, `governed_dispatch.py`, `governance_executor.py`, `telemetry_chain.py` |
| MITRE coverage | `/api/mitre/coverage`, `backend/scripts/mitre_coverage_evidence_report.py` |
| Integrations | `/api/integrations/*`, `backend/integrations_manager.py` |

## Acceptance criteria for "working"

The system is considered working when:

1. Required services are healthy.
2. Login and protected route access work.
3. Core SOC workspaces load without fatal errors.
4. Unified-agent APIs can list/register/heartbeat in the configured auth mode.
5. Optional integrations fail gracefully and visibly when unavailable.
6. Simulated/demo paths are labeled and not used as production evidence.
7. High-impact commands are traceable through governance/audit records.
