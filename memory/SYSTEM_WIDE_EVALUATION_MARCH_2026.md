# Metatron / Seraph System-Wide Evaluation

## Current Code-Logic Snapshot (updated 2026-04-28)

Backend API is FastAPI version `3.0.0` in `backend/server.py`, served on `8001` with health at `/api/health`. The repo has 61 backend router modules plus package init, 32 backend service modules plus package init, 68 JSX frontend pages plus `GraphWorld.tsx`, 68 `<Route` occurrences in `frontend/src/App.js`, unified agent version `2.0.0`, and 63 backend test files. The authenticated frontend hub is `/command`. Root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack health test.


## Executive Summary

This updated system-wide evaluation replaces the earlier March 2026 static snapshot with the current repository logic. Seraph is a broad unified security platform made of a FastAPI backend, React operator console, MongoDB/Redis data layer, unified endpoint agent, and optional security-tool integrations.

The codebase demonstrates wide implemented coverage. The most important correction is that current counts and runtime contracts differ from older docs: backend health is `/api/health` on port `8001`, and the active UI hub is `/command`.

## Current Platform Coverage

| Category | Current status | Evidence |
|---|---|---|
| EDR / endpoint agent | Implemented | `unified_agent/core/agent.py`, `/api/unified/...`, unified-agent tests |
| SOC command console | Implemented | `/command`, command workspace routes, threats/alerts redirects |
| Investigation workflows | Implemented | `/investigation`, threat-intel/correlation/attack-path redirects |
| Response operations | Implemented | `/response-operations`, quarantine/response/SOAR/EDR redirects |
| Detection engineering | Implemented | `/detection-engineering`, Sigma/Atomic/MITRE redirects plus Zeek/osquery pages |
| Deception/ransomware | Implemented | deception, honeypot, honey-token, ransomware routers/services |
| Identity and zero trust | Implemented/partial | identity and zero-trust routers/services; production depth depends on config |
| CSPM/cloud posture | Implemented/partial | CSPM router/engine; requires cloud credentials for live findings |
| Email protection/gateway | Implemented/partial | email routers and `/email-security`; SMTP production relay remains deployment work |
| Mobile/MDM | Implemented/partial | mobile and MDM routers plus `/endpoint-mobility`; live sync requires platform credentials |
| AI/Triune/world model | Implemented/partial | Metatron/Michael/Loki routers, triune package, world model services |
| Integrations | Implemented/partial | backend integrations router and local agent integration runners |

## Runtime and Deployment Reality

- Full compose brings up backend, frontend, MongoDB, Redis, and optional service families.
- The backend container runs `uvicorn backend.server:app` on `8001`.
- Frontend is a Craco React app served on `3000` in development and by Nginx in the production image.
- Unified-agent local dashboard runs separately on port `5000` when launched.
- Optional security services should be treated as capability amplifiers, not core health requirements.

## Testing and Assurance Reality

Current test assets include 63 backend `test_*.py` files, unified-agent tests, contract-assurance workflow tests, unified-agent monitor regression workflow tests, and frontend `craco test` support. Assurance remains uneven relative to breadth, so contract, denial-path, degraded-mode, and high-risk-action coverage should continue to expand.

## Current Priority Themes

1. Contract integrity: keep route inventories, frontend call sites, and docs synchronized with `backend/server.py` and `frontend/src/App.js`.
2. Operational truth: validate success states with health, heartbeat, command result, or external evidence.
3. Degraded-mode clarity: standardize behavior for missing optional services.
4. Production integration readiness: document required credentials and services for SMTP, MDM, cloud, AI, SIEM, and sandbox domains.
5. Security assurance: expand auth, denial-path, policy, replay, and audit-chain regression tests.

## Conclusion

The platform is broad, active, and materially implemented. Its documentation should remain source-aligned: FastAPI on `8001`, React on `3000`, `/api` plus selected `/api/v1` routes, `/command` as the UI hub, `/api/unified` as the agent control plane, MongoDB/Redis as core data services, and optional integrations documented as conditional capabilities.
