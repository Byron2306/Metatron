# Metatron / Seraph System-Wide Evaluation

**Updated:** 2026-05-01
**Scope:** Repository-wide implementation review based on current code paths.

## Executive summary

Metatron/Seraph is a broad, multi-domain security platform with a real FastAPI backend, React SOC dashboard, and large unified endpoint agent. The major product planes are present in code: endpoint control, AI-agentic detection, SOC workflows, SOAR, EDM/DLP, email gateway/protection, mobile/MDM, cloud posture, deception, identity, governance, and optional integrations.

The current assessment is that the platform is feature-rich and increasingly coherent, but its risk profile is dominated by consistency and assurance issues: route-contract drift, broad optional dependency behavior, legacy compatibility paths, governance-state durability, and security regression depth.

## Current metrics

| Metric | Current repository evidence |
| --- | --- |
| Backend router modules | 62 files under `backend/routers/` |
| Backend service modules | 32 files under `backend/services/` plus domain engines in `backend/` |
| Frontend page modules | 69 JSX/TSX page files under `frontend/src/pages/` |
| Unified agent source | `unified_agent/core/agent.py`, a large cross-platform monitor/remediation runtime |
| Primary API root | `/api` in `backend/server.py` |
| Native v1 surfaces | Selected routers with `/api/v1` prefixes, including CSPM, identity, attack paths, secure boot, and kernel sensors |
| Compose ports | Backend `8001`, frontend `3000`, MongoDB `27017`, Redis `6379`, optional WireGuard `51820/udp` |

## Category assessment

| Category | Status | Current logic |
| --- | --- | --- |
| Endpoint / EDR | Strong | Unified agent monitors process, network, registry, DLP/EDM, ransomware, rootkit/kernel, identity, CLI, email, mobile, and WebView2 signals. |
| Agent control plane | Strong | `/api/unified/*` handles registration, heartbeats, telemetry, commands, deployment, EDM datasets/rollouts, alerts, stats, and downloads. |
| SOC dashboard | Strong | React workspaces consolidate command, investigation, response, detection engineering, email security, and endpoint mobility views. |
| AI-agentic defense | Strong architecture | AATL/AATR, cognition, governed dispatch, triune routers, and AI reasoning modules exist; quality depends on runtime data and tests. |
| Response / SOAR | Strong | Quarantine, response, ransomware, SOAR, deception, honey token, and command paths are implemented. |
| Data protection / EDM | Strong | Dataset governance, signature/readiness/rollback, agent matching, hit telemetry, and enhanced DLP are present. |
| Email protection / gateway | Strong | Backend service/router and workspace UI exist for email analysis, authentication checks, quarantine, policy, block/allow lists, and test processing. |
| Mobile / MDM | Strong framework | Mobile security plus Intune, JAMF, Workspace ONE, and Google Workspace connector framework are implemented; live value depends on credentials/integration setup. |
| CSPM / cloud | Strong framework | Multi-cloud scanners and `/api/v1/cspm` surface exist; production scale and credential setup remain environment-dependent. |
| Browser isolation | Partial | URL analysis, filtering, sanitization, sessions, and modes exist; full remote pixel-stream isolation depth remains limited. |
| Governance / enterprise controls | Strong architecture, partial durability | Policy, token, tool gateway, SIEM, telemetry chain, identity, and multi-tenant modules exist; HA/durability and bypass-resistance need continued hardening. |

## Current architecture summary

1. `docker-compose.yml` starts the core stack and optional integrations.
2. `backend/server.py` initializes MongoDB, binds services, configures CORS, mounts routers, and starts background tasks.
3. `frontend/src/App.js` defines the protected UI shell and redirects legacy pages to canonical workspaces.
4. `frontend/src/lib/api.js` chooses a valid configured backend URL or same-origin `/api`.
5. `unified_agent/core/agent.py` performs endpoint monitoring/remediation and communicates with backend control-plane routes.
6. `backend/routers/unified_agent.py` projects agent state into world entities and emits world events for downstream intelligence.

## Strategic risk register

| Risk | Severity | Notes |
| --- | --- | --- |
| Contract drift | High | Many routers and pages move quickly; API/client schema checks need enforcement. |
| Governance-state durability | High | Some governance-sensitive concepts need stronger persistence and scale semantics. |
| Optional integration ambiguity | Medium | Degraded mode should be explicit for SIEM, AI, sandbox, MDM, SMTP, CSPM credentials, and security tools. |
| Legacy path sprawl | Medium | Compatibility redirects/adapters are useful but increase maintenance burden. |
| Security regression depth | Medium | Denial-path, bypass-resistance, RBAC, and audit-chain tests should continue expanding. |

## Bottom line

The platform has moved beyond a narrow prototype into a large integrated security fabric. The next work should focus less on adding new domains and more on making existing domains deterministic, contract-tested, durably governed, and operationally clear.
