# Metatron Feature Reality Matrix

**Updated:** 2026-05-01
**Scope:** Quantitative implementation snapshot aligned to current code paths.

## Legend

- `PASS`: Real logic exists in the normal configured code path.
- `PARTIAL`: Real implementation exists but depends on optional services, credentials, scale hardening, or additional assurance.
- `LIMITED`: Capability exists as a reduced-depth, compatibility, local-demo, or fallback path.

## Maturity score table

| Domain | Score | Status | Evidence |
| --- | ---: | --- | --- |
| Backend API composition | 8.5 | PASS/PARTIAL | `backend/server.py`, `backend/routers/` |
| Frontend route/workspace wiring | 8.5 | PASS/PARTIAL | `frontend/src/App.js`, `frontend/src/pages/` |
| Unified agent control plane | 9.0 | PASS | `backend/routers/unified_agent.py` |
| Unified endpoint agent | 8.5 | PASS/PARTIAL | `unified_agent/core/agent.py` |
| EDM governance and telemetry | 9.0 | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` |
| DLP and data protection | 8.5 | PASS/PARTIAL | `backend/enhanced_dlp.py`, agent monitors |
| Email protection | 8.5 | PASS/PARTIAL | `backend/email_protection.py`, email workspace |
| Email gateway | 8.0 | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` |
| Mobile security | 8.0 | PASS/PARTIAL | `backend/mobile_security.py`, mobile workspace |
| MDM connectors | 8.0 | PASS/PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` |
| Cloud posture (CSPM) | 8.0 | PASS/PARTIAL | `backend/cspm_engine.py`, cloud scanner modules |
| Identity and zero trust | 8.0 | PASS/PARTIAL | `backend/routers/identity.py`, `backend/zero_trust.py` |
| SOAR, response, quarantine | 8.0 | PASS/PARTIAL | `backend/soar_engine.py`, `backend/threat_response.py`, `backend/quarantine.py` |
| Deception, honeypots, honey tokens | 8.0 | PASS/PARTIAL | `backend/deception_engine.py`, routers |
| AI-agentic defense | 8.0 | PASS/PARTIAL | `backend/services/aatl.py`, `aatr.py`, `cce_worker.py` |
| Triune cognition/governance | 7.5 | PARTIAL | `backend/triune/`, `backend/services/governance_*` |
| Kernel and secure boot surfaces | 7.5 | PARTIAL | `backend/enhanced_kernel_security.py`, `ebpf_kernel_sensors.py`, `secure_boot_verification.py` |
| Browser isolation | 6.5 | PARTIAL | `backend/browser_isolation.py` |
| Optional integrations | 7.0 | PARTIAL | `unified_agent/integrations/`, compose profiles |
| Verification depth | 7.0 | PARTIAL | `backend/tests/`, `unified_agent/tests/`, `test_reports/` |

## Current reality matrix

| Area | Status | What is real | Practical caveat |
| --- | --- | --- | --- |
| API router mesh | PASS | 62 router modules mounted by `backend/server.py`. | Central startup remains dense and sensitive to optional import behavior. |
| React dashboard | PASS/PARTIAL | 69 page modules and workspace routes with legacy redirects. | Some older pages are compatibility shells or redirected surfaces. |
| Agent registration/heartbeat | PASS | `/api/unified/*` handles registration, heartbeat, fleet state, stats, alerts, commands, installers, and WebSocket paths. | Fleet-scale behavior depends on database and operational deployment discipline. |
| Monitor summary ingestion | PASS | `MONITOR_TELEMETRY_KEYS` canonicalize endpoint monitor status. | Additional monitor detail may need schema governance as agent modules evolve. |
| EDM rollout | PASS | Dataset metadata, versioning, rollout, telemetry, readiness, and rollback paths exist. | Production governance should keep signature and contract tests in CI. |
| Email gateway | PASS/PARTIAL | Process, quarantine, policy, blocklist, allowlist, and stats APIs exist. | Production SMTP relay credentials/topology are environment-specific. |
| MDM | PASS/PARTIAL | Connector management, sync, device/policy listing, and device action APIs exist. | Live sync requires vendor credentials and API access. |
| CSPM | PASS/PARTIAL | Multi-cloud engine/scanners and `/api/v1/cspm` surface exist. | Cloud credentials and provider permissions determine real scan depth. |
| Deception | PASS/PARTIAL | Deception router mounted under `/api/deception` and `/api/v1/deception`. | Real containment depends on integrated downstream action paths. |
| Governance | PARTIAL | Policy/token/tool/telemetry concepts and governed dispatch services exist. | Some governance-sensitive state still needs stronger durability and restart semantics. |
| Local unified-agent UI | PASS/PARTIAL | Agent-side FastAPI, Flask dashboard, desktop tray, and native shell directories exist. | Local surfaces are secondary to central dashboard and may have demo/in-memory stores. |
| Integrations | PARTIAL | Many integration adapters/parsers are present under `unified_agent/integrations/`. | External tools and credentials determine runtime availability. |
| Browser isolation | LIMITED/PARTIAL | URL analysis, session, sanitization, and isolation-mode APIs exist. | Full remote browser pixel-streaming depth is not leader-grade. |

## Current code-logic updates that changed the summary

1. Root README counts were stale; current repository evidence shows 62 backend router modules and 69 frontend page modules.
2. `/api/unified/*` is the canonical agent control plane; older `/agents`, `/swarm`, and `/agent-commands*` dashboard paths redirect to `/unified-agent`.
3. Email and mobile UX is now workspace-oriented through `/email-security` and `/endpoint-mobility`, while old direct routes redirect to tabs.
4. `frontend/src/lib/api.js` supports same-origin `/api` by default and avoids invalid localhost targets from remote browsers.
5. Docker Compose uses backend port `8001` and frontend port `3000`, with MongoDB and Redis as core infrastructure and several optional integrations.
6. `unified_agent/server_api.py` is a secondary local agent-side API surface, not the main product backend.

## Remaining gaps

1. Contract governance across the broad router/page surface.
2. Denial-path and bypass-resistance tests for security-critical routes.
3. Durable governance state for policy, token, approval, and tool execution workflows.
4. Production credentials and live integration coverage for SMTP, MDM, cloud, SIEM, sandbox, and security tools.
5. Anti-tamper, signed-update, and endpoint hardening depth.
6. Clear degraded-mode reporting for every optional integration.

## Bottom line

The implementation is real and broad. Current maturity is best described as **advanced platform in hardening and assurance phase**: strong feature coverage exists, but production trust depends on contract discipline, integration configuration, operational hardening, and repeatable verification.
