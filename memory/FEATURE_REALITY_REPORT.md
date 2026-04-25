# Feature Reality Report

**Reviewed:** 2026-04-25  
**Scope:** Code-evidence narrative for implemented platform behavior, operational realism, and remaining conditional surfaces.  
**Primary evidence:** `backend/server.py`, `backend/routers/*`, `backend/services/*`, `frontend/src/App.js`, `unified_agent/core/agent.py`, `docker-compose.yml`, and current memory/test artifacts.

## Executive Verdict

Metatron/Seraph is a broad FastAPI + React + unified-agent security platform. The current codebase contains real route/service implementations across SOC operations, endpoint telemetry, AI-agentic detection, response automation, deception, cloud posture, email/mobile security, MDM integration, governance, and triune/world-model services.

The important correction from older summaries is that the platform should be described as **code-rich and integration-ready**, not universally production-complete. Several domains have substantial implementation logic, while others depend on live credentials, optional services, host capabilities, or importable integrations.

## Current Implementation Snapshot

| Surface | Current code-evidence snapshot |
|---|---:|
| Backend router modules | 61 files in `backend/routers` excluding `__init__.py` |
| Backend service modules | 32 files in `backend/services` excluding `__init__.py` |
| Router include calls | 65 `app.include_router(...)` calls in `backend/server.py`, including duplicate/versioned mounts |
| Frontend page imports | 43 page components imported by `frontend/src/App.js` |
| Frontend route entries | 67 `<Route>` entries, many redirecting legacy paths into workspaces |
| Docker Compose services | 21 services in root `docker-compose.yml` |
| Unified-agent backend telemetry keys | 24 first-class monitor telemetry keys in `backend/routers/unified_agent.py` |
| Unified-agent local monitors | 25+ runtime monitor entries depending on OS/config in `unified_agent/core/agent.py` |

## Architecture Reality

### Backend control plane

`backend/server.py` is the central FastAPI wiring point. It initializes MongoDB via Motor or optional `mongomock-motor`, configures CORS, sets router database dependencies, constructs world/triune services, registers routers, and starts background workers at application startup.

Key startup services include the CCE worker, network discovery, agent deployment, AATL/AATR initialization, integrations scheduler, and governance executor.

Most routers are mounted under `/api`. Some routers carry native `/api/v1` prefixes or are mounted in compatibility forms: CSPM, identity, tier-1 attack path/secure boot/kernel sensors routes, and the deception router.

### Frontend application model

`frontend/src/App.js` now routes operators into workspace pages instead of one page per historical feature. The index route redirects to `/command`. Major workspaces include `/command`, `/ai-activity`, `/investigation`, `/detection-engineering`, `/response-operations`, `/email-security`, `/endpoint-mobility`, `/world`, and `/unified-agent`.

Legacy paths such as `/dashboard`, `/alerts`, `/threats`, `/agents`, `/soar`, `/edr`, `/email-gateway`, and `/mdm` mostly redirect into these workspaces with tab query parameters.

### Unified agent

`unified_agent/core/agent.py` initializes monitors for process/network when enabled, then enterprise monitors such as registry, process tree, LOLBin, code signing, DNS, memory, application whitelist, DLP, vulnerability, YARA, ransomware, rootkit, kernel security, self-protection, identity, auto-throttle, firewall, CLI telemetry, hidden file, alias/rename, privilege escalation, email protection, and mobile security. Windows-specific monitors include AMSI and WebView2.

The backend unified-agent router exposes `/api/unified/*` and explicitly recognizes 24 first-class telemetry keys from `MONITOR_TELEMETRY_KEYS`.

## Domain Reality by Area

| Domain | Current status | Evidence | Practical interpretation |
|---|---|---|---|
| Core SOC workflows | Implemented | `threats.py`, `alerts.py`, `dashboard.py`, `timeline.py`, `audit.py`, `reports.py` | Real APIs and pages exist; data depth depends on configured sensors and DB contents. |
| Unified agent control plane | Implemented | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Registration, heartbeat, commands, EDM, downloads, and telemetry paths are present; high-impact commands are governance-aware. |
| AI-agentic detection | Implemented/conditional | `services/aatl.py`, `services/aatr.py`, `services/cognition_engine.py` | Core logic and API surfaces exist; detection quality depends on event volume, tuning, and optional model services. |
| Triune/world model | Implemented | `triune/*`, `routers/metatron.py`, `routers/michael.py`, `routers/loki.py`, `routers/world_ingest.py` | Services are instantiated at startup and exposed through routers. |
| Governance plane | Implemented/advancing | `routers/governance.py`, `services/governance_*`, `governed_dispatch.py` | Approval/execution loop exists; durability and denial-path assurance remain critical review areas. |
| Email protection | Implemented | `backend/email_protection.py`, `routers/email_protection.py`, `/email-security` workspace | Authentication checks, phishing/URL/attachment/DLP logic and UI routes are present. |
| Email gateway | Integration-ready | `backend/email_gateway.py`, `routers/email_gateway.py` | Gateway/quarantine/blocklist/allowlist/policy APIs exist; production SMTP relay requires live server configuration and validation. |
| Mobile security | Implemented | `backend/mobile_security.py`, `routers/mobile_security.py`, `/endpoint-mobility` workspace | Device/threat/compliance logic exists; live mobile fleet value depends on enrolled devices. |
| MDM connectors | Integration-ready | `backend/mdm_connectors.py`, `routers/mdm_connectors.py` | Intune/JAMF/Workspace ONE/Google connector framework exists; production sync requires tenant credentials and API access. |
| CSPM | Implemented/conditional | `backend/cspm_engine.py`, `routers/cspm.py` | Versioned `/api/v1/cspm` routes exist and scan paths are authenticated; cloud depth requires credentials. |
| Browser isolation | Partial | `backend/browser_isolation.py`, `routers/browser_isolation.py` | URL/session/filtering surfaces exist; full remote browser isolation/pixel streaming is still limited. |
| Kernel/security sensors | Conditional | `routers/kernel_sensors.py`, `routers/secure_boot.py`, `backend/enhanced_kernel_security.py` | Modules are present, but `server.py` disables tier-1 routers if imports fail and host capabilities are required. |
| Container/network tooling | Conditional | `container_security.py`, `routers/containers.py`, `vpn_integration.py`, Docker services | Trivy/Falco/Suricata/Zeek/WireGuard are wired in Compose; runtime evidence depends on container privileges and enabled services. |
| Sandbox | Conditional | `sandbox_analysis.py`, `routers/sandbox.py`, Cuckoo services | APIs and optional Cuckoo stack exist; full detonation depends on sandbox services and host setup. |

## Corrected Interpretation of What Works

Works as implemented code paths:

- FastAPI route mesh and React route/workspace shell.
- Authenticated platform workflows when MongoDB and backend are running.
- Unified-agent registration, heartbeat, installer/download, telemetry, EDM, and command-control surfaces.
- Email protection, email gateway framework, mobile security, and MDM connector APIs.
- Governance executor loop and governed dispatch hooks for sensitive agent actions.
- Docker Compose topology for local full-stack operation with core and optional services.

Works but remains conditional:

- Production SMTP relay behavior, which needs real relay/server configuration.
- Production MDM sync/action behavior, which needs valid tenant credentials and API permissions.
- CSPM, SIEM, sandbox, VPN, container runtime, and model-backed AI behavior, which require external services or privileged runtime configuration.
- Tier-1 routers for attack paths, secure boot, and kernel sensors, which can be disabled at import time.
- Browser isolation depth beyond URL/session filtering.

Should not be stated without qualification:

- Universal endpoint efficacy parity with leading EDR/XDR platforms.
- Complete compliance certification or audit-grade evidence coverage.
- Production completion of every Docker-profile integration in an arbitrary environment.
- Fixed historical counts from older docs; current counts should be regenerated from the codebase rather than copied forward.

## Remaining Gaps and Review Focus

1. **Contract governance:** Keep backend routes, frontend calls, scripts, and docs synchronized through generated inventories and tests.
2. **Durability:** Persist governance-critical decisions, approvals, tokens, and high-risk action evidence consistently across restarts and scale-out.
3. **Production integrations:** Validate SMTP, MDM, CSPM, SIEM, sandbox, VPN, and model integrations with real credentials and failure-mode tests.
4. **Security assurance:** Expand denial-path tests, bypass resistance tests, and regression coverage for auth, CORS, governance, and command execution.
5. **Detection quality:** Add replay/benchmark loops and suppression governance before claiming leader-grade precision.
6. **Operator run modes:** Keep required vs optional services explicit so degraded pages do not look like platform-wide failure.

## Bottom Line

The current platform is best summarized as an **advanced, feature-dense adaptive defense system with substantial implemented logic and a large integration surface**. It is strongest when described with file-backed precision: core APIs, workspaces, unified agent telemetry, triune/world services, governance hooks, and email/mobile/MDM frameworks are present. The next documentation and engineering emphasis should remain on truth alignment, contract assurance, durable governance, and production validation of optional integrations.
