# Feature Reality Report

**Updated:** 2026-04-30  
**Scope:** Qualitative current-state report grounded in active code paths.

---

## Executive Verdict

Metatron / Seraph is a broad, working security platform with real implementations across the SOC backend, operator frontend, unified endpoint agent, AI/cognition services, world model, and governance-gated automation. The correct current framing is **implemented framework plus configurable runtime integrations**: many domains have active routers and services, while production value depends on credentials, external tools, and environment-specific deployment.

The most important current code logic is the shift from simple direct command dispatch toward a governed pipeline:

1. Agent/domain action is requested.
2. `GovernedDispatchService` asks `OutboundGateService` to gate the action.
3. The command is persisted with `gated_pending_approval` and decision metadata.
4. `/api/governance/decisions/...` approves or denies the decision.
5. `GovernanceExecutorService` releases approved work to command queues or executes supported domain operations.
6. World events and tamper-evident telemetry are emitted where configured.

## Reality by Domain

| Domain | Reality status | Current code evidence | Notes |
|---|---|---|---|
| Main backend API | Real | `backend/server.py`, `backend/routers/` | FastAPI v3 app, MongoDB-backed, 65 router registrations, app-level WebSockets. |
| Auth and user control | Real | `backend/routers/auth.py`, `backend/routers/dependencies.py` | JWT, bcrypt hashing, setup/admin flows, permission dependencies. |
| SOC operations | Real | Threat, alert, dashboard, network, hunting, report, audit, timeline, response routers | Breadth is high; maturity differs by feature and dependency. |
| Unified agent control | Real | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Registration, heartbeat, telemetry, monitors, EDM/DLP, command/deployment surfaces. |
| Governance and dispatch | Real and important | `backend/services/governed_dispatch.py`, `backend/routers/governance.py`, `backend/services/governance_executor.py` | High-impact command flow is explicitly gated and auditable. |
| Triune reasoning | Real orchestration with service-backed/stubbed persona boundaries | `backend/services/triune_orchestrator.py`, `backend/triune/`, `backend/routers/metatron.py`, `michael.py`, `loki.py` | World snapshot -> Metatron assessment -> Michael plan -> Loki challenge. |
| CCE / CLI cognition | Real worker | `backend/services/cce_worker.py`, `backend/services/cognition_engine.py` | Polls CLI command events, groups sessions, analyzes command velocity/intent, stores summaries. |
| World model | Real | `backend/services/world_model.py`, `backend/routers/world_ingest.py`, world events usage | Agents and events can project into graph/world state. |
| AATL/AATR | Real services | `backend/services/aatl.py`, `backend/services/aatr.py`, `backend/routers/ai_threats.py` | Initialized at startup and exposed via AI-threat routes. |
| Email security and gateway | Implemented framework | `backend/email_protection.py`, `backend/email_gateway.py`, routers, React workspace redirects | Production relay/reputation behavior depends on environment and credentials. |
| Mobile and MDM | Implemented framework | `backend/mobile_security.py`, `backend/mdm_connectors.py`, routers, endpoint mobility workspace | Live platform sync depends on real MDM credentials. |
| CSPM | Implemented framework | `backend/cspm_engine.py`, `backend/routers/cspm.py` | Multi-cloud posture surfaces exist; cloud access depends on credentials. |
| Deception | Real framework | `backend/deception_engine.py`, `backend/routers/deception.py` | Mounted under `/api/deception` and `/api/v1/deception` for compatibility. |
| Browser isolation | Partial | `backend/browser_isolation.py`, `frontend/src/pages/BrowserIsolationPage.jsx` | URL filtering/sanitization exists; full remote browser/pixel-streaming should not be implied. |
| Kernel/security sensors | Implemented framework | `backend/secure_boot_verification.py`, kernel sensor routers/services | Runtime depth depends on OS capabilities and privileges. |
| Frontend | Real | `frontend/src/App.js`, `frontend/src/components/Layout.jsx`, pages | React/Craco app with protected shell and consolidated workspaces. |
| Agent portal | Real separate API/UI | `unified_agent/server_api.py`, `unified_agent/ui/web/app.py` | Runs separately from main backend; docs should refer to `backend/server.py`, not legacy `server_old.py`. |
| Testing and guardrails | Real, improving | `backend/tests/`, `unified_agent/tests/`, `.github/workflows/`, guardrail script | Strongest on selected contract/durability/monitor paths. |

## What Works Best Today

- Backend route composition and health endpoint.
- Authenticated operator UI routing.
- Unified-agent telemetry, monitor summary, and world-state projection concepts.
- Governed dispatch and approval/denial flow.
- CLI session cognition worker logic.
- Static governance guardrails for mutating endpoint auth, shell execution, and queue-write discipline.
- Docker Compose orchestration for local/integration environments.

## What Is Conditional

- Production email relay behavior requires SMTP/server configuration and reputation/feed integrations.
- Live MDM synchronization requires platform credentials and API availability.
- Cloud posture findings require real cloud credentials and account scope.
- Kernel/eBPF-style behavior depends on host OS, privileges, and mounted devices/logs.
- AI/model-augmented quality depends on configured model services such as Ollama or other providers.
- Agent deployment success depends on network reachability, SSH/WinRM, target OS, and post-install heartbeat evidence.

## Reality-Driven Priority Actions

1. Keep documentation tied to active files, endpoints, and test evidence.
2. Expand contract tests beyond the highest-risk control-plane subset.
3. Add explicit runtime health/degraded-state schemas for optional integrations.
4. Continue routing all impactful commands through governed dispatch.
5. Normalize stale labels and comments that refer to old server names or old route structures.
6. Add more denial-path and restart/scale tests for governance and command execution.

## Final Reality Statement

The platform is real and substantial, but the most accurate claim is not that every advertised integration is production-complete out of the box. The accurate claim is that the repository contains a broad governed-defense framework with working APIs, UI flows, agent telemetry/control, cognition, world-state, and approval-gated automation, plus many integration modules whose production behavior depends on external configuration and validation.
