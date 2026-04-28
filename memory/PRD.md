# Seraph AI Defense System - Product Requirements Document

Updated: 2026-04-28
Source basis: direct repository review of `backend/server.py`, `backend/routers/`, `backend/services/`, `frontend/src/App.js`, `unified_agent/`, `docker-compose.yml`, and committed validation reports.

## Product overview

Seraph / Metatron is an adaptive cybersecurity platform focused on AI-era defense, endpoint telemetry, SOC workflows, governed automation, deception, and multi-domain security operations. The current product combines a central FastAPI backend, React operator UI, unified endpoint agent, local agent UIs, Triune cognition services, governance controls, and a broad integration framework.

## Current product state

The repository currently implements:

- A primary backend API in `backend/server.py` on port 8001.
- 61 backend router modules and 32 service modules.
- A React/Craco frontend with 63 `*Page` files and route consolidation through workspace pages.
- A unified endpoint agent with broad monitor families and backend `/api/unified/*` control-plane routes.
- Triune cognition using Metatron, Michael, Loki, world model/events, cognition fabric, and governance gates.
- Governance and high-impact action controls using authority, outbound gate, executor, token broker, tool gateway, MCP server, and tamper-evident telemetry.
- Security domains for SOC, EDR, threat intel, hunting, response/SOAR, deception, ransomware, cloud posture, identity, zero trust, email, mobile, MDM, VPN, browser isolation, sandboxing, detection engineering, and runtime integrations.

## Current route and UX model

Primary authenticated UX:

- `/command`: command/dashboard/alerts/threats workspace.
- `/world`: world model graph/view.
- `/ai-activity`: AI/cognition activity workspace.
- `/response-operations`: response, quarantine, EDR, SOAR workspace.
- `/investigation`: intelligence, correlation, attack path workspace.
- `/detection-engineering`: Sigma, atomic validation, MITRE workspace.
- `/email-security`: email protection and gateway workspace.
- `/endpoint-mobility`: mobile and MDM workspace.
- `/unified-agent`: fleet, agent, swarm, command, monitor, and installer workflows.

Legacy routes redirect into these workspaces where appropriate.

## Product requirements by area

### Core platform

1. Backend health, auth, and core SOC routes must be available under the documented `/api` contract.
2. Frontend must use shared API base resolution and avoid hard-coded backend URLs where possible.
3. Optional integrations must expose explicit degraded/unavailable states.
4. Documentation must state exact run modes and validation evidence for readiness claims.

### Unified agent

1. Agents must be able to register, heartbeat, submit telemetry, and receive commands.
2. Monitor summaries must be projectable into world entities and audit/world-event streams.
3. Installer/download endpoints must remain aligned with backend deployment paths.
4. Local web/desktop UIs must remain clearly separate from the central backend API.

### Governance and Triune

1. High-impact actions must route through governance decision, queue/approval, executor, token/tool enforcement, and audit linkage.
2. World events must trigger Triune/cognition recompute when severity and policy require it.
3. Terminal execution outcomes should include decision, queue, token, execution, audit, and world-event identifiers where applicable.

### Security domains

1. Email gateway/protection, mobile/MDM, CSPM, identity, response, and integrations must state credential/tool requirements.
2. Runtime integrations must fail explicitly when tools, logs, containers, or targets are unavailable.
3. Browser isolation should be positioned as URL analysis/filtering unless remote isolation is implemented and validated.
4. Endpoint monitor capabilities must be documented per OS/privilege requirement.

## Non-goals and cautions

- Do not claim full incumbent XDR parity without detection-quality, scale, and assurance evidence.
- Do not treat queued or simulated work as verified success.
- Do not use `python3 smoke_test.py` as canonical validation; it is not a simple smoke-test script in the current repo.
- Do not present optional integration failures as core platform failures unless the selected run mode requires them.

## Release acceptance criteria

A release should be considered documentable as current only when:

1. Backend route inventory, frontend route inventory, and API clients are checked for drift.
2. Core run mode passes `/api/health`, frontend load, login, and representative SOC route checks.
3. Unified-agent register/heartbeat/command or monitor flows are validated for the target OS/runtime.
4. High-impact mutating flows demonstrate governance and audit linkage.
5. Optional integration docs list prerequisites and degraded behavior.
6. README and memory review documents are updated with exact code evidence and avoid stale counts.
