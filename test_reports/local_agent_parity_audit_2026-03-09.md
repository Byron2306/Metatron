# Local Agent Parity Audit (2026-03-09)

## Scope
This audit compares:
- Remote admin/control plane capabilities (backend + port 3000 UI)
- Local endpoint capabilities in the unified agent codebase
- Local dashboard wiring on localhost:5000

## Executive Verdict
- Local monolithic agent core is operational at monitor level: 25/25 monitor scans execute in a one-pass runtime smoke test.
- Previously failing CLI telemetry NameError due to HAS_PSUTIL was fixed by switching to PSUTIL_AVAILABLE.
- There is an architecture split on localhost:5000:
  - Substantive Flask UI uses desktop core (main.py) via WebAgentBridge.
  - Monolithic agent.py has its own different built-in LocalWebUIServer.
- Remote features like Trivy/Falco/Suricata/CSPM/MCP are primarily backend-side services and are not fully replicated as local endpoint engines.

## Runtime Evidence Summary
- UnifiedAgent initialization succeeds and registers 25 monitors.
- One-pass scan execution result:
  - OK: process, network, registry, process_tree, lolbin, code_signing, dns, memory, whitelist, dlp, vulnerability, yara, ransomware, rootkit, kernel_security, self_protection, identity, auto_throttle, firewall, hidden_file, alias_rename, priv_escalation, cli_telemetry, email_protection, mobile_security
  - FAIL: none

## Architecture Reality (Important)
- Flask local UI imports desktop core:
  - unified_agent/ui/web/app.py:70
  - unified_agent/ui/web/app.py:139
  - unified_agent/ui/web/app.py:148
- Monolithic core has separate built-in UI server:
  - unified_agent/core/agent.py:14118
  - unified_agent/core/agent.py:15429
- Remote admin UI is aggregate control plane and links out to local UI URLs:
  - frontend/src/pages/UnifiedAgentPage.jsx:106
  - frontend/src/pages/UnifiedAgentPage.jsx:558
  - frontend/src/pages/UnifiedAgentPage.jsx:559
  - backend/routers/unified_agent.py:3915
  - backend/routers/unified_agent.py:678
  - backend/routers/unified_agent.py:679

## Feature Parity Matrix

### 1) Endpoint monitor stack (local)
- Expected local behavior:
  - Monitors execute locally and feed local dashboard + heartbeat telemetry.
- Actual:
  - 25 monitors are instantiated in monolithic core.
  - All monitor scan paths run in one-pass smoke execution.
- Evidence:
  - unified_agent/core/agent.py:14464
  - unified_agent/core/agent.py:14520
  - unified_agent/core/agent.py:11823
  - unified_agent/core/agent.py:12933
- Status: Working
- Required changes:
  - Add regression test that runs all monitor.scan once under Linux.

### 2) YARA local scanning
- Expected local behavior:
  - Rules load/compile and scans are callable from local UI and heartbeat summaries.
- Actual:
  - YARAMonitor present and wired in monolithic core.
  - Local /api/yara and /api/yara/scan exist in monolithic LocalWebUIServer.
  - Remote aggregate stats now include YARA summary fields in unified stats/monitors.
- Evidence:
  - unified_agent/core/agent.py:13709
  - unified_agent/core/agent.py:14374
  - unified_agent/core/agent.py:15030
  - backend/routers/unified_agent.py:3939
  - backend/routers/unified_agent.py:4041
  - frontend/src/pages/UnifiedAgentPage.jsx:106
- Status: Working (monolithic path), Partial (5000 depends on which app is launched)
- Required changes:
  - Standardize localhost:5000 entrypoint to one UI/core path.

### 3) Kernel/email/local security monitors in local UI
- Expected local behavior:
  - Kernel, email, identity, ransomware, etc. visible and actionable in local dashboard.
- Actual:
  - Flask Web UI exposes dedicated routes for kernel/email/monitor stats.
  - Monolithic LocalWebUIServer is more limited and not equivalent to Flask feature surface.
- Evidence:
  - unified_agent/ui/web/app.py:2300
  - unified_agent/ui/web/app.py:2347
  - unified_agent/ui/web/app.py:2279
  - unified_agent/core/agent.py:15015
- Status: Partial due to split UI implementations
- Required changes:
  - Unify dashboard implementation around one core (preferred: monolithic core), or
  - Keep both and explicitly document support matrix + startup scripts.

### 4) Remote aggregate UI (port 3000)
- Expected behavior:
  - Aggregate all agents and fleet monitor telemetry, not replace endpoint-local UI depth.
- Actual:
  - Correct by design. Pulls /api/unified/stats/monitors and presents fleet controls.
  - Supports local_ui_url deep links per endpoint.
- Evidence:
  - frontend/src/pages/UnifiedAgentPage.jsx:106
  - frontend/src/pages/UnifiedAgentPage.jsx:558
  - backend/routers/unified_agent.py:3915
- Status: Working as aggregator
- Required changes:
  - None architectural. Continue adding aggregate fields as monitors evolve.

### 5) Trivy/Falco/Suricata
- Expected behavior (from remote stack intent):
  - These are remote backend/container security services; local agent can consume/emit related events.
- Actual:
  - Backend implements these heavily; local unified_agent package has no full local engine integration.
- Evidence:
  - backend/container_security.py:56
  - backend/container_security.py:715
  - backend/routers/agents.py:119
  - backend/routers/agents.py:154
- Status: Remote-only core capability, local interaction is indirect/telemetry-driven
- Required changes (if local parity is desired):
  - Implement local connectors/adapters in unified_agent/core for scanner invocation or sensor ingestion.
  - Add monitor surfaces and heartbeat summary fields for those adapters.

### 6) Volatility
- Expected behavior:
  - If claimed as remote forensic capability, local agent should trigger/collect memory artifacts or requests.
- Actual:
  - No concrete volatility integration located in unified_agent package.
- Status: Missing locally
- Required changes:
  - Add memory forensics adapter monitor and backend command type contract.

### 7) CSPM/Cloud posture
- Expected behavior:
  - Primarily server-side; local agent may provide cloud metadata if endpoint context is required.
- Actual:
  - CSPM is backend API/service owned.
- Evidence:
  - backend/routers/cspm.py:49
- Status: Remote-owned feature; local parity not implemented (and may not be required by design)
- Required changes (optional):
  - Add endpoint cloud-context collector only if needed by CSPM model.

### 8) MCP tooling
- Expected behavior:
  - Backend MCP orchestration sends commands to agents; agents execute supported command types.
- Actual:
  - Monolithic core has command poll + execute/report loop.
  - Backend has full MCP server and tool catalog.
  - Direct tool parity at endpoint is command-type dependent, not full MCP server on endpoint.
- Evidence:
  - unified_agent/core/agent.py:15073
  - unified_agent/core/agent.py:15094
  - backend/routers/advanced.py:99
  - backend/services/mcp_server.py:1832
- Status: Partial integration (orchestration path exists, endpoint tool parity limited)
- Required changes:
  - Define and version a strict command contract matrix: MCP tool -> agent command_type -> implementation.

## Critical Gaps To Fix First
1. Dual localhost:5000 implementations (desktop-core Flask UI vs monolithic LocalWebUIServer) causing parity ambiguity.
2. No explicit endpoint adapters for Trivy/Falco/Suricata/Volatility if true local parity is desired.
3. Missing explicit backend-to-agent command contract coverage tests for MCP-to-command mappings.

## Recommended Remediation Plan
1. Stabilize monolithic runtime:
  - Keep the HAS_PSUTIL -> PSUTIL_AVAILABLE fix and add full one-pass scan regression in CI.
2. Decide 5000 ownership:
   - Option A: Make Flask UI consume monolithic UnifiedAgent core.
   - Option B: Keep both but give separate ports and explicit product naming.
3. Define parity contract document:
   - For each remote feature, mark local role as one of: local engine, local sensor, command executor, or remote-only.
4. Add backend-to-agent contract tests:
   - Validate heartbeat monitors_summary includes expected keys.
   - Validate command execution for mapped MCP tool families.

## Current Confidence
- Local endpoint security monitors: High (post-fix one-pass scan success 25/25).
- Local dashboard parity with claimed full feature set: Medium (split-core architecture).
- Remote-to-local integration parity for Trivy/Falco/Suricata/Volatility/CSPM/MCP: Medium-Low without explicit adapters and contract tests.
