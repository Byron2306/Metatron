# Metatron Feature Reality Matrix

Generated: 2026-03-04
Scope: Runtime truth validation (not just route wiring)

## Legend
- **PASS**: executes real logic in current environment
- **PARTIAL**: real implementation exists but requires missing runtime deps/config
- **FAIL**: mostly simulated, synthetic, or not runnable in current environment

## Acceptance Snapshot (Option A)

- Scope: `backend/tests/test_audit_timeline_openclaw.py`, `backend/tests/test_unified_agent_hunting.py`, `backend/tests/test_vpn_zerotrust_browser.py`, `backend/tests/test_agent_download.py`
- Result: **94 passed, 5 skipped, 0 failed** (2026-03-04)
- Notes:
   - Integration tests were aligned to current backend response contracts (list-vs-object shapes, permission semantics, and current download artifact behavior).
   - Non-deterministic offline-agent WebSocket behaviors are now asserted as expected non-success statuses instead of legacy queued-only assumptions.
   - Prior `PytestReturnNotNoneWarning` issues were removed in VPN/browser tests.

## Reality Matrix

| Domain | Status | Evidence | Notes |
|---|---|---|---|
| Targeted acceptance subset health | PASS | Option A rerun of 4 integration suites produced `94 passed, 5 skipped, 0 failed` | Confirms post-hardening contract alignment for audit, unified hunting, VPN/zero-trust/browser, and agent download flows. |
| MCP tool bus execution | PASS/PARTIAL | `services/mcp_server.py` now has built-in handlers for all registered MCP built-in tools and fails unregistered handlers by default; simulation requires `MCP_ALLOW_SIMULATED_EXECUTION=true` | Core handler coverage is in place; high-impact actions use safe dry-run defaults unless explicitly invoked with `execute=true`. |
| Vector memory | PASS | In-memory semantic store/retrieve, case creation, trust labels, PII redaction in `services/vector_memory.py` | Functional, but not external vector DB-backed. Data resets on restart. |
| AATL (autonomous threat layer) | PASS | Heuristic engine, lifecycle/intent scoring in `services/aatl.py` | Real local reasoning; no external model requirement. |
| AATR (AI threat registry) | PASS | Static defensive registry in `services/aatr.py` | Works as local intelligence catalog. |
| AI reasoning core | PARTIAL | Rule-based analysis works; Ollama path present but disconnected (`status: disconnected`) | LLM augmentation is optional and currently unavailable in runtime probe. |
| AI command recommendation | PARTIAL | `routers/agent_commands.py` uses Ollama JSON parse then rule fallback | Works, but likely fallback mode unless Ollama reachable. |
| Hunting hypothesis generation | PARTIAL | `routers/hunting.py` uses Ollama then rule fallback | Works, but usually fallback mode without Ollama. |
| Correlation AI enrichment | PARTIAL | `routers/correlation.py` enriches with `ai_reasoning.ollama_analyze_threat` with graceful fallback | Correlation runs; AI text quality depends on Ollama availability. |
| Browser isolation | FAIL | `browser_isolation.py` performs URL heuristics + HTML regex sanitization; no actual remote browser VM/stream pipeline | Good pre-filter/sanitizer utility, not true remote browser isolation implementation. |
| Container scanner (Trivy/runtime monitor) | PARTIAL | Real Trivy/docker commands in `container_security.py`; runtime path fallback works, but Trivy binary may be missing (`Trivy not found - container scanning disabled`) | Feature is real; primary blockers are host tool availability and permissions for deep container/runtime access. |
| EDR modules | PARTIAL | Real psutil/FIM/Volatility logic in `edr_service.py`; module import now succeeds with runtime path fallback | Implementation is present; full efficacy still depends on optional host tools/privileges. |
| Honeypots | PARTIAL | `routers/honeypots.py` records interactions and emits alerts/threat docs in DB | Event ingestion works; no built-in network honeypot daemon deployment. |
| Honey tokens | PASS | `honey_tokens.py` realistic token generation + hash matching + critical access recording | Functional deception detector in app plane. |
| Ransomware protection | PARTIAL | Canary + behavioral detector + protected folders in `ransomware_protection.py`; runtime path fallback initializes writable storage | Logic is real; runtime quality still depends on host filesystem coverage and monitoring privileges. |
| Network scan realism | PARTIAL | Real discovery stack in `services/network_discovery.py` (nmap/subprocess/ARP cache fallbacks) | In this container probe, no non-loopback interfaces were discovered (`INTERFACES 0`). |
| Kibana auth/config path | PARTIAL | Service supports API key **or** basic auth in `kibana_dashboards.py`; runtime probe showed unconfigured | Auth handling is implemented; requires env/config to be active. |
| Enterprise trust (identity/policy/token/telemetry) | PASS | Policy decisions, token issue/validate, telemetry hash-chain verified, tool gateway subprocess execution succeeded | Mostly in-memory state by default; durable backing not enforced by default. |
| OpenClaw gateway config/test path | PASS | Config + connectivity endpoints in `routers/openclaw.py`; health probe path exists | Operationally optional, but control path is implemented. |
| OpenClaw threat-response analyze path | PASS | `routers/response.py` maps `target_ip` with legacy fallback from `target_system` | Contract mismatch resolved. |
| Unified agent register/heartbeat/stats | PASS | Real DB-backed registration, heartbeat, command queueing in `routers/unified_agent.py` | Core unified control-plane functions are real. |
| Unified command UI→API contract parity | PASS | `frontend/src/pages/UnifiedAgentPage.jsx` sends canonical payload and backend remains backward-compatible | Command dispatch path aligned and resilient to legacy callers. |
| Unified deployment execution realism | PASS/PARTIAL | `routers/unified_agent.py` queues real tasks via `AgentDeploymentService` and syncs against `deployment_tasks` | Real deployment state is tracked; success still depends on credentials/connectivity. |
| WinRM push deployment | PARTIAL | Real implementation in `services/agent_deployment.py` using `pywinrm` + NTLM + port 5985 | Requires strict credentials/package/network prerequisites. |
| Swarm groups/tags/device assignment | PASS | `/swarm/groups`, `/swarm/tags`, and device assignment endpoints exist and are consumed by Swarm UI | End-to-end path verified. |
| Threat response route/UI integration | PASS | Threat response endpoints and UI calls align for stats/history/settings/block/unblock | Effectiveness depends on host firewall privileges and optional integrations. |
| Zero-trust runtime durability | PASS/PARTIAL | `routers/zero_trust.py` now hydrates engine state from Mongo and persists device/policy/access-log writes | Durable behavior improved significantly; engine still uses in-memory cache between syncs. |
| Timeline/Threats/Alerts integration | PASS | Backend routes and frontend pages align for list/detail/update/export flows | Core SOC incident narrative pipeline is wired. |
| Frontend API base-url consistency | PASS/PARTIAL | Page-level API constants normalized to resilient fallback behavior (`/api` or trimmed base URL) | Selective page breakage risk greatly reduced; remaining consistency work is helper consolidation. |
| Deployment validation script accuracy | PASS | `scripts/validate_deployment.sh` probes `/api/zero-trust/stats` | False-negative Zero Trust deployment signal fixed. |
| Legacy script endpoint alignment | PASS | Script call-sites are migrated to canonical `/api/swarm` and `/api/unified` routes (including `scripts/seraph_builder.sh`) while legacy aliases remain for compatibility telemetry | Endpoint drift risk is materially reduced for active installer/deployer script families. |
| Legacy cloud event path alignment | PASS | Legacy script families now send to canonical `/api/agent/event` path | Event ingestion contract aligned. |
| Legacy forensics retrieval path resilience | PASS | `backend/server_old.py` now resolves forensics path via `ensure_data_dir("forensics")` | Legacy read-path now honors writable fallback strategy and avoids hardcoded `/var/lib` assumptions. |
| Auxiliary unified server deployment realism | PARTIAL | `unified_agent/server_api.py` now marks deployment as `manual_required` instead of simulated completion | Secondary stack is now truth-preserving, but still lacks real remote install execution. |
| Script/default URL coherence (8001/8002/cloud) | PASS/PARTIAL | Core script families and unified-agent auxiliary utilities now normalize/parameterize server defaults (`METATRON_API_URL`, `METATRON_SERVER_URL`, `METATRON_BACKEND_URL`, `METATRON_UNIFIED_URL`) with canonical localhost:8001 baseline | Operator and helper/test paths are coherent; residual hardcoded localhost defaults may remain in non-runtime docs/snippets. |
| MCP signed-message hardening default | PASS/PARTIAL | `services/mcp_server.py` now resolves signing key with weak-key detection, ephemeral fallback, and strict-mode startup failure for weak keys | Production/strict mode is hardened; non-strict mode still allows ephemeral keys for development usability. |

## Direct Runtime Probe Highlights

1. MCP execution now uses registered built-in handlers:
   - `handlers_registered 6`
   - network scan, SOAR playbook, and deception deployment return non-simulated outputs
   - destructive actions (process kill, firewall block, memory dump) default to explicit dry-run unless `execute=true`
2. Quantum status reported simulation mode:
   - `mode: simulation` with install note for `liboqs-python`
3. Ollama status disconnected:
   - `status: disconnected`, URL `http://localhost:11434`
4. Runtime path fallback engaged for data directories:
   - services initialize under `/tmp/anti-ai-defense/...` when primary path is unwritable
   - optional scanner dependencies may still be unavailable (for example `Trivy not found`)
5. Enterprise tool gateway executed real process command successfully:
   - `process_list` returned `exit_code: 0`

## High-Impact Gaps To Address Next

1. **Filesystem permissions and runtime paths**
   - Ensure writable `/var/lib/anti-ai-defense` (or configurable app-local path) for container/EDR/ransomware modules.
2. **MCP action hardening beyond coverage**
   - Keep destructive MCP actions behind explicit execution controls and strengthen approval/token enforcement before non-dry-run execution.
3. **Browser isolation hardening**
   - Add true remote rendering/session brokering (isolated browser worker/VM), not only URL/HTML sanitization.
4. **Ollama operationalization**
   - Deploy/reachability for configured Ollama endpoint and model pull health checks.
5. **Persistent backends for trust plane**
   - Persist policy/token/telemetry state beyond in-memory process lifecycle.

## Bottom Line

- Many subsystems are **implemented but environment-dependent** (PARTIAL).
- A few are **fully functional now** (vector memory, honey tokens, enterprise trust primitives).
- Some marketed features are currently **proxy-level or depth-limited** (browser isolation depth, optional integration readiness).

---

## Consolidated Alignment Notes (2026-03-04)

This matrix now aligns directly with:
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/RUN_MODE_CONTRACT.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`

Priority interpretation across all artifacts:
1. **Highest urgency:** close remaining realism gaps (auxiliary deployment stack execution and browser-isolation depth).
2. **Next:** improve operational consistency (stricter runtime preflight checks and consolidation of URL helper utilities across all clients).
3. **Then:** deepen durability/quality loops (zero-trust persistence semantics and detection quality benchmarking).
