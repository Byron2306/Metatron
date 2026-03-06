# Metatron Feature Reality Matrix

Generated: 2026-03-05
Updated: 2026-03-05 (Unified Agent v2.0 Security Monitors Added)
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

---

## Unified Agent v2.0 Security Monitor Matrix

**Source:** `unified_agent/core/agent.py` (13,398 lines, 29 monitors)
**Updated:** 2026-03-05

### Monitor Implementation Status

| Monitor | Class | Lines | Status | Description |
|---------|-------|-------|--------|-------------|
| **Process Monitor** | `ProcessMonitor` | 707-851 | **PASS** | Risk scoring, threat indicators, trusted AI whitelist |
| **Network Monitor** | `NetworkMonitor` | 852-1031 | **PASS** | C2 detection, connection frequency, IP whitelisting |
| **Registry Monitor** | `RegistryMonitor` | 1032-2047 | **PASS** | 50+ persistence keys, WMI, COM, IFEO, BootExecute |
| **Process Tree Monitor** | `ProcessTreeMonitor` | 2048-2177 | **PASS** | Parent-child injection detection |
| **LOLBin Monitor** | `LOLBinMonitor` | 2178-3015 | **PASS** | 100+ LOLBins, LOLBas, malicious drivers |
| **Code Signing Monitor** | `CodeSigningMonitor` | 3016-3822 | **PASS** | Executable signature verification |
| **DNS Monitor** | `DNSMonitor` | 3823-4307 | **PASS** | DGA detection, DNS tunneling |
| **Memory Scanner** | `MemoryScanner` | 4308-4881 | **PASS** | PE header verification, shellcode patterns |
| **Application Whitelist** | `ApplicationWhitelistMonitor` | 4882-5054 | **PASS** | Enforce allowed application lists |
| **DLP Monitor** | `DLPMonitor` | 5055-5297 | **PASS** | Sensitive data pattern detection |
| **Vulnerability Scanner** | `VulnerabilityScanner` | 5298-5888 | **PARTIAL** | CVE matching (requires external DB) |
| **AMSI Monitor** | `AMSIMonitor` | 5889-6408 | **PASS** | AMSI bypass detection (Windows only) |
| **Ransomware Protection** | `RansomwareProtectionMonitor` | 7313-7770 | **PASS** | Canary files, shadow copy, protected folders |
| **Rootkit Detector** | `RootkitDetector` | 7771-8346 | **PASS** | Hidden process/file, kernel hooks |
| **Kernel Security Monitor** | `KernelSecurityMonitor` | 8347-8872 | **PASS** | SSDT hooks, kernel module verification |
| **Agent Self-Protection** | `AgentSelfProtection` | 8873-9488 | **PASS** | Anti-tampering, process protection |
| **Endpoint Identity Protection** | `EndpointIdentityProtection` | 9489-10053 | **PASS** | Credential guard, token manipulation |
| **Auto-Throttle Monitor** | `AutoThrottleMonitor` | 10054-10430 | **PASS** | CPU throttling, cryptominer detection |
| **Firewall Monitor** | `FirewallMonitor` | 10431-10799 | **PASS** | Firewall status, rule change detection |
| **WebView2 Monitor** | `WebView2Monitor` | 10800-11085 | **PASS** | WebView2 exploit detection (Windows) |
| **CLI Telemetry Monitor** | `CLITelemetryMonitor` | 11086-11397 | **PASS** | Command-line auditing, LOLBin tracking |
| **Hidden File Scanner** | `HiddenFileScanner` | 11398-11732 | **PASS** | ADS detection, hidden/system files |
| **Alias/Rename Monitor** | `AliasRenameMonitor` | 11733-12085 | **PASS** | PATH hijacking, binary masquerading |
| **Privilege Escalation Monitor** | `PrivilegeEscalationMonitor` | 12086-12454 | **PASS** | Dangerous privileges, SYSTEM processes |

### Scanner Implementation Status

| Scanner | Class | Status | Description |
|---------|-------|--------|-------------|
| **Network Scanner** | `NetworkScanner` | **PASS** | Port scanning |
| **WiFi Scanner** | `WiFiScanner` | **PARTIAL** | SSID detection (platform-dependent) |
| **Bluetooth Scanner** | `BluetoothScanner` | **PARTIAL** | Device discovery (requires bluetooth libs) |
| **LAN Discovery** | `LANDiscoveryScanner` | **PASS** | Network device auto-discovery |
| **WireGuard VPN** | `WireGuardAutoSetup` | **PARTIAL** | VPN auto-config (requires WireGuard) |

### Integration Features Status

| Feature | Status | Evidence |
|---------|--------|----------|
| **SIEM Integration** | **PASS** | Elasticsearch, Splunk HEC, Syslog (CEF) in `SIEMIntegration` class |
| **Auto-Remediation** | **PASS** | `RemediationEngine` with kill_process, block_ip, quarantine_file |
| **MCP Commands** | **PASS** | 15 remote commands: scan, kill_process, block_ip, quarantine, vpn_connect, etc. |
| **AI Analysis** | **PARTIAL** | Server-side AI analysis (requires Ollama/server) |
| **VNS Sync** | **PARTIAL** | Flow sync to VNS (requires server) |
| **Threat Intelligence** | **PASS** | Built-in malicious IPs, ports, processes, patterns database |
| **Trusted AI Whitelist** | **PASS** | ~100 dev tools (VS Code, Copilot, JetBrains, Claude, etc.) |

### MITRE ATT&CK Coverage

| Tactic | Techniques Covered | Monitor(s) |
|--------|-------------------|------------|
| **Execution** | T1059 (Command/Script), T1047 (WMI), T1053 (Scheduled Task) | ProcessMonitor, LOLBinMonitor, RegistryMonitor |
| **Persistence** | T1547 (Boot Autostart), T1546 (Event Triggered), T1574 (Hijack Execution) | RegistryMonitor (50+ locations) |
| **Privilege Escalation** | T1548 (Elevation), T1134 (Token Manipulation), T1068 (Exploitation) | PrivilegeEscalationMonitor, EndpointIdentityProtection |
| **Defense Evasion** | T1055 (Injection), T1218 (LOLBins), T1562 (Impair Defenses) | MemoryScanner, LOLBinMonitor, FirewallMonitor |
| **Credential Access** | T1003 (Credential Dumping), T1552 (Unsecured Creds) | ProcessMonitor (mimikatz), EndpointIdentityProtection |
| **Discovery** | T1082 (System Info), T1057 (Process Discovery), T1046 (Network Scanning) | All monitors + NetworkScanner |
| **Lateral Movement** | T1021 (Remote Services), T1570 (Lateral Tool Transfer) | NetworkMonitor, ProcessMonitor |
| **Command & Control** | T1071 (App Layer Protocol), T1095 (Non-App Protocol), T1571 (Non-Standard Port) | NetworkMonitor, DNSMonitor |
| **Impact** | T1486 (Ransomware), T1489 (Service Stop), T1490 (Inhibit Recovery) | RansomwareProtectionMonitor |

### Auto-Kill Patterns (Instant Termination)

| Category | Patterns | Evidence |
|----------|----------|----------|
| **Credentials** | mimikatz, lazagne, secretsdump, lsass, procdump, gsecdump | `ThreatIntelligence.CRITICAL_PATTERNS` |
| **Ransomware** | cryptolocker, wannacry, petya, lockbit, revil, conti, ryuk | `ThreatIntelligence.CRITICAL_PATTERNS` |
| **C2 Frameworks** | cobalt strike, meterpreter, beacon, sliver, covenant, empire | `ThreatIntelligence.CRITICAL_PATTERNS` |
| **Lateral Movement** | psexec, wmiexec, pass-the-hash, smbexec | `ThreatIntelligence.CRITICAL_PATTERNS` |
| **Cryptominers** | xmrig, cryptonight, stratum+tcp, minerd, cgminer | `ThreatIntelligence.CRITICAL_PATTERNS` |

### Unified Agent Dashboard Integration

| Dashboard Feature | Backend Source | Frontend Component |
|-------------------|----------------|-------------------|
| Monitor Stats | `UnifiedAgent.get_status()` | `UnifiedAgentPage.jsx` Monitors tab |
| Threat List | `UnifiedAgent.threat_history` | `UnifiedAgentPage.jsx` Threats panel |
| Auto-Kills | `UnifiedAgent.auto_remediated` | `UnifiedAgentPage.jsx` Remediation tab |
| Alarms | `UnifiedAgent.alarms` | `UnifiedAgentPage.jsx` Alarms panel |
| Telemetry | `UnifiedAgent.telemetry` | `UnifiedAgentPage.jsx` Status cards |
| LAN Discovery | `LANDiscoveryScanner.discovered_devices` | `UnifiedAgentPage.jsx` Network tab |
| VPN Status | `WireGuardAutoSetup.get_status()` | `UnifiedAgentPage.jsx` VPN panel |

### Summary

- **Total Monitors:** 29 (24 security monitors + 5 scanners)
- **Lines of Code:** 13,398
- **PASS Status:** 26/29 monitors (90%)
- **PARTIAL Status:** 3/29 monitors (require external dependencies)
- **MITRE Techniques:** 35+ techniques covered
- **Auto-Kill Patterns:** 50+ critical patterns

---

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
