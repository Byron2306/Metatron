# Security Features Analysis

Updated: 2026-04-26  
Scope: Code-evidence summary of implemented security capability surfaces.

## Summary

The repository implements a broad security platform with endpoint telemetry, SOC workflows, deception, email/mobile controls, cloud posture, zero trust concepts, triune governance, and advanced memory/reasoning services. Feature breadth is high; maturity varies by whether a capability is a durable control-plane workflow, an in-process engine, or an adapter requiring external infrastructure.

## Implemented capability map

| Domain | Evidence | Current status |
|---|---|---|
| Endpoint detection and response | `unified_agent/core/agent.py`, `backend/routers/edr.py`, `backend/edr_service.py` | Broad local monitor set and backend EDR surfaces are present. |
| Unified agent control | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Agent registration, telemetry, EDM, installers, commands, and command durability paths are implemented. |
| Command governance | `backend/services/outbound_gate.py`, `backend/services/governed_dispatch.py`, `backend/routers/governance.py` | High-impact agent, response, quarantine, swarm, and tool actions are queued for triune approval. |
| World model and triune reasoning | `backend/services/world_model.py`, `backend/services/world_events.py`, `backend/services/triune_orchestrator.py`, `backend/triune/*.py` | Events persist to `world_events`; strategic/action-critical events trigger Metatron, Michael, and Loki recomputation. |
| Autonomous-agent threat logic | `backend/services/aatl.py`, `backend/services/aatr.py`, `backend/services/cognition_fabric.py` | CCE/AATL/AATR signals feed cognition snapshots used by triune decisions. |
| Response and SOAR | `backend/routers/response.py`, `backend/routers/soar.py`, `backend/quarantine.py`, `backend/threat_response.py` | Response workflows exist; high-impact execution paths should be treated as governed. |
| Threat operations | `backend/routers/threats.py`, `alerts.py`, `timeline.py`, `threat_intel.py`, `hunting.py`, `correlation.py` | Core SOC read/write surfaces and enrichment modules are present. |
| Deception | `backend/deception_engine.py`, `backend/routers/deception.py`, `backend/routers/honeypots.py`, `backend/routers/honey_tokens.py` | Honeypot/honeytoken/deception APIs are wired into the backend. |
| Vector memory | `backend/services/vector_memory.py`, `backend/routers/advanced.py` | Namespaced memory entries, trust levels, incident cases, similarity search, and stats endpoints are implemented. |
| MCP and tool execution | `backend/services/mcp_server.py`, `backend/services/tool_gateway.py`, `backend/routers/advanced.py` | Tool execution surfaces exist and can be tied to governance context depending on configuration. |
| Token/policy/identity governance | `backend/services/token_broker.py`, `policy_engine.py`, `identity.py`, `governance_authority.py` | Core primitives are implemented; durability and enforcement consistency remain key risk areas. |
| Email protection and gateway | `backend/email_protection.py`, `backend/email_gateway.py`, `backend/routers/email_protection.py`, `backend/routers/email_gateway.py` | Protected-user, SPF/DKIM/DMARC-style checks, phishing/DLP analysis, gateway processing, quarantine, lists, and policies are exposed. |
| Mobile security and MDM | `backend/mobile_security.py`, `backend/mdm_connectors.py`, `backend/routers/mobile_security.py`, `backend/routers/mdm_connectors.py` | Device security and connector framework for Intune, JAMF, Workspace ONE, and Google Workspace are implemented; live value depends on real credentials/API reachability. |
| Cloud and container security | `backend/routers/cspm.py`, `backend/cspm_*_scanner.py`, `backend/routers/containers.py`, `backend/container_security.py` | CSPM and container surfaces exist with optional scanners/integrations. |
| Network, VPN, and browser controls | `backend/routers/network.py`, `vpn.py`, `browser_isolation.py`, `services/vns.py` | VPN, topology, VNS, and browser-analysis controls are present; full remote browser isolation is limited. |
| Kernel and secure boot | `backend/enhanced_kernel_security.py`, `backend/ebpf_kernel_sensors.py`, `backend/secure_boot_verification.py`, related routers | Kernel sensor and secure-boot APIs are implemented, subject to host/kernel/runtime privileges. |
| Frontend SOC UX | `frontend/src/App.js`, `frontend/src/pages/*` | React dashboard consolidates many legacy routes into workspace pages and calls `/api` surfaces. |

## Important implementation details

### Event and governance coupling

Routers and services call `emit_world_event()` for canonical event persistence. Event classification distinguishes passive facts, local reflexes, strategic recomputes, and action-critical recomputes. Strategic and action-critical classes invoke `TriuneOrchestrator`, which builds a world snapshot and returns Metatron assessment, Michael ranked plan, Loki advisory, and beacon cascade output.

High-impact outbound actions use `OutboundGateService.gate_action()`. Mandatory high-impact action types cannot downgrade below `high` impact and cannot bypass triune approval. `GovernedDispatchService.queue_gated_agent_command()` persists agent commands as `gated_pending_approval` with `queue_id`, `decision_id`, transition log, and authority context.

### Endpoint agent scope

The unified agent includes monitors for process, network, registry, process tree, LOLBin, code signing, DNS, memory, application whitelist, DLP, vulnerability, AMSI, YARA, ransomware, rootkit, kernel security, self-protection, endpoint identity, throttling, firewall, WebView2, CLI telemetry, hidden files, alias/rename, privilege escalation, email protection, and mobile security.

### Current limitations

- External integrations require credentials, local services, or host privileges.
- Browser isolation is primarily analysis/filtering rather than full remote pixel-streaming isolation.
- Several governance primitives are implemented, but restart/scale durability and end-to-end evidence guarantees need continued validation.
- Detection quality depends on local rules, heuristics, configured feeds, and available optional AI services; it is not equivalent to a cloud-scale commercial telemetry corpus.
- Documentation and tests should avoid treating adapter availability as proof of production integration.

## Test evidence to consult

- Backend tests: `backend/tests/`
- Unified-agent tests: `unified_agent/tests/`
- Broad API walk: `full_feature_test.py`
- Full-stack validation scripts: `backend/scripts/full_stack_e2e_validate.py`, `backend/scripts/e2e_threat_pipeline_test.py`
- Integration runtime smoke: `backend/scripts/integration_runtime_full_smoke.py`
- Frontend tests/build: `yarn test`, `yarn build` in `frontend/`
