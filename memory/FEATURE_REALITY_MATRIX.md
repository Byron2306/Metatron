# Metatron Feature Reality Matrix (Code-Evidence Refresh)

Generated: 2026-04-23  
Evidence base: repository state on branch `cursor/memory-code-logic-readme-c190`

## Scoring legend
- **PASS**: Implemented in active code paths and exposed through registered API/UI routes.
- **PARTIAL**: Implemented with bounded fallback, optional dependency, or limited production depth.
- **LIMITED**: Early/framework implementation only.

---

## Platform snapshot (current code)

| Area | Current state | Evidence |
|---|---|---|
| Backend API composition | **PASS** (large modular surface) | `backend/server.py` includes **65** routers |
| Router depth | **PASS** (broad endpoint coverage) | `backend/routers/*.py` contains **62** router modules and **697** route handlers |
| Frontend route shell | **PASS** (workspace model + legacy redirects) | `frontend/src/App.js` |
| AuthN/AuthZ baseline | **PASS** | `backend/routers/dependencies.py`, `backend/routers/auth.py` |
| Unified agent control plane | **PASS** | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` |
| Triune governance gating | **PASS** | `backend/services/outbound_gate.py`, `backend/services/governed_dispatch.py`, `backend/services/governance_executor.py` |
| CSPM durability + governance hooks | **PASS** | `backend/routers/cspm.py` |
| Email security stack | **PASS** | `backend/email_protection.py`, `backend/email_gateway.py`, matching routers |
| Mobile + MDM stack | **PASS** | `backend/mobile_security.py`, `backend/mdm_connectors.py`, matching routers |
| Optional security integrations (Falco/Suricata/Zeek/Cuckoo/Ollama) | **PARTIAL** | `docker-compose.yml`, integration-specific services/routers |

---

## Domain maturity matrix

| Domain | Status | Evidence | Notes |
|---|---|---|---|
| Core API + data plane | PASS | `backend/server.py`, `backend/routers/*` | Central wiring remains dense, but routerized execution is broad and active. |
| Authentication + permission model | PASS | `backend/routers/dependencies.py` | JWT, role gates, remote-admin guardrails, machine token paths are implemented. |
| Unified agent lifecycle | PASS | `backend/routers/unified_agent.py` | Register, heartbeat, command queueing, command results, deploy APIs, monitor telemetry are active. |
| Endpoint monitor depth (agent-side) | PASS | `unified_agent/core/agent.py` | Extensive monitor set (process/network/registry/rootkit/kernel/email/mobile/DLP/EDM). |
| EDM governance + telemetry loop-back | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Dataset versioning, publish/rollback, rollout/readiness, signed dataset checks, endpoint hit loop-back. |
| DLP + exact data match | PASS | `unified_agent/core/agent.py`, `backend/enhanced_dlp.py` | Agent DLP monitor and EDM match collection are wired. |
| Email protection | PASS | `backend/routers/email_protection.py`, `backend/email_protection.py` | Analyze/email-auth/DLP/quarantine/protected-users/block-trust lists are present. |
| Email gateway | PASS | `backend/routers/email_gateway.py`, `backend/email_gateway.py` | Process, quarantine, policies, blocklist/allowlist endpoints are active. |
| Mobile security | PASS | `backend/routers/mobile_security.py`, `backend/mobile_security.py` | Device enrollment/status/compliance/threat/app analysis/dashboard flows present. |
| MDM connectors | PASS | `backend/routers/mdm_connectors.py`, `backend/mdm_connectors.py` | Connector mgmt, sync, lock/wipe/retire, platform metadata are implemented. |
| CSPM | PASS | `backend/routers/cspm.py`, `backend/cspm_engine.py` | Provider config + scan lifecycle + finding transitions + dashboard/export/compliance paths are implemented. |
| Governance dispatch and execution | PASS | `backend/services/outbound_gate.py`, `backend/services/governance_executor.py` | High-impact actions are forced through triune queue and executed from approved decisions. |
| Identity/policy/token/tool governance substrate | PASS | `backend/services/identity.py`, `policy_engine.py`, `token_broker.py`, `tool_gateway.py` | Capability-level governance primitives exist and are integrated. |
| Tamper-evident telemetry chain | PASS | `backend/services/telemetry_chain.py` | Hash-chain/audit record logic exists and is consumed by routers/services. |
| Browser isolation depth | PARTIAL | `backend/browser_isolation.py`, `backend/routers/browser_isolation.py` | Functional URL/session/sanitization model; full remote isolated browsing model still bounded. |
| Deployment realism | PARTIAL | `backend/services/agent_deployment.py`, `backend/routers/unified_agent.py` | Real SSH/WinRM paths exist; runtime environment and credential availability govern depth. |
| Optional AI/model-assisted reasoning | PARTIAL | `backend/routers/advanced.py`, service dependencies in compose | Works with local/optional model services; quality/availability depends on runtime config. |

---

## Notable implementation anchors (current)

- **Unified route density:** `backend/routers/unified_agent.py` currently exposes 50+ endpoints including EDM lifecycle, deployment, command and monitor APIs.
- **Governed command pipeline:** unified agent commands are queued via `GovernedDispatchService` and triune outbound approvals before execution release.
- **CSPM durability pattern:** scan and finding updates use explicit state-version checks and transition logs for conflict-safe state mutation.
- **Security event projection:** multiple routers/services emit world events and write telemetry-chain audit records.

---

## Current gaps (engineering reality)

1. **Dense central composition:** `backend/server.py` is still a high-coupling registration hub.
2. **Optional integration variance:** behavior quality for advanced integrations depends on external service readiness.
3. **Browser isolation completeness:** still short of full remote/pixel-isolated browsing architecture.
4. **Operational hardening depth:** many controls exist, but production consistency remains a discipline/workflow concern rather than missing code.

---

## Bottom line

The repository now reflects a **broadly implemented multi-domain security platform** with substantial real code paths across endpoint, email, mobile/MDM, CSPM, and governance. Remaining risk centers on **operational consistency and integration depth**, not basic feature absence.
