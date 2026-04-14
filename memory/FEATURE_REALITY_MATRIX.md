# Metatron Feature Reality Matrix (Current Code-State)

**Last Updated:** 2026-04-14  
**Scope:** Implementation reality based on live repository code paths

## Legend

- **IMPLEMENTED**: Active logic exists in code and is wired.
- **IMPLEMENTED (ENV-DEPENDENT)**: Logic exists; operational value depends on external credentials/services.
- **PARTIAL**: Present but with limited depth/consistency constraints.

---

## Domain Matrix

| Domain | Status | Evidence | Notes |
|---|---|---|---|
| API composition and route wiring | IMPLEMENTED | `backend/server.py` | Central composition with high route volume and mixed prefix strategy. |
| Auth/JWT/role permission framework | IMPLEMENTED | `backend/routers/dependencies.py` | Includes strict-mode secret handling and role checks. |
| Remote admin restriction model | IMPLEMENTED | `backend/routers/dependencies.py` | Non-local access constrained by admin role/email allowlist when enabled. |
| CORS strict configuration | IMPLEMENTED | `backend/server.py` | Wildcard origins rejected in strict/prod-like mode. |
| Machine token dependencies | IMPLEMENTED | `backend/routers/dependencies.py` | Required/optional token checks for service and websocket channels. |
| Unified agent control-plane APIs | IMPLEMENTED | `backend/routers/unified_agent.py` | Registration, heartbeat, telemetry, control, EDM/governance pathways. |
| Unified agent monitor architecture | IMPLEMENTED | `unified_agent/core/agent.py` | Broad monitor map including endpoint, identity, kernel, DLP/EDM, and email/mobile monitors. |
| EDM + DLP endpoint pipeline | IMPLEMENTED | `unified_agent/core/agent.py`, `backend/routers/unified_agent.py` | Fingerprinting + dataset/rollout controls integrated. |
| Email protection service/API | IMPLEMENTED | `backend/email_protection.py`, `backend/routers/email_protection.py` | Analysis/quarantine/list management flows present. |
| Email gateway service/API | IMPLEMENTED (ENV-DEPENDENT) | `backend/email_gateway.py`, `backend/routers/email_gateway.py` | Gateway logic and API are implemented; production relay behavior depends on SMTP integration. |
| Mobile security service/API | IMPLEMENTED | `backend/mobile_security.py`, `backend/routers/mobile_security.py` | Device lifecycle, compliance, threat and app analysis operations present. |
| MDM connectors service/API | IMPLEMENTED (ENV-DEPENDENT) | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` | Multi-platform connectors exist; production value depends on vendor credentials/connectivity. |
| CSPM service/API | IMPLEMENTED (ENV-DEPENDENT) | `backend/cspm_engine.py`, `backend/routers/cspm.py` | Scan and provider lifecycle implemented; real fidelity depends on cloud provider configuration. |
| Identity protection and incident lifecycle | IMPLEMENTED | `backend/routers/identity.py`, `backend/identity_protection.py` | Incident persistence, transitions, and provider-event pathways are present. |
| Governance approval-to-execution bridge | IMPLEMENTED | `backend/services/governance_executor.py` | Approved actions can dispatch to response/quarantine/VPN/command operations. |
| Deception domain APIs | IMPLEMENTED | `backend/routers/deception.py`, `backend/deception_engine.py` | Dual prefix wiring used for compatibility. |
| Response + quarantine operations | IMPLEMENTED | `backend/threat_response.py`, `backend/quarantine.py`, related routers | Action and lifecycle logic active with audit/event patterns. |
| Startup orchestration for background services | IMPLEMENTED | `backend/server.py` startup/shutdown handlers | CCE, discovery, deployment, AATL/AATR, governance executor startup hooks present. |
| Frontend protected route model | IMPLEMENTED | `frontend/src/App.js`, auth context | Access guard + workspace redirect pattern implemented. |
| Full remote browser isolation depth | PARTIAL | `backend/browser_isolation.py`, related UI pages | Browser isolation exists but full remote-isolation depth remains limited. |
| Uniform invariants across all legacy-compatible paths | PARTIAL | Cross-cutting | Compatibility aliases increase ongoing contract/hardening consistency pressure. |
| Restart/scale durability for all orchestration state | PARTIAL | Cross-cutting | Many DB-backed transitions exist, but in-memory coordination still appears in several domains. |

---

## Focused Route Surface Snapshot

| Area | Verified Route Count | Source |
|---|---:|---|
| `email_gateway` router handlers | 12 | `backend/routers/email_gateway.py` |
| `mdm_connectors` router handlers | 18 | `backend/routers/mdm_connectors.py` |
| `server.py` `include_router` registrations | 65 | `backend/server.py` |
| Unified agent monitor keys initialized | 30 | `unified_agent/core/agent.py` |

Notes:
- Router registration count includes compatibility aliases/duplicate-prefix registrations.
- Monitor count includes conditional/platform-specific entries.

---

## Reality Summary

The codebase contains broad, real implementation across endpoint, identity, cloud, email, mobile, and governance-controlled response operations.  
Current practical limitations are concentrated in environment-dependent integrations and consistency assurance across a high-complexity API/runtime surface.
