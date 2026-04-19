# Seraph Feature Reality Matrix (Updated April 2026)

This matrix reflects implemented behavior observed in the current repository, not planned intent.

## Legend

- **Implemented**: Feature has active backend endpoints and/or service logic wired in `backend/server.py`.
- **Partially implemented**: Feature exists but has known contract drift, legacy paths, or limited runtime guarantees.
- **Infrastructure-dependent**: Feature is implemented in code but requires optional services/tooling to be fully operational.

## Platform snapshot (code-grounded)

- Backend entrypoint: `backend/server.py`
- Backend routers mounted: **62**
- Backend service modules: **33**
- Router endpoint decorators (`@router.*`): **694**
- Frontend page modules: **68**
- Frontend route declarations in `frontend/src/App.js`: **66**
- Unified-agent integration adapters: **12** (`unified_agent/integrations/*`)

## Current reality matrix

| Domain | Reality | Evidence (primary files) | Notes |
|---|---|---|---|
| Auth + RBAC | Implemented | `backend/routers/auth.py`, `backend/routers/dependencies.py` | JWT auth, role/permission checks, setup-token bootstrap path. |
| Threats + Alerts | Implemented | `backend/routers/threats.py`, `backend/routers/alerts.py`, `backend/server.py` | Core SOC flows are mounted under `/api`. |
| Unified agent control plane | Implemented | `backend/routers/unified_agent.py`, `backend/routers/agent_commands.py` | Rich agent telemetry + command APIs; large module footprint. |
| Governance gate + execution | Implemented | `backend/services/governed_dispatch.py`, `backend/services/governance_authority.py`, `backend/services/governance_executor.py`, `backend/routers/governance.py` | Approved decision -> executor -> command queue flow is present. |
| Integrations runtime orchestration | Implemented | `backend/routers/integrations.py`, `backend/integrations_manager.py`, `unified_agent/integrations_client.py` | Supports server-runtime and unified-agent runtime targeting. |
| World model + ingest | Implemented | `backend/services/world_model.py`, `backend/services/world_events.py`, `backend/routers/world_ingest.py` | Machine-token protected ingest endpoints plus event projection. |
| Email protection | Implemented | `backend/routers/email_protection.py`, `backend/email_protection.py` | Analysis + quarantine + protected user controls present. |
| Email gateway | Implemented | `backend/routers/email_gateway.py`, `backend/email_gateway.py` | Process/quarantine/allowlist/blocklist/policy APIs. |
| Mobile security + MDM | Implemented | `backend/routers/mobile_security.py`, `backend/routers/mdm_connectors.py`, `backend/mdm_connectors.py` | Connectors + sync/device action endpoints available. |
| CSPM | Implemented | `backend/routers/cspm.py`, `backend/cspm_engine.py` | `/api/v1/cspm/*` namespace with authenticated scan operations. |
| Identity protection | Implemented | `backend/routers/identity.py`, `backend/services/identity.py` | `/api/v1/identity/*` with governance/tamper-evident hooks. |
| Zero trust + VPN | Implemented | `backend/routers/zero_trust.py`, `backend/routers/vpn.py`, `backend/services/policy_engine.py` | Endpoint + policy surfaces exist; runtime depends on environment capability. |
| EDR + response orchestration | Implemented | `backend/routers/edr.py`, `backend/routers/response.py`, `backend/services/outbound_gate.py` | Response actions and gating are wired. |
| Deception + honeypots/honey tokens | Implemented | `backend/routers/deception.py`, `backend/routers/honeypots.py`, `backend/routers/honey_tokens.py` | Deception is mounted with dual prefix compatibility. |
| Detection engineering (Sigma/Zeek/Osquery/MITRE/Atomic) | Implemented | `backend/routers/sigma.py`, `zeek.py`, `osquery.py`, `mitre_attack.py`, `atomic_validation.py` | Broad endpoint surface available. |
| Advanced services (MCP/vector/VNS/quantum/AI reasoning) | Partially implemented | `backend/routers/advanced.py`, `backend/services/*` | Large API surface exists; some behaviors are integration/runtime dependent. |
| Triune services (Metatron/Michael/Loki) | Partially implemented | `backend/routers/metatron.py`, `michael.py`, `loki.py`, `backend/triune/*` | Present and mounted, but operational depth varies by deployment profile. |
| Frontend workspace routing | Implemented | `frontend/src/App.js`, workspace pages under `frontend/src/pages/*Workspace*` | Route consolidation is in place via workspace pages + `Navigate` aliases. |
| Frontend-to-backend endpoint alignment | Partially implemented | static audit (`memory/full_pages_wiring_audit.md`) | 142/148 mapped call-sites; remaining endpoints are legacy placeholders. |

## Known contract drift (still open)

1. `frontend/src/pages/AIDetectionPage.jsx` uses `/api/data` (no clean backend match).
2. `frontend/src/pages/DeceptionPage.jsx` references `/api/login` instead of `/api/auth/*`.
3. `frontend/src/pages/ZeroTrustPage.jsx` references `/api/admin/users`; users API is `/api/users`.

## Bottom line

The platform is **broadly implemented** with a large active API surface and strong subsystem coverage.  
Current risk is primarily **contract consistency and runtime reliability across optional integrations**, not absence of core feature code.
