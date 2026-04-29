# Metatron Feature Reality Matrix

**Rebaselined:** 2026-04-29

## Legend

- `PASS`: Real code executes in normal configured environments.
- `PARTIAL`: Real code exists but depends on optional providers, credentials, runtime services, or deeper assurance.
- `LIMITED`: Framework, compatibility, demo, fallback, or in-memory behavior that should not be treated as production-complete.

## Current Reality Matrix

| Domain | Status | Evidence | Practical Notes |
|---|---|---|---|
| Backend FastAPI platform | PASS | `backend/server.py`, `backend/routers/*.py` | Broad router mesh registered under `/api` and selected `/api/v1`. |
| Mongo-backed platform state | PASS | `backend/server.py`, domain services | MongoDB is configured at startup and injected into routers/services. |
| Frontend protected route shell | PASS | `frontend/src/App.js`, `AuthContext.jsx`, `Layout.jsx` | Login protected routes with workspace consolidation and compatibility redirects. |
| API base normalization | PARTIAL | `frontend/src/lib/api.js`, page-local API constants | Shared helper exists, but many pages still build API URLs directly. |
| Governance outbound queue | PASS | `services/outbound_gate.py`, `routers/governance.py` | Creates queue/decision records and supports approve/deny flows. |
| Governance executor | PASS/PARTIAL | `services/governance_executor.py` | Background processor exists; production behavior depends on env/config and downstream adapters. |
| Governed agent commands | PASS | `services/governed_dispatch.py` | Gated commands are persisted as `gated_pending_approval`. |
| Governance context enforcement | PASS | `services/governance_context.py`, `token_broker.py`, `tool_gateway.py` | Sensitive paths require approved decision/queue context. |
| World model ingestion | PASS | `routers/world_ingest.py`, `services/world_model.py` | Machine-token protected ingestion for entities, edges, detections, alerts, and policy violations. |
| Vector memory | PARTIAL | `services/vector_memory.py`, `routers/advanced.py` | In-process semantic memory with namespaces/trust; not an external durable vector DB. |
| Unified agent backend | PASS/PARTIAL | `routers/unified_agent.py`, `routers/swarm.py` | Control plane exists; deployment realism varies with credentials/protocol reachability. |
| Unified agent local API | LIMITED/PARTIAL | `unified_agent/server_api.py` | Useful local proxy/control service; uses in-memory dicts. |
| Email protection | PASS/PARTIAL | `backend/email_protection.py`, `routers/email_protection.py` | Analysis and API code exists; live fidelity depends on DNS/config/reputation inputs. |
| Email gateway | PARTIAL | `backend/email_gateway.py`, `routers/email_gateway.py`, `EmailGatewayPage.jsx` | Gateway/quarantine/list/policy framework exists; production SMTP relay integration is deployment work. |
| Mobile security | PASS/PARTIAL | `backend/mobile_security.py`, `routers/mobile_security.py` | Device/threat/compliance logic exists; live fleet fidelity depends on agents/provider data. |
| MDM connectors | PARTIAL | `backend/mdm_connectors.py`, `routers/mdm_connectors.py`, `MDMConnectorsPage.jsx` | Provider connector framework exists; real sync/actions require MDM credentials and scopes. |
| CSPM | PASS/PARTIAL | `backend/cspm_engine.py`, `routers/cspm.py` | Multi-cloud posture surface exists; provider coverage depends on cloud credentials. |
| Identity protection | PASS/PARTIAL | `backend/identity_protection.py`, `routers/identity.py` | API and engine exist; enterprise response depth remains environment-specific. |
| Response/SOAR/quarantine | PASS/PARTIAL | `threat_response.py`, `soar_engine.py`, `quarantine.py` | Core workflows exist; high-impact execution should use governance. |
| Browser isolation | PARTIAL | `browser_isolation.py`, `routers/browser_isolation.py` | URL filtering/sanitization exists; full remote browser isolation is limited. |
| Optional AI augmentation | PARTIAL | `services/ai_reasoning.py`, `ai/ollama_client.py`, advanced routes | Rule/framework paths exist; model quality requires live model services. |
| CAS sidecar docs | LIMITED | `cas_shield_sidecar.py`, `memory/docker-compose.yml` | Runnable top-level sidecar exists; `memory/` compose references a missing local `src/` tree. |

## Acceptance Snapshot

No new full runtime acceptance suite was executed for this documentation rebaseline. The matrix above is a code-evidence snapshot. Runtime acceptance should verify minimal compose startup, login, command workspace, world ingestion with machine token, governance approve/deny, and representative optional degraded states.

## Bottom Line

The codebase has real breadth and several mature control-plane primitives. The safest maturity language is domain-by-domain `PASS/PARTIAL/LIMITED`, with explicit notes for optional providers, in-memory local services, and governance/test coverage requirements.
