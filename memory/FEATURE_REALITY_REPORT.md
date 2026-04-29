# Feature Reality Report

**Rebaselined:** 2026-04-29
**Scope:** Qualitative implementation reality by domain, based on current repository structure and code paths.

## Executive Verdict

Metatron/Seraph has real implementation breadth across SOC operations, endpoint/agent control, governance, world modeling, response automation, email/mobile security, cloud posture, deception, and optional AI-assisted services. The accurate current summary is not that every domain is production-complete; it is that most domains have concrete backend/frontend code, while maturity varies by persistence depth, external-provider configuration, test coverage, and governance enforcement.

## Current Maturity Summary

| Domain | Current Reality | Practical Notes |
|---|---|---|
| Backend API platform | Strong | `backend/server.py` registers a broad FastAPI router mesh under `/api` and selected `/api/v1` prefixes. |
| Frontend workspaces | Strong | React routes are consolidated into command, world, investigation, response, email, endpoint-mobility, AI activity, and detection-engineering workspaces. |
| Governance and outbound gating | Strong architecture, medium assurance | Queue/decision/approval/executor code exists; denial-path and bypass tests should continue expanding. |
| World model and ingestion | Strong architecture | Machine-token protected ingestion upserts entities, edges, detections, alerts, and policy violations. |
| Unified agent control | Strong breadth | Backend and local-agent surfaces exist; deployment realism depends on environment and credentials. |
| Email protection/gateway | Implemented framework | Backend routers/services and UI exist; production SMTP/reputation integrations require live configuration. |
| Mobile security/MDM | Implemented framework | Connectors and UI exist; real sync/action fidelity depends on external MDM credentials and provider availability. |
| CSPM/identity/enterprise plane | Implemented, mixed maturity | API and dashboards exist; scale and provider coverage need environment validation. |
| Response/SOAR/quarantine | Implemented | Core workflows exist; high-impact actions should remain governance-gated. |
| Browser isolation/sandbox/AI augmentation | Partial | Useful API/UI/framework paths exist; full remote-browser isolation and live model quality are optional/provider-dependent. |

## Reality by Domain

### Governance and High-Impact Actions

Implemented paths include `OutboundGateService`, `GovernedDispatchService`, `GovernanceDecisionAuthority`, and `GovernanceExecutorService`. High-impact action types can force triune review, create records in `triune_outbound_queue` and `triune_decisions`, and update related `agent_commands`. Governance context is enforced in sensitive token/tool paths.

**Limits:** assurance depends on configured executor behavior, consistent use by all high-impact routers, and regression tests for denial/bypass paths.

### World Model and Triune Events

`backend/routers/world_ingest.py` accepts machine-authenticated entities, edges, detections, alerts, and policy violations. `WorldModelService` persists graph-like state, while world events can return triune metadata.

**Limits:** ingestion depends on valid machine tokens; downstream quality depends on producers sending normalized evidence.

### Frontend Operator Experience

The UI is no longer accurately described as dozens of independent top-level pages. `App.js` now uses protected workspace routes plus compatibility redirects. This improves navigation but means old page-count metrics and direct-route lists are stale.

**Limits:** API access patterns are still split across page-local fetch/axios calls and the shared `lib/api.js`.

### Email Gateway and Email Protection

Email protection and gateway modules are present in backend services/routers and frontend workspaces. They cover analysis, policy concepts, quarantine/list management, and gateway testing surfaces.

**Limits:** production SMTP relay operation, external reputation sources, and organization-specific mail-flow integration require deployment credentials/configuration.

### Mobile Security and MDM Connectors

Mobile and MDM modules provide device/compliance/action concepts, multi-provider connector classes, API endpoints, and UI dashboards.

**Limits:** live device inventory, webhook events, and remote lock/wipe fidelity require real MDM provider credentials and permission scopes.

### Unified Agent and Local Plane

The repository includes the endpoint agent, local FastAPI proxy/control API, and desktop UI. Backend unified-agent and swarm routes support central control-plane operations.

**Limits:** the local API uses in-memory dictionaries; deployment and command outcomes must be interpreted against environment-specific execution evidence.

## Bottom Line

The platform is best documented as a broad, actively implemented security fabric with real governance and world-model primitives. The remaining gap is not feature naming; it is consistent contract assurance, external-provider validation, durable state semantics, and clear degraded-mode communication.
