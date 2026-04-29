# Feature Reality Report

Updated: 2026-04-29
Scope: code-evidence narrative for implemented platform logic, operational realism, and current gaps.

## Executive verdict

Metatron / Seraph is implemented as a broad adaptive cyber-defense platform, not a single-purpose EDR. The current codebase is centered on a FastAPI control plane (`backend/server.py`), a React workspace UI (`frontend/src/App.js`), and a cross-platform unified endpoint agent (`unified_agent/core/agent.py`).

The current architecture is defined by:

- a Mongo-backed API router mesh mounted mainly below `/api`;
- unified-agent registration, heartbeat, telemetry, EDM, deployment, and governed command dispatch below `/api/unified/*`;
- world-model ingestion and Metatron/Michael/Loki Triune reasoning over security state;
- outbound governance through policy, dispatch, telemetry-chain, and executor services;
- MITRE coverage aggregation at `/api/mitre/coverage`;
- consolidated frontend workspaces that redirect older feature routes into command, investigation, response, detection-engineering, email-security, and endpoint-mobility experiences.

The platform is materially implemented across many domains, but production confidence still depends on credentials, external service availability, deployment verification, governance-state durability, and regression coverage.

## Current maturity snapshot

| Domain | Status | Current code evidence | Reality note |
|---|---|---|---|
| Backend API composition | Strong | `backend/server.py` | FastAPI app wires Mongo, CORS, domain services, startup workers, and many routers. Central wiring remains dense. |
| Unified agent control plane | Strong | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Real register/heartbeat/command/EDM/deployment surfaces. Impactful commands are routed through governed dispatch. |
| World model and Triune cognition | Strong emerging | `backend/services/world_events.py`, `backend/services/triune_orchestrator.py`, `backend/triune/*`, `backend/routers/metatron.py` | World events can trigger Metatron assessment, Michael planning, Loki challenge, and beacon cascade logic. |
| Governance and outbound action control | Strong emerging | `backend/services/outbound_gate.py`, `governed_dispatch.py`, `governance_executor.py`, `policy_engine.py`, `telemetry_chain.py` | Governance path is real, but durability and scale semantics remain a key hardening area. |
| MITRE coverage | Strong | `backend/routers/mitre_attack.py`, `backend/scripts/mitre_coverage_evidence_report.py` | Aggregates evidence from Sigma, osquery, Zeek, atomic validation, EDR, deception, integrations, AI mapping, and world/audit sources. |
| Frontend route and API wiring | Strong | `frontend/src/App.js`, `frontend/src/context/AuthContext.jsx`, workspace pages | Protected routes, same-origin `/api` fallback, and consolidated workspaces are implemented. Some pages still use demo data when APIs are empty. |
| Email security and MDM | Strong framework | `backend/email_gateway.py`, `backend/email_protection.py`, `backend/mdm_connectors.py`, related routers and workspace pages | Gateway, protection, mobile, and MDM frameworks exist; live value depends on SMTP and MDM credentials/webhooks. |
| Integrations | Partial to strong by connector | `backend/integrations_manager.py`, `backend/routers/integrations.py`, `unified_agent/integrations/*` | Tool orchestration and parsers exist; production behavior varies by installed tools and credentials. |
| Deployment realism | Partial | `backend/services/agent_deployment.py`, unified-agent deployment routes | SSH/WinRM execution paths exist; simulated deployment can be enabled and must be treated as non-production evidence. |
| AI/model augmentation | Partial | `backend/services/cognition_engine.py`, `cognition_fabric.py`, `ai_reasoning.py`, AATL/AATR services | Rule-based and local reasoning paths exist; model-backed quality depends on available model services. |

## What works well

1. **Core platform boot and routing**
   - `backend/server.py` creates the app, configures Mongo or `mongomock`, applies strict CORS validation in production/strict mode, initializes shared services, and registers the router mesh below `/api`.
   - Startup hooks seed an admin account when configured and launch services such as the CCE worker, network discovery, deployment service, AATL/AATR, Falco callback, integration scheduler, and governance executor.

2. **Unified agent lifecycle**
   - Agents register and heartbeat through `/api/unified/agents/register` and `/api/unified/agents/{agent_id}/heartbeat`.
   - The backend projects agent telemetry into the world model and can trigger Triune reasoning when threat counts indicate elevated risk.
   - The agent implements many local monitors and remediation helpers in `unified_agent/core/agent.py`, including process, network, registry, DNS, memory, DLP, YARA, ransomware, rootkit, kernel, self-protection, identity, CLI, email, and mobile monitor families.

3. **Governed response path**
   - High-impact commands are not just raw REST writes. `GovernedDispatchService` and `OutboundGateService` queue or gate actions, `policy_engine.py` models approval tiers/categories, `telemetry_chain.py` records tamper-evident actions, and `governance_executor.py` dispatches approved decisions to supported domains.

4. **World-state reasoning**
   - `WorldModelService` stores entities, edges, hotspots, campaigns, and graph metrics.
   - `TriuneOrchestrator.handle_world_change()` builds a snapshot, adds cognition-fabric signals, asks Metatron for assessment, asks Michael for ranked action plans, asks Loki to challenge the plan, and may apply beacon cascade behavior.
   - The UI reads Metatron/world state through routes such as `/api/metatron/state`.

5. **MITRE and detection engineering**
   - `/api/mitre/coverage` computes coverage by combining evidence from multiple implemented detectors and integrations rather than a static table only.
   - Detection-engineering UI routes consolidate Sigma, atomic validation, and MITRE views.

6. **Frontend consolidation**
   - `frontend/src/App.js` redirects legacy pages into workspace pages: `/command`, `/investigation`, `/response-operations`, `/detection-engineering`, `/email-security`, and `/endpoint-mobility`.
   - `AuthContext.jsx` resolves `REACT_APP_BACKEND_URL` safely and falls back to same-origin `/api` for reverse-proxied deployments.

## Conditional or limited areas

- **External integrations:** SMTP, MDM, SIEM, sandbox, WireGuard, Elasticsearch/Kibana, Ollama, Trivy, Falco, Suricata, Arkime, BloodHound, Amass, and SpiderFoot depend on installed tools, credentials, or enabled profiles.
- **Simulation and demo behavior:** mock Mongo, CSPM demo seed, dashboard seed data, simulated deployment, MCP simulated execution, and several frontend empty-state demo datasets are useful for development but should not be counted as production evidence.
- **Governance durability:** the governance stack is real, but the review priority remains making policy decisions, approvals, executor state, and token/audit chains fully durable across restarts and scaled workers.
- **Deployment proof:** SSH/WinRM paths exist, but production success must be tied to verified install evidence and subsequent agent heartbeat.
- **AI efficacy:** deterministic/rule fallback exists; model-assisted analysis quality depends on live model configuration and evaluation datasets.

## Updated bottom line

Metatron / Seraph is best described as a **governed adaptive defense fabric in active hardening**. It has real multi-domain code and increasingly strong control-plane logic. The highest-value next work is not adding more nominal features; it is making action governance durable, validating contracts in CI, strengthening deployment truth, and separating demo/simulation evidence from production evidence.
