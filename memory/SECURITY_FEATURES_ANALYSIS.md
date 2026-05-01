# Metatron Security Features Analysis

**Reviewed:** 2026-05-01
**Scope:** Current security feature inventory mapped to code paths.

## Executive summary

Metatron/Seraph implements a broad security platform across endpoint/XDR, SOC operations, AI-agentic defense, governance, DLP/EDM, email, mobile, CSPM, deception, kernel/security sensors, and integration surfaces. The implementation is distributed across:

- backend services and routers in `backend/`
- a React SOC dashboard in `frontend/src/`
- a large cross-platform endpoint agent in `unified_agent/core/agent.py`
- local agent APIs/UIs and integration runners under `unified_agent/`

The most important caveat is operational realism: many feature families have real service/router/UI code, but production depth varies depending on credentials, external tools, optional services, and denial-path test coverage.

## Implemented security domains

| Domain | Evidence | Current assessment |
| --- | --- | --- |
| Endpoint detection and response | `unified_agent/core/agent.py`, `backend/edr_service.py`, `backend/routers/edr.py` | Strong implementation breadth with process, network, registry, memory, DLP/EDM, ransomware, identity, kernel, CLI, email, and mobile monitor signals. |
| Unified agent control plane | `backend/routers/unified_agent.py` | Strong API surface for registration, heartbeat, fleet state, commands, EDM governance, deployments, alerts, stats, installers, and WebSocket support. |
| SOC workflows | `backend/routers/{threats,alerts,dashboard,timeline,audit,hunting,correlation,reports}.py` | Broad operational surface with React workspace pages and legacy redirects. |
| Response and SOAR | `backend/threat_response.py`, `backend/quarantine.py`, `backend/soar_engine.py`, `backend/routers/{response,quarantine,soar}.py` | Real orchestration and response code; strongest when paired with policy and audit controls. |
| AI-agentic defense | `backend/services/aatl.py`, `backend/services/aatr.py`, `backend/services/cognition_engine.py`, `backend/services/cce_worker.py` | Distinctive platform capability for machine-paced CLI/session analysis and autonomous-agent threat modeling. |
| Governance and enterprise controls | `backend/services/{identity,policy_engine,token_broker,tool_gateway,telemetry_chain,governed_dispatch}.py`, `backend/routers/enterprise.py` | Strong primitives; durability and scale semantics remain primary assurance targets. |
| Triune intelligence | `backend/triune/`, `backend/routers/{metatron,michael,loki}.py`, `backend/schemas/triune_models.py` | Implemented as an orchestration/intelligence layer over world events and governance context. |
| DLP and EDM | `backend/enhanced_dlp.py`, `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Mature control-plane shape: dataset versioning, signing, staged rollout, readiness, rollback, and hit telemetry. |
| Email protection | `backend/email_protection.py`, `backend/routers/email_protection.py`, `frontend/src/pages/EmailSecurityWorkspacePage.jsx` | SPF/DKIM/DMARC, phishing, attachment, impersonation, DLP, protected-user, and quarantine-style workflows represented in code. |
| Email gateway | `backend/email_gateway.py`, `backend/routers/email_gateway.py`, `frontend/src/pages/EmailGatewayPage.jsx` | SMTP-style message processing, policies, quarantine, allow/block lists, statistics, and test processing. Production relay use depends on real mail infrastructure. |
| Mobile security | `backend/mobile_security.py`, `backend/routers/mobile_security.py`, `frontend/src/pages/EndpointMobilityWorkspacePage.jsx` | Device lifecycle, jailbreak/root, app, compliance, network, and risk-score workflows represented. |
| MDM connectors | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py`, `frontend/src/pages/MDMConnectorsPage.jsx` | Intune, JAMF, Workspace ONE, and Google Workspace connector classes and APIs. Production sync depends on valid tenant/API credentials. |
| CSPM | `backend/cspm_engine.py`, `backend/cspm_*_scanner.py`, `backend/routers/cspm.py`, `frontend/src/pages/CSPMPage.jsx` | Multi-cloud posture surface with `/api/v1` routing and authenticated access paths. |
| Kernel and secure boot | `backend/enhanced_kernel_security.py`, `backend/ebpf_kernel_sensors.py`, `backend/secure_boot_verification.py`, `backend/routers/{kernel_sensors,secure_boot}.py` | Strong feature representation; production effectiveness depends on host permissions and kernel/runtime availability. |
| Network and browser isolation | `backend/vpn_integration.py`, `backend/browser_isolation.py`, `backend/routers/{vpn,browser_isolation,zeek,osquery,sigma}.py` | Implemented controls and integration points. Full remote browser isolation remains shallower than isolation-specialist products. |
| Deception and ransomware | `backend/deception_engine.py`, `backend/ransomware_protection.py`, `backend/honey_tokens.py`, routers and pages | Broad deception, honey-token, ransomware, and containment workflows. |
| Integrations | `backend/integrations_manager.py`, `backend/routers/integrations.py`, `unified_agent/integrations/` | Many tool adapters; quality varies by optional dependency and external service availability. |

## Security hardening state

| Control area | Current logic | Risk focus |
| --- | --- | --- |
| Auth and permissions | Auth dependencies and permission checks are used across critical routers. | Normalize legacy/secondary entrypoints and denial-path tests. |
| CORS | `backend/server.py` rejects wildcard/no origins in production/strict mode. | Keep environment validation explicit in deployment docs. |
| Machine-to-machine keys | `INTEGRATION_API_KEY` is required in production for internal ingestion/workers. | Ensure deployments provide keys and rotate them. |
| WebSockets | Server agent WebSocket validates machine tokens in `backend/server.py`. | Continue aligning agent, swarm, and unified WS contracts. |
| Auditability | Tamper-evident telemetry and world-event emission appear across major workflows. | Increase coverage for all high-risk actions and failure cases. |

## Primary gaps and limits

1. **Production credential dependencies:** email relay, MDM, SIEM, cloud scanners, sandbox, and tool integrations require real infrastructure and secrets.
2. **Governance durability:** policy/token/tool state needs persistent, restart-safe semantics across all high-risk paths.
3. **Contract governance:** 62 routers and 69 page modules create ongoing API/client drift risk.
4. **Denial-path coverage:** authentication, authorization, and fail-closed behavior need systematic regression coverage.
5. **Anti-tamper depth:** endpoint self-protection exists conceptually and partially in code, but does not yet match mature commercial EDR hardening.
6. **Browser isolation depth:** URL analysis and sanitization are present; full remote browser isolation remains limited.

## Bottom line

The security feature set is broad and materially implemented. The platform should be described as an advanced, high-breadth security fabric in active hardening, not as a finished incumbent-equivalent XDR. Its strongest differentiators are unified agent control, AI-agentic defense, governed dispatch concepts, DLP/EDM rollout controls, and rapid cross-domain feature composition.
