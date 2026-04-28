# Metatron / Seraph Feature Reality Matrix

## Current Code-Logic Snapshot (updated 2026-04-28)

Backend API is FastAPI version `3.0.0` in `backend/server.py`, served on `8001` with health at `/api/health`. The repo has 61 backend router modules plus package init, 32 backend service modules plus package init, 68 JSX frontend pages plus `GraphWorld.tsx`, 68 `<Route` occurrences in `frontend/src/App.js`, unified agent version `2.0.0`, and 63 backend test files. The authenticated frontend hub is `/command`. Root `smoke_test.py` is CAS Shield sidecar code, not a Seraph full-stack health test.


## Legend

- `PASS`: Real code is present and active in normal configured environments.
- `PARTIAL`: Code is present but depends on optional services, credentials, external products, or deeper assurance before production claims.
- `LIMITED`: Current implementation is compatibility, local/demo, framework-level, or reduced-depth.

## Feature Maturity Matrix

| Domain | Status | Current code evidence | Reality notes |
|---|---|---|---|
| Backend API composition | PASS | `backend/server.py`, 61 router modules plus package init | FastAPI composition root with broad router mesh; central wiring remains dense. |
| Frontend SOC console | PASS | `frontend/src/App.js`, `frontend/src/pages/` | `/command` is the landing route; legacy paths often redirect into workspaces. |
| Unified agent control plane | PASS | `backend/routers/unified_agent.py`, `unified_agent/core/agent.py` | Agent version 2.0.0; backend route family under `/api/unified/...`. |
| EDM/DLP governance | PASS | unified-agent router, agent core, DLP modules | Dataset and hit-loop concepts are implemented; assurance depends on targeted tests and deployment data. |
| Threat operations | PASS | threats, alerts, hunting, timeline, threat-intel, correlation routers/services | Broad SOC flows exist and are wired into frontend workspaces. |
| Response, SOAR, quarantine | PASS/PARTIAL | SOAR, quarantine, response modules and routers | Core workflows exist; external providers and high-risk action assurance remain conditional. |
| Deception and ransomware | PASS | deception, honeypot, honey-token, ransomware modules/routers | Deception engine is registered with compatibility routes under `/api/deception` and `/api/v1/deception`. |
| Identity protection | PASS/PARTIAL | `backend/routers/identity.py`, identity services | Versioned identity route family exists; enterprise-scale response depth and durability remain assurance focus areas. |
| CSPM | PASS/PARTIAL | `backend/routers/cspm.py`, `backend/cspm_engine.py` | Production cloud value depends on real credentials and scan configuration. |
| Email protection | PASS/PARTIAL | email protection router/modules, `/email-security` workspace | Protection APIs and UI route are present; production efficacy depends on DNS, policy, and mail-flow configuration. |
| Email gateway | PASS/PARTIAL | email gateway router/modules, `/email-security?tab=gateway` redirect | Gateway control surface exists; real inline relay operation requires production SMTP integration. |
| Mobile security | PASS/PARTIAL | mobile security router/modules, `/endpoint-mobility` workspace | Live posture depends on enrolled devices and platform signals. |
| MDM connectors | PASS/PARTIAL | MDM router/modules, `/endpoint-mobility?tab=mdm` | Real sync requires Intune/JAMF/Workspace ONE/Google credentials. |
| Kernel and secure boot | PASS/PARTIAL | secure-boot and kernel-sensor routers/modules | Runtime depends on host OS/kernel privileges and sensor availability. |
| Browser isolation | PARTIAL | browser isolation router/module | URL analysis/filtering exists; full remote browser pixel-stream isolation remains limited. |
| AI/Triune/world model | PASS/PARTIAL | `backend/triune/`, triune orchestrator, world model services | Model-backed quality depends on configured AI services. |
| Integrations | PASS/PARTIAL | integrations router, `unified_agent/integrations/` | Tool runners exist; runtime depends on binaries, services, and credentials. |
| Testing and assurance | PARTIAL | 63 backend tests, unified-agent tests, workflows | Good targeted coverage exists; breadth still needs contract and denial-path expansion. |

## Current Gaps and Constraints

1. Production SMTP relay configuration is required before claiming full email gateway enforcement.
2. MDM platform credentials and webhooks are required before claiming live fleet management.
3. Optional AI/model services improve analysis quality but are not mandatory core dependencies.
4. Full browser isolation remains limited compared with remote pixel-streaming isolation products.
5. Contract drift remains a documentation and CI risk because router/page counts and redirects change quickly.

## Bottom Line

The repository represents a broad, working security platform with active backend, frontend, unified-agent, integration, and test surfaces. The accurate maturity framing is feature-rich and operationally plausible, with production claims gated by external credentials, optional service availability, and assurance depth.
