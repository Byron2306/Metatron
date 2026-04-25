# Metatron Feature Reality Matrix

**Reviewed:** 2026-04-25  
**Scope:** Quantitative and qualitative implementation snapshot from repository evidence.

## Legend

- `PASS`: Real logic is present and should execute when documented runtime prerequisites are available.
- `PARTIAL`: Real implementation exists, but completeness depends on optional services, credentials, host privileges, durability depth, or additional verification.
- `CONDITIONAL`: Framework/API exists but meaningful production behavior requires external systems or environment-specific configuration.
- `LIMITED`: Reduced-depth implementation compared with the product claim.

## Current Inventory Snapshot

| Surface | Count / state | Evidence |
|---|---:|---|
| Backend router modules | 61 | `backend/routers/*.py` excluding `__init__.py` |
| Backend service modules | 32 | `backend/services/*.py` excluding `__init__.py` |
| FastAPI router registrations | 65 include calls | `backend/server.py` |
| Frontend route entries | 67 | `frontend/src/App.js` |
| Frontend page imports from App | 43 | `frontend/src/App.js` |
| Frontend page files | 68 JSX files | `frontend/src/pages/*.jsx` |
| Docker Compose services | 21 | root `docker-compose.yml` |
| Unified-agent telemetry keys | 24 | `MONITOR_TELEMETRY_KEYS` in `backend/routers/unified_agent.py` |

## Feature Maturity Matrix

| Domain | Status | Evidence | Current summary |
|---|---|---|---|
| Backend route composition | PASS | `backend/server.py`, `backend/routers/*` | Large modular FastAPI app with `/api` and selected `/api/v1` surfaces. |
| Frontend workspace routing | PASS | `frontend/src/App.js` | Workspace-oriented SPA with legacy redirects into command, investigation, response, detection, email, endpoint/mobility, world, and unified-agent workspaces. |
| Auth and user management | PASS/PARTIAL | `routers/auth.py`, `routers/dependencies.py` | JWT and role controls exist; production secret/origin governance must be configured. |
| Unified agent lifecycle | PASS | `routers/unified_agent.py`, `unified_agent/core/agent.py` | Registration, heartbeat, telemetry, command, installer/download, and EDM routes exist. |
| Unified agent monitors | PASS/PARTIAL | `unified_agent/core/agent.py` | 25+ monitors are initialized depending on OS/config; Windows-only monitors are conditional. |
| Governed dispatch | PASS/PARTIAL | `services/governed_dispatch.py`, `services/governance_executor.py` | High-impact dispatch hooks and executor loop exist; durability and policy-denial assurance need continued testing. |
| EDM and DLP | PASS/PARTIAL | `routers/unified_agent.py`, `unified_agent/core/agent.py`, `backend/enhanced_dlp.py` | Dataset/version/telemetry flows and local scanning are implemented; broad contract automation remains a focus. |
| AI-agentic layer | PARTIAL | `services/aatl.py`, `services/aatr.py`, `services/cognition_engine.py` | Runtime services and APIs exist; model-backed quality and calibration are environment/data dependent. |
| Triune/world model | PASS/PARTIAL | `triune/*`, `routers/metatron.py`, `routers/michael.py`, `routers/loki.py`, `routers/world_ingest.py` | Startup instantiates services and routers expose them; operational depth depends on ingested world events. |
| Threat ops and SOC workflows | PASS | `threats.py`, `alerts.py`, `timeline.py`, `audit.py`, `hunting.py`, `correlation.py` | Core read/write workflows are present. |
| Response/SOAR/quarantine | PASS/PARTIAL | `response.py`, `soar.py`, `quarantine.py`, `soar_engine.py` | Action orchestration exists; high-risk actions require policy, credentials, and failure-mode validation. |
| Deception/honeypots/honey tokens | PASS/PARTIAL | `deception.py`, `deception_engine.py`, `honeypots.py`, `honey_tokens.py` | Engine and compatibility mounts exist; runtime signal value depends on deployment. |
| Email protection | PASS | `email_protection.py`, `routers/email_protection.py` | SPF/DKIM/DMARC, phishing, URL, attachment, impersonation, DLP, quarantine-oriented logic is present. |
| Email gateway | CONDITIONAL | `email_gateway.py`, `routers/email_gateway.py` | Gateway APIs and processing framework are present; production SMTP relay needs real configuration. |
| Mobile security | PASS/PARTIAL | `mobile_security.py`, `routers/mobile_security.py` | Device, app, threat, network, and compliance logic exists; live value depends on enrolled devices. |
| MDM connectors | CONDITIONAL | `mdm_connectors.py`, `routers/mdm_connectors.py` | Intune/JAMF/Workspace ONE/Google connector framework exists; live sync/actions need tenant credentials. |
| CSPM | PASS/PARTIAL | `cspm_engine.py`, `routers/cspm.py` | Versioned scan/finding routes exist with auth; actual cloud evidence requires credentials. |
| Zero trust and identity | PASS/PARTIAL | `zero_trust.py`, `identity.py`, `identity_protection.py` | Policy and identity surfaces exist; restart/scale durability and AD response depth require more proof. |
| Kernel sensors and secure boot | CONDITIONAL | `kernel_sensors.py`, `secure_boot.py`, `enhanced_kernel_security.py` | Routers are optional-imported and host capabilities matter. |
| Browser isolation | LIMITED/PARTIAL | `browser_isolation.py`, `routers/browser_isolation.py` | URL/session/filtering surfaces exist; full remote isolation is limited. |
| Containers, VPN, network sensors | CONDITIONAL | `containers.py`, `vpn.py`, Docker services | Tool integrations are wired; runtime depends on services, privileges, and host networking. |
| Sandbox analysis | CONDITIONAL | `sandbox.py`, `sandbox_analysis.py`, Cuckoo Compose services | API and optional Cuckoo stack exist; meaningful detonation requires sandbox services. |
| Multi-tenant / enterprise plane | PASS/PARTIAL | `multi_tenant.py`, `enterprise.py`, `services/*` | Control-plane primitives exist; enterprise-scale assurance remains an open maturity area. |

## Unified Agent Monitor Snapshot

`unified_agent/core/agent.py` initializes these monitor entries in normal code flow, with process/network controlled by config and AMSI/WebView2 controlled by Windows platform checks:

- process, network
- registry, process_tree, lolbin, code_signing, dns
- memory, whitelist, dlp, vulnerability, yara
- amsi on Windows
- ransomware, rootkit, kernel_security, self_protection, identity
- auto_throttle, firewall
- webview2 on Windows
- cli_telemetry, hidden_file, alias_rename, priv_escalation
- email_protection, mobile_security

The backend telemetry contract currently lists 24 first-class monitor telemetry keys and does not include every local-only scanner/helper.

## Corrected Acceptance Snapshot

Older documents cite dated acceptance counts such as `94 passed` or `96 passed`. Treat those as historical snapshots only unless rerun in the target environment. Current evidence from repository inspection supports a code-level architecture update, not a fresh full-stack runtime certification.

## Remaining Gaps

1. Full remote browser isolation beyond URL/session filtering.
2. Production SMTP relay configuration and end-to-end mail flow validation.
3. Production MDM tenant credentials and live sync/action validation.
4. Durable governance state and evidence-grade high-risk action audit chains.
5. Generated contract inventory and CI checks for route/client/script drift.
6. Detection precision/recall measurement and suppression governance.
7. Optional-service degraded-mode UX and health semantics.

## Bottom Line

Metatron/Seraph has extensive implemented code, broader route/service/page coverage than older summaries report, and meaningful unified-agent, governance, email, mobile, MDM, AI, and SOC surfaces. The accurate current position is **advanced and integration-rich, with explicit conditional runtime dependencies and assurance gaps**.
