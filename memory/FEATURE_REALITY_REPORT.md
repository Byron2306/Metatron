# Feature Reality Report

**Updated:** 2026-05-01
**Scope:** Qualitative implementation narrative aligned to current code paths.

## Executive verdict

Metatron/Seraph is a broad, actively integrated security platform. The codebase contains real implementations for the core dashboard, FastAPI control plane, unified endpoint agent, SOC workflows, AI-agentic detection, SOAR, EDM/DLP, cloud posture, email protection/gateway, mobile security/MDM, deception, and governance services.

The remaining reality gap is not feature-category absence. The main risks are consistency and assurance: contract drift across many APIs and pages, optional integration behavior, durability of governance-sensitive state, and production hardening across secondary/legacy surfaces.

## What is real in the current code

### Backend API and control plane

- Canonical app: `backend/server.py`.
- Database: MongoDB through Motor, with optional `mongomock` for configured test/dev use.
- Router mesh: 62 modules in `backend/routers/`.
- Normal route base: `/api`, with selected routers carrying `/api/v1`.
- Background/runtime services: CCE worker, network discovery, agent deployment, world model events, governance dispatch, Celery worker/beat, and optional integration services.

### Frontend dashboard

- Canonical app: `frontend/src/App.js`.
- API base helper: `frontend/src/lib/api.js`.
- Protected dashboard shell with route consolidation into workspace pages:
  - `/command`
  - `/investigation`
  - `/detection-engineering`
  - `/response-operations`
  - `/ai-activity`
  - `/email-security`
  - `/endpoint-mobility`
  - `/unified-agent`
- Legacy pages/routes still exist where useful, but many older routes redirect to canonical workspaces.

### Unified agent

- Primary behavior source: `unified_agent/core/agent.py`.
- Agent-side surfaces: `unified_agent/server_api.py`, `unified_agent/ui/web/app.py`, `unified_agent/ui/desktop/main.py`, and native UI shells.
- Control-plane API: `backend/routers/unified_agent.py` under `/api/unified/*`.
- Monitor summary keys include registry, process tree, lolbin, code signing, DNS, memory, DLP, ransomware, rootkit, kernel security, self protection, identity, CLI telemetry, email protection, mobile security, and WebView2.

### EDM and DLP

- Agent-side matching and telemetry live in `unified_agent/core/agent.py`.
- Backend dataset governance, signatures, rollout/readiness, telemetry ingest, and rollback live in `backend/routers/unified_agent.py`.
- Broader DLP logic is implemented in `backend/enhanced_dlp.py`.

### Email and mobile domains

- Email protection: `backend/email_protection.py`, `backend/routers/email_protection.py`.
- Email gateway: `backend/email_gateway.py`, `backend/routers/email_gateway.py`.
- Mobile security: `backend/mobile_security.py`, `backend/routers/mobile_security.py`.
- MDM connectors: `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py`.
- UI routes are consolidated through `/email-security` and `/endpoint-mobility`, with legacy redirects for direct email/mobile pages.

### AI-agentic defense and governance

- AATL/AATR: `backend/services/aatl.py`, `backend/services/aatr.py`.
- Cognition and worker logic: `backend/services/cognition_engine.py`, `backend/services/cce_worker.py`.
- Governed dispatch and governance services: `backend/services/governed_dispatch.py`, `backend/services/governance_*`.
- Enterprise policy, identity, token, tool, SIEM, and telemetry chain modules live under `backend/services/`.
- Triune services and routers are present for Metatron, Michael, and Loki.

### Security operations breadth

Implemented surfaces include threats, alerts, dashboard, audit, timeline, hunting, correlation, reports, response, quarantine, SOAR, ransomware, deception, honeypots, honey tokens, CSPM, identity, zero trust, containers, VPN, Zeek, osquery, Sigma, sandbox, browser isolation, MITRE ATT&CK, atomic validation, kernel sensors, secure boot, and integrations.

## What remains conditional

| Area | Current reality |
| --- | --- |
| Production SMTP relay | Gateway logic and APIs exist; live production relay depends on external SMTP configuration and operational deployment. |
| Live MDM sync | Connector framework and APIs exist; real inventory/actions require tenant credentials and provider availability. |
| Optional tools | Trivy, Falco, Suricata, Cuckoo, Elasticsearch, Kibana, Ollama, WireGuard, and SIEM integrations are environment-dependent. |
| Remote deployment | SSH/WinRM paths exist; success depends on credentials, network reachability, remote policy, and post-install heartbeat verification. |
| Full remote browser isolation | URL analysis and sanitization exist; mature pixel-streaming remote isolation remains limited. |
| Governance durability | Strong concepts and services exist; restart/scale durability and denial-path assurance require ongoing hardening. |

## Current product interpretation

The platform should be described as an implementation-heavy adaptive defense platform with substantial code coverage across endpoint, SOC, cloud, email, mobile, data, deception, and AI governance domains. It should not be described as fully equivalent to mature commercial XDR incumbents in global telemetry scale, certification depth, hardened anti-tamper maturity, or managed-service ecosystem.

## Priority actions

1. Keep `backend/server.py`, frontend API helpers, tests, and memory docs synchronized through route inventory checks.
2. Strengthen contract tests for `/api/unified`, email/mobile, governance, CSPM, SOAR, and deployment workflows.
3. Standardize degraded-mode responses for optional integrations.
4. Persist governance-critical state and audit evidence consistently.
5. Expand denial-path tests for auth, policy, M2M ingestion, and high-risk response commands.
