# Metatron Feature Reality Matrix

**Updated:** 2026-04-30  
**Scope:** Quantitative-style implementation snapshot aligned to current code paths.

---

## Legend

- `PASS`: Real logic exists and is normally reachable in a configured environment.
- `PASS/PARTIAL`: Real logic exists, but production behavior depends on external services, credentials, host permissions, or deployment wiring.
- `PARTIAL`: Capability surface exists, but depth, durability, or runtime backing is limited.
- `CONDITIONAL`: Router/service may be optional, fail-open, profile-gated, or environment-dependent.

---

## Current Feature Matrix

| Domain | Status | Current evidence | Notes |
|---|---|---|---|
| Backend composition | PASS | `backend/server.py` | FastAPI, MongoDB setup, CORS, router mesh, websockets, startup/shutdown tasks. |
| Frontend routing | PASS | `frontend/src/App.js` | 68 route declarations; protected layout; workspace redirects. |
| Auth and users | PASS | `backend/routers/auth.py`, dependencies | JWT/password/permission dependencies and setup/admin paths. |
| Threats/alerts/dashboard | PASS | routers and pages | Main SOC data surfaces exist. |
| Timeline/audit/reports | PASS/PARTIAL | routers/pages | Core flows exist; evidence/report depth varies by data and integrations. |
| Hunting/correlation/threat intel | PASS/PARTIAL | routers/services | Real service logic with optional feed/model dependencies. |
| SOAR/response/quarantine | PASS/PARTIAL | routers/services | Action surfaces exist; external providers and guarded transitions require verification. |
| Unified agent API | PASS | `backend/routers/unified_agent.py` | Agent registration, commands, downloads/installers, telemetry/control-plane paths. |
| Unified agent runtime | PASS/PARTIAL | `unified_agent/core/agent.py` | 17k-line endpoint runtime with 28 monitor-class families; OS/privilege dependent. |
| EDM/DLP | PASS/PARTIAL | agent DLP monitor, unified agent router, DLP modules | Real dataset and scan concepts; rollout/contract assurance should remain tested. |
| Email protection | PASS | `backend/email_protection.py`, `backend/routers/email_protection.py` | Auth checks, phishing/URL/attachment/DLP/impersonation/quarantine logic. |
| Email gateway | PASS/PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py`, `EmailSecurityWorkspacePage.jsx` | REST processing, policies, queues, lists, quarantine; live relay requires SMTP/MTA deployment. |
| Mobile security | PASS/PARTIAL | `backend/mobile_security.py`, router, `EndpointMobilityWorkspacePage.jsx` | Device/threat/app/compliance model; live mobile telemetry is integration-dependent. |
| MDM connectors | PASS/PARTIAL | `backend/mdm_connectors.py`, router | Intune/JAMF/Workspace ONE/Google connector classes; real sync/actions require credentials. |
| CSPM | PASS/PARTIAL | `backend/routers/cspm.py`, engine | Authenticated route surface; cloud account coverage requires configuration. |
| Identity protection | PASS/PARTIAL | `backend/routers/identity.py`, services | `/api/v1/identity` surface and service logic; response depth is still a maturation area. |
| Zero trust | PASS/PARTIAL | `backend/routers/zero_trust.py`, `backend/zero_trust.py` | Policy/evaluation paths exist; durability/scale assurance remains important. |
| Multi-tenant/enterprise | PASS/PARTIAL | routers/services | API surfaces and services exist; production tenant isolation requires review. |
| Attack paths | CONDITIONAL | try/except import in `server.py` | Registered only if import succeeds. |
| Secure boot | CONDITIONAL | try/except import in `server.py` | Registered only if import succeeds. |
| Kernel sensors | CONDITIONAL | try/except import in `server.py` | Registered only if import succeeds. |
| Browser isolation | PARTIAL | router/service/page | URL filtering/sanitization exists; full remote browser isolation not proven. |
| AI activity/AATL/AATR/CCE | PASS/PARTIAL | services and routers | Framework and workers exist; model/runtime quality depends on config. |
| Triune governance | PASS/PARTIAL | Metatron/Michael/Loki routers, schemas, services | Integrated into backend; governance outcomes require workflow testing. |
| Docker full stack | PASS/PARTIAL | `docker-compose.yml` | Compose covers core and optional stack; host capabilities and env settings matter. |

---

## Current Route and Runtime Facts

| Fact | Value |
|---|---|
| Backend port | `8001` |
| Backend health | `GET /api/health` |
| API root | `GET /api/` |
| Websockets | `/ws/threats`, `/ws/agent/{agent_id}` |
| Frontend primary route | `/` redirects to `/command` after auth |
| Email workspace | `/email-security`; legacy `/email-protection` and `/email-gateway` redirect to tabs |
| Endpoint mobility workspace | `/endpoint-mobility`; legacy `/mobile-security` and `/mdm` redirect to tabs |
| Agent control prefix | `/api/unified/...` |
| CSPM prefix | `/api/v1/cspm...` |
| Identity prefix | `/api/v1/identity...` |

---

## Remaining Gaps

1. Production SMTP/MTA wiring for inline email gateway operation.
2. Production MDM credentials/API permissions for live device sync and remote actions.
3. Contract tests that cover all workspace redirects, backend response shapes, and `/api` vs `/api/v1` paths.
4. Durable persistence review for in-memory queues, gateway state, MDM manager state, and governance execution state.
5. Normalized startup failure semantics for optional routers/services.
6. Stronger denial-path/security regression testing across admin, write, and machine-token routes.
7. Full remote browser isolation if that remains a product goal.

---

## Bottom Line

The current matrix should be read as an implementation reality map, not a marketing scorecard. The codebase contains extensive working logic, but several high-value domains are framework-complete and integration-dependent rather than universally production-complete.
