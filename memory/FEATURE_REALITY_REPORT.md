# Feature Reality Report

Generated: 2026-04-10  
Scope: Qualitative implementation narrative (feature depth, durability, contract assurance, operational realism)  
Method: Direct repository evidence review across backend, unified agent, frontend routing, and operational wiring.

---

## Executive Verdict

Metatron is a broad, actively integrated security platform with real implementation across endpoint, identity, cloud, response, and governance domains.  
The current codebase is strongest in **control-plane APIs + agent telemetry + workflow orchestration**.  

Recent memory documents overstated some capabilities as fully production-complete. This rebaseline reflects what is materially implemented now:

- **Real and active:** unified agent + EDM telemetry loop, CSPM authenticated API surface, identity workflows, email protection analysis, mobile/MDM management APIs, large frontend workspace wiring.
- **Partially conditional:** eBPF depth (environment dependent), CSPM scanning depth (credential/SDK dependent), mobile/MDM efficacy (real credentials needed), browser isolation remote rendering.
- **Overstated in prior docs:** email gateway as turnkey SMTP relay runtime; 4-platform MDM parity (code currently instantiates Intune + JAMF only).

---

## Rebased Maturity Table

| Domain | Score (0-10) | Status | Why |
|---|---:|---|---|
| Unified Agent Control Plane | 9.0 | PASS | Registration, heartbeat, command polling, monitor payloads, EDM hit ingestion are implemented. |
| EDM Governance & Telemetry | 8.8 | PASS/PARTIAL | Dataset versioning/rollout/rollback + telemetry are real; some hit-tail and schema alignment limits remain. |
| DLP / Exact Data Match | 8.2 | PASS/PARTIAL | Agent DLP/EDM path is real; standalone `enhanced_dlp.py` is not exposed as a dedicated backend router. |
| Email Protection | 8.4 | PASS/PARTIAL | SPF/DKIM/DMARC, URL/attachment/impersonation logic and APIs exist; operational quality depends on live signal quality. |
| Email Gateway | 6.8 | PARTIAL | Strong processing API/framework exists; no in-repo SMTP listener/runtime entrypoint found. |
| Mobile Security | 7.8 | PASS/PARTIAL | Device/threat/compliance APIs are implemented; depth depends on real endpoint data feeds. |
| MDM Connectors | 6.9 | PARTIAL | Intune + JAMF connectors implemented; Workspace ONE / Google Workspace not instantiated in manager path. |
| Identity Protection | 8.2 | PASS/PARTIAL | Broad API/engine surface and incident workflows are present; depends on external event quality. |
| CSPM | 8.0 | PASS/PARTIAL | Authenticated router and engine/scanner framework are real; scan depth depends on credentials/SDK availability. |
| Kernel Security | 7.2 | PARTIAL | eBPF sensor routes and enhanced checks exist; real-time depth depends on BCC/kernel privileges. |
| Browser Isolation | 6.0 | PARTIAL/LIMITED | URL analysis/session APIs implemented; returned proxy path lacks matching router endpoint in current code. |
| Zero Trust | 7.3 | PARTIAL | Engine + router + DB sync implemented; not a universal API enforcement layer across all routes. |

---

## Domain Reality (Code-Evidence Narrative)

### 1) Unified Agent + EDM Governance
**Status: PASS/PARTIAL**

**Evidence**
- `unified_agent/core/agent.py`
  - Monitor initialization includes DLP, identity, kernel security, email protection, mobile security.
  - `heartbeat()` sends telemetry + monitor snapshots + `edm_hits`.
  - `_collect_edm_hits()` queues deduplicated EDM hits.
- `backend/routers/unified_agent.py`
  - `AgentHeartbeatModel` includes `edm_hits`.
  - Ingestion persists telemetry and EDM hit events.
  - EDM dataset/rollout collections and rollout evaluation logic are implemented.
  - Command polling returns commands in `pending` / `queued` states.

**Reality**
- This is one of the most concrete and durable implementation paths in the repository.
- Limitation: monitor schema alignment is not perfect across all monitor payload keys, and EDM hit collection is shaped by the DLP details tail window.

---

### 2) Email Protection
**Status: PASS/PARTIAL**

**Evidence**
- `backend/email_protection.py` implements SPF/DKIM/DMARC checks, URL and attachment analysis, impersonation scoring, and DLP analysis logic.
- `backend/routers/email_protection.py` exposes analysis, stats, and list-management APIs.

**Reality**
- Real code exists for layered analysis and risk scoring.
- Production effectiveness still depends on data quality and integration context (DNS quality, tuning, and threat-intel augmentations).

---

### 3) Email Gateway
**Status: PARTIAL**

**Evidence**
- `backend/email_gateway.py` includes `SMTPGateway`, parsing, scoring, quarantine/list/policy logic, and milter-style callback patterns.
- `backend/routers/email_gateway.py` provides management + `/process` API endpoints.
- No SMTP server start/listen runtime function is present in `backend/email_gateway.py`.

**Reality**
- The gateway is currently an API-driven processing framework and policy/quarantine manager.
- It should not be described as a turnkey in-repo SMTP relay service without additional runtime integration.

---

### 4) Mobile Security + MDM Connectors
**Status: PASS/PARTIAL (Mobile), PARTIAL (MDM)**

**Evidence**
- `backend/mobile_security.py` and `backend/routers/mobile_security.py` implement registration, status, compliance, and analysis APIs.
- `backend/mdm_connectors.py` defines platform enum values but `MDMConnectorManager.add_connector(...)` instantiates only:
  - `IntuneConnector`
  - `JAMFConnector`
  - unsupported platforms return `False`.
- `backend/routers/mdm_connectors.py` exposes status/connectors/devices/policies/sync endpoints.

**Reality**
- Mobile + MDM control-plane APIs are real.
- Current implementation parity is strongest for Intune/JAMF; Workspace ONE and Google Workspace remain framework/enum-level but not full connector implementations in manager wiring.

---

### 5) CSPM + Identity
**Status: PASS/PARTIAL**

**Evidence**
- `backend/routers/cspm.py` uses `APIRouter(prefix="/api/v1/cspm")` and auth dependencies (`Depends(get_current_user)` / `check_permission(...)`) on sensitive routes.
- `backend/cspm_engine.py` plus scanner modules provide cloud scanning framework.
- `backend/routers/identity.py` and `backend/identity_protection.py` implement broad identity workflows.

**Reality**
- Previous claim that CSPM had a public unauthenticated gap is now outdated; authentication checks are present.
- Operational depth still depends on real provider credentials and event pipelines.

---

### 6) Kernel Security + Browser Isolation + Zero Trust
**Status: PARTIAL**

**Evidence**
- Kernel:
  - `backend/ebpf_kernel_sensors.py` and `backend/routers/kernel_sensors.py`.
  - `backend/server.py` conditionally imports kernel router (disabled if import fails).
- Browser isolation:
  - `backend/browser_isolation.py` builds proxy URLs under `/api/browser-isolation/proxy/...`.
  - `backend/routers/browser_isolation.py` does not define a matching `/proxy` route.
- Zero trust:
  - `backend/zero_trust.py` engine + `backend/routers/zero_trust.py` API/state sync.

**Reality**
- These capabilities are meaningful but conditional.
- Production claims should explicitly include environment/runtime dependencies and remaining gaps.

---

## What Is Accurate to Claim Now

### Strong claims (defensible)
- Broad FastAPI domain coverage with substantial router registration and integration.
- Unified agent heartbeat/control-plane with monitor telemetry and EDM governance loop.
- Authenticated CSPM route surface and mature identity API coverage.
- Workspace-based frontend wiring for command, response, investigation, detection engineering, email security, and endpoint mobility.

### Conditional claims (must be qualified)
- eBPF/kernel runtime depth.
- End-to-end CSPM efficacy across providers.
- MDM coverage beyond Intune/JAMF.
- Email gateway as full SMTP relay runtime.
- Full remote browser isolation.

---

## Priority Corrections for Documentation Accuracy

1. Reclassify email gateway from "fully operational SMTP relay" to "processing framework + management API, runtime integration required."
2. Reclassify MDM connectors from "4-platform fully implemented" to "2-platform implemented + 2-platform placeholders/framework."
3. Mark browser-isolation proxy flow as partial until router endpoint parity exists.
4. Keep kernel/eBPF status conditional on environment prerequisites.
5. Keep EDM control-plane strong, while noting telemetry-shape and tail-window caveats.

---

## Final Reality Statement

Metatron is **implementation-rich and operationally meaningful**, with strong control-plane and telemetry foundations.  
The platform is best characterized as:

- **Enterprise-capable in architecture and breadth**
- **Production-leaning in several core paths**
- **Still requiring integration/hardening completion in specific domains before claiming uniform full maturity**

This document supersedes earlier v6.7.0 narrative overstatements and should be treated as the current reality baseline.
