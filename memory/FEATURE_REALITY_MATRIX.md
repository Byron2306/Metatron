# Metatron Feature Reality Matrix (Rebased)

**Generated:** 2026-04-15  
**Scope:** Quantitative/qualitative implementation snapshot based on current repository code.

## Legend

- `PASS`: Implemented code path executes in normal configured environments.
- `PARTIAL`: Implemented but dependent on optional services, credentials, or deeper hardening/assurance.
- `LIMITED`: Present with narrower scope than full production expectation.

---

## 1) Current Wiring and Coverage Metrics

| Metric | Current Value | Evidence |
|---|---:|---|
| Frontend route entries (`App.js`) | 67 | `frontend/src/App.js` |
| Frontend page files (excluding tests) | 69 | `frontend/src/pages` |
| Backend `include_router` registrations | 65 | `backend/server.py` |
| Router modules (excluding dependencies) | 61 | `backend/routers/*.py` |
| API handler decorators (`@router.*`) | 694 | `backend/routers/*.py` static scan |
| Frontend API call-sites (`fetch`/`axios`) | 339 | `frontend/src/pages/*.jsx|tsx` static scan |
| Pages with API call-sites | 58 | static scan |
| Pages with zero API call-sites | 11 | static scan |
| Unmatched API call-sites found | 1 | `TimelinePage.jsx` false positive due to API base composition |

---

## 2) Domain Reality Matrix

| Domain | Status | Primary Evidence | Practical Notes |
|---|---|---|---|
| Auth + JWT + RBAC | PASS | `backend/routers/auth.py`, `backend/routers/dependencies.py` | JWT + role permissions + remote admin gating are implemented. |
| Core SOC (threats/alerts/hunting/correlation) | PASS | `backend/routers/threats.py`, `alerts.py`, `hunting.py`, `correlation.py` | Core analytics and case workflows are broad and active. |
| Timeline/forensics | PASS/PARTIAL | `backend/routers/timeline.py`, `backend/threat_timeline.py` | Rich timeline APIs; deeper forensic assurance depends on ops/test depth. |
| Response + quarantine + SOAR | PASS/PARTIAL | `backend/routers/response.py`, `quarantine.py`, `soar.py` | Action paths exist; high-impact execution governance depends on queue/approval flow. |
| Unified agent + swarm control | PASS | `backend/routers/unified_agent.py`, `swarm.py`, `agent_commands.py` | Register/heartbeat/control surfaces are implemented. |
| Governance control plane | PASS | `services/outbound_gate.py`, `services/governance_executor.py`, `services/governance_context.py` | Queue/decision/dispatch model is explicit and integrated with audit/world events. |
| World ingest + event-driven cognition | PASS | `routers/world_ingest.py`, `services/world_events.py`, `services/triune_orchestrator.py` | Machine-token gated ingest with optional triune triggers. |
| CSPM | PASS/PARTIAL | `routers/cspm.py`, `cspm_engine.py` | Auth enforced; can seed demo data when providers are absent. |
| Email protection | PASS | `backend/email_protection.py`, `routers/email_protection.py` | SPF/DKIM/DMARC + phishing + DLP logic implemented. |
| Email gateway | PASS/PARTIAL | `backend/email_gateway.py`, `routers/email_gateway.py` | Gateway APIs and policy/quarantine paths exist; production relay depends on deployment config. |
| Mobile security | PASS | `backend/mobile_security.py`, `routers/mobile_security.py` | Device and threat workflows implemented. |
| MDM connectors | PASS/PARTIAL | `backend/mdm_connectors.py`, `routers/mdm_connectors.py` | Multi-platform connectors implemented; enterprise value depends on live credentials. |
| Kernel and secure-boot surfaces | PASS/PARTIAL | `routers/kernel_sensors.py`, `routers/secure_boot.py`, related services | Strong coverage in code; environment/kernel support affects runtime depth. |
| Browser isolation | PARTIAL | `backend/browser_isolation.py`, `routers/browser_isolation.py` | URL analysis/sanitization present; full remote-isolation expectations are broader. |
| Optional AI augmentation | PARTIAL | `services/ai_reasoning.py`, triune and advanced routes | Works with local/remote model dependencies when configured. |

---

## 3) Static Wiring Notes

### Pages with zero direct API call-sites (expected in many cases)

- `frontend/src/pages/AIActivityWorkspacePage.jsx`
- `frontend/src/pages/CommandWorkspacePage.jsx`
- `frontend/src/pages/DetectionEngineeringWorkspacePage.jsx`
- `frontend/src/pages/EmailSecurityWorkspacePage.jsx`
- `frontend/src/pages/EndpointMobilityWorkspacePage.jsx`
- `frontend/src/pages/GraphWorld.jsx`
- `frontend/src/pages/InvestigationWorkspacePage.jsx`
- `frontend/src/pages/JobCard.jsx`
- `frontend/src/pages/LoginPage.jsx`
- `frontend/src/pages/ResponseOperationsPage.jsx`
- `frontend/src/pages/WorldGraph.jsx`

These are mostly workspace/aggregation or presentational wrappers; zero direct API call-sites is not inherently a defect.

### Unmatched call-site note

- `frontend/src/pages/TimelinePage.jsx` static scanner reports `.../api/timelines/recent`, but runtime resolution includes a configurable base URL prefix, and backend route exists at `/api/timelines/recent` via `timelines_router` in `backend/routers/timeline.py`.

---

## 4) Remaining Gaps (Implementation vs Production Expectations)

1. Frontend API base construction is still mixed across pages.
2. Governance and denial-path assurance needs broader automated regression coverage.
3. Optional integration behavior should be more uniformly validated across run modes.
4. Documentation requires periodic script-driven refresh to avoid metric drift.

---

## 5) Bottom Line

The current matrix supports a **high implementation reality** assessment: the majority of major domains are code-complete and wired.  
Current maturity work should prioritize **consistency and assurance**, not raw feature count growth.

