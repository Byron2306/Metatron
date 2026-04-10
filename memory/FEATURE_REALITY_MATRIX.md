# Metatron Feature Reality Matrix

Generated: 2026-04-10  
Scope: Quantitative implementation snapshot (feature depth, durability, contract assurance, operational realism)  
Method: Router + service + agent + frontend wiring review against current repository state.

## Legend
- `PASS`: Real logic executes in normal configured environments.
- `PARTIAL`: Real logic exists but depends on integration prerequisites or has notable implementation gaps.
- `LIMITED`: Compatibility/framework-level capability; important runtime pieces are missing or incomplete.

---

## Feature Maturity Score Table

| Domain | Score (0-10) | Status | Evidence Anchor |
|---|---:|---|---|
| Unified Agent Control Plane | 9.0 | PASS | `unified_agent/core/agent.py`, `backend/routers/unified_agent.py` |
| EDM Governance & Telemetry | 8.8 | PASS/PARTIAL | `backend/routers/unified_agent.py` EDM models/rollouts + agent `edm_hits` heartbeat |
| DLP / EDM Detection | 8.2 | PASS/PARTIAL | `DLPMonitor` + `EDMFingerprintEngine`; `enhanced_dlp.py` lacks dedicated router |
| Email Protection | 8.4 | PASS/PARTIAL | `backend/email_protection.py`, `backend/routers/email_protection.py` |
| Email Gateway | 6.8 | PARTIAL | `backend/email_gateway.py`, `backend/routers/email_gateway.py` |
| Mobile Security | 7.8 | PASS/PARTIAL | `backend/mobile_security.py`, `backend/routers/mobile_security.py` |
| MDM Connectors | 6.9 | PARTIAL | `backend/mdm_connectors.py`, `backend/routers/mdm_connectors.py` |
| Identity Protection | 8.2 | PASS/PARTIAL | `backend/identity_protection.py`, `backend/routers/identity.py` |
| CSPM Capability Plane | 8.0 | PASS/PARTIAL | `backend/cspm_engine.py`, `backend/routers/cspm.py` |
| Kernel Security | 7.2 | PARTIAL | `backend/ebpf_kernel_sensors.py`, conditional router import in `backend/server.py` |
| Browser Isolation | 6.0 | PARTIAL/LIMITED | `backend/browser_isolation.py`, `backend/routers/browser_isolation.py` |
| Zero Trust | 7.3 | PARTIAL | `backend/zero_trust.py`, `backend/routers/zero_trust.py` |
| Security Hardening | 8.0 | PASS/PARTIAL | Auth/CORS improvements and route dependencies in active paths |
| Frontend Wiring Integrity | 8.5 | PASS/PARTIAL | `frontend/src/App.js`, `frontend/src/components/Layout.jsx` |

---

## Current Reality Matrix

| Domain | Status | Concrete Evidence | Practical Notes |
|---|---|---|---|
| Backend router composition | PASS | `backend/server.py` has broad `include_router(...)` wiring (65 registrations in current file). | Large surface area increases integration complexity and drift risk. |
| Unified agent register/heartbeat/control | PASS | Agent `register()`, `heartbeat()`, `poll_commands()` + router ingestion and command queue retrieval. | One of the strongest durable paths. |
| EDM publish/rollout/rollback | PASS/PARTIAL | EDM collections + rollout evaluator and telemetry counting in `backend/routers/unified_agent.py`. | Strong governance logic; telemetry shape still needs stricter schema parity. |
| Agent DLP + EDM scan loop | PASS/PARTIAL | `DLPMonitor.scan()` includes clipboard/file/network + exact match scan. | EDM hits in heartbeat derive from monitor details window; tail truncation can reduce completeness. |
| Enhanced DLP engine exposure | LIMITED | `backend/enhanced_dlp.py` defines singleton engine only. | No dedicated router means platform-level usage is narrower than prior claims implied. |
| Email protection analysis | PASS/PARTIAL | SPF/DKIM/DMARC + phishing/attachment/impersonation logic in service; APIs in router. | Strong framework, quality depends on runtime tuning/data sources. |
| Email gateway management | PARTIAL | Gateway parse/process/quarantine/list/policy logic + `/email-gateway/*` APIs. | No in-repo SMTP listener/runtime startup path found. |
| Mobile security management | PASS/PARTIAL | Registration/status/compliance/threat APIs in mobile security modules. | Depends on real device telemetry for production-grade efficacy. |
| MDM connector platform support | PARTIAL | `MDMConnectorManager.add_connector()` instantiates Intune/JAMF; unsupported others return `False`. | Workspace ONE and Google Workspace are enum-level, not full manager-backed connectors. |
| Identity incident APIs | PASS/PARTIAL | `backend/routers/identity.py` and identity engine workflows. | Strong API breadth; depth depends on upstream event quality and response automation maturity. |
| CSPM auth + scan framework | PASS/PARTIAL | `APIRouter(prefix="/api/v1/cspm")` + auth dependencies on key routes. | Real scans require credentials/SDK availability. |
| Kernel/eBPF sensors | PARTIAL | eBPF modules + kernel router, conditionally imported in server. | Environment-dependent (BCC/kernel privileges/capabilities). |
| Browser isolation sessions/analysis | PARTIAL/LIMITED | Session and analysis endpoints exist; service returns proxy path under `/api/browser-isolation/proxy/...`. | Router has no matching `/proxy` endpoint; remote isolation narrative must stay qualified. |
| Zero trust domain APIs | PARTIAL | Zero-trust engine + router + DB sync logic. | Not global enforcement for all API requests. |
| Frontend route/domain alignment | PASS/PARTIAL | Workspace routes for command, investigation, response, email-security, endpoint-mobility in `App.js`. | Some legacy imports/pages are now redirects or effectively orphaned. |

---

## Domain-Specific Detail Tables

### Email Gateway (Rebased)
| Capability | Status | Evidence |
|---|---|---|
| API-based message processing (`/process`) | PASS | `backend/routers/email_gateway.py` |
| Threat scoring + decision model | PASS | `backend/email_gateway.py` (`process_message`) |
| Quarantine + release/delete | PASS | Router quarantine endpoints |
| Blocklist/allowlist management | PASS | Router endpoints + gateway sets |
| Policy retrieval/update APIs | PASS | `/policies` endpoints |
| Native SMTP listener/runtime in repo | LIMITED | No `start/listen/run` SMTP runtime function found in service file |

### MDM Connectors (Rebased)
| Capability | Status | Evidence |
|---|---|---|
| Intune connector | PASS/PARTIAL | `IntuneConnector` in `backend/mdm_connectors.py` |
| JAMF connector | PASS/PARTIAL | `JAMFConnector` in `backend/mdm_connectors.py` |
| Workspace ONE connector implementation | LIMITED | Enum exists, manager does not instantiate connector class |
| Google Workspace connector implementation | LIMITED | Enum exists, manager does not instantiate connector class |
| Connector management API surface | PASS | `backend/routers/mdm_connectors.py` |
| Multi-platform claim (all 4 fully operational) | LIMITED | Not supported by manager wiring in current code |

### Browser Isolation (Rebased)
| Capability | Status | Evidence |
|---|---|---|
| Session creation/listing/deletion APIs | PASS | `backend/routers/browser_isolation.py` |
| URL analysis/sanitization APIs | PASS | `/analyze-url`, `/sanitize` endpoints |
| Proxy URL generation in service | PARTIAL | `backend/browser_isolation.py` returns `/api/browser-isolation/proxy/...` |
| Router proxy endpoint parity | LIMITED | No `/proxy` route present in router file |

---

## Acceptance Snapshot (Rebased)

- No full-suite rerun is attached to this document.
- This matrix is evidence-derived from current code inspection and route/service analysis.
- Historical pass-rate statements in prior memory docs should be treated as point-in-time only.

---

## High-Impact Corrections vs Prior Memory Snapshots

1. **Email Gateway:** reclassified from "fully operational SMTP relay mode" to "processing/control API framework; runtime SMTP serving not in repo."
2. **MDM Connectors:** reclassified from "all four major platforms fully implemented" to "Intune/JAMF implemented; others partial/framework."
3. **Browser Isolation:** explicitly marks proxy route mismatch between service path generation and router exposure.
4. **DLP Narrative:** distinguishes robust agent-side EDM/DLP from standalone backend `enhanced_dlp` exposure gap.

---

## Bottom Line

Metatron remains a high-breadth security platform with substantial real implementation.  
The highest-confidence mature areas are **unified-agent control plane, EDM governance, and broad API/UI wiring**.  
The biggest documentation corrections concern **gateway runtime claims, MDM parity claims, and conditional platform/integration dependencies**.
