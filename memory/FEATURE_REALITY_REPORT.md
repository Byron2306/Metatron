# Feature Reality Report (Code-Revalidated)

Generated: 2026-04-14  
Scope: Major feature domains revalidated against current code paths in `backend/server.py`, `backend/routers/*`, `backend/services/*`, `frontend/src/*`, and `docker-compose.yml`.

## Executive Verdict

Metatron/Seraph currently ships a **broad, real, modular security platform** with production-oriented controls (JWT enforcement, machine-token gates, DB-backed state transitions, startup workers, and containerized dependencies).  

The implementation is strongest in:
- backend router/service breadth,
- unified agent lifecycle/control telemetry,
- identity/CSPM durability patterns,
- email/mobile/MDM feature surfaces.

The most important reality constraints are:
1. Several routes use `check_permission("admin")`, but `"admin"` is not a defined permission token in `ROLES`; those endpoints currently deny all users.
2. Some features are operationally complete in framework terms but still depend on external credentials/infrastructure (SMTP relay target, MDM credentials, cloud credentials).
3. Legacy/alternate surfaces still exist (for example, `unified_agent/server_api.py`) and should not be treated as equivalent to the primary backend contract.

---

## Current Maturity Snapshot

| Domain | Status | Reality Summary |
|---|---|---|
| Core API Platform | PASS | FastAPI app with large modular router mesh; Mongo binding is centralized and active. |
| AuthN/AuthZ | PASS/PARTIAL | JWT + role-permission model + remote-admin gate; permission-token mismatch affects `"admin"` checks. |
| Unified Agent Control Plane | PASS | Register/heartbeat/command/deployment/EDM APIs are extensive and DB-backed. |
| Email Protection | PASS | SPF/DKIM/DMARC checks, phishing/attachment/DLP logic, quarantine workflows. |
| Email Gateway | PASS/PARTIAL | Inline processing/quarantine/block/allow/policy model exists; policy update route currently blocked by admin-permission mismatch. |
| Mobile Security | PASS | Device lifecycle, compliance, threat, app-analysis flows are implemented. |
| MDM Connectors | PASS/PARTIAL | Connector/sync/action framework exists; multiple admin endpoints affected by admin-permission mismatch. |
| CSPM | PASS | `/api/v1/cspm/scan` requires auth; DB-backed scan/finding transitions, provider config, reporting. |
| Identity Protection | PASS | DB-backed incidents, provider event ingestion, token-abuse analytics, response action queuing/dispatch. |
| Deployment Realism | PASS/PARTIAL | Real SSH/WinRM deployment paths; simulated deployments gated by `ALLOW_SIMULATED_DEPLOYMENTS`. |
| Browser Isolation | PARTIAL | URL filtering/sanitization exists; full remote-browser isolation stack is not the default implementation. |

---

## Domain Reality Details

### 1) Core Backend Runtime

**What is real now**
- `backend/server.py` initializes Mongo (real or `mongomock`), binds DB into router dependencies, and registers broad router coverage.
- Startup hooks launch CCE worker, network discovery, deployment service, AATL/AATR init, integration scheduler, and governance executor.
- CORS is runtime-resolved with strict-mode protection for wildcard misuse in prod/strict configurations.
- Machine-token validation is used in websocket and ingest paths.

**Current constraints**
- `backend/server.py` remains a heavy orchestration entrypoint and central coupling point.

### 2) Email Security Plane

**What is real now**
- `backend/routers/email_protection.py`: analysis endpoints, quarantine operations, protected users, blocked senders, trusted domains.
- `backend/routers/email_gateway.py`: stats/process/quarantine/blocklist/allowlist/policy routes.
- Email processing supports raw base64 parsing and structured payload mode.

**Critical accuracy note**
- `PUT /api/email-gateway/policies/{policy_name}` uses `check_permission("admin")`; due to permission-token mismatch this route is effectively unavailable to normal roles until fixed.

### 3) Mobile + MDM Plane

**What is real now**
- `backend/routers/mobile_security.py`: register/update/list/check-compliance/analyze-app/threat and dashboard flows.
- `backend/routers/mdm_connectors.py`: connector lifecycle, sync, device actions, compliance, policies, platforms.

**Critical accuracy note**
- Several MDM endpoints use `check_permission("admin")` and are currently blocked by the same permission-token mismatch.

### 4) Cloud + Identity Planes

**What is real now**
- CSPM router (`/api/v1/cspm`) has authenticated scan start, DB-backed status transitions, findings state transitions, and export/reporting flows.
- Identity router (`/api/v1/identity`) includes durable incident transitions, machine-token ingest endpoints (Entra/Okta/M365), analytics, and response action dispatch.

**Current constraints**
- Cloud and identity value still depends on correct provider credentials and upstream event feeds.

---

## Corrected Interpretation of "Working"

System should be considered working when:
1. Backend auth works (`/api/auth/*`) and protected routes load with valid JWT.
2. Core workflows (threats/alerts/timeline/unified agent) execute against Mongo-backed state.
3. Optional/provider-dependent features degrade clearly without crashing core routes.
4. Deployment and response statuses reflect actual execution outcomes (not implicit success).

System should **not** be considered fully healthy when:
- admin-only flows depend on `check_permission("admin")` without a corresponding permission definition fix,
- required credentials for SMTP/MDM/cloud providers are absent for environments that expect live integrations.

---

## Priority Corrections (Documentation + Engineering)

1. Replace/fix all `check_permission("admin")` usages (map to role check or `manage_users`-style explicit permission).
2. Align all docs to active ports and contracts (`backend :8001`, `frontend :3000`, `unified_agent/server_api.py :8002` as adjunct).
3. Explicitly separate:
   - framework-complete features (code exists),
   - integration-complete features (credentials and provider connectivity verified).
4. Keep memory/review docs aligned to router-level contract evidence, not legacy claims.

---

## Final Reality Statement

Metatron/Seraph is **implementation-rich and operationally credible**, with most major feature domains materially present in code and wired into the API/runtime model.  

The largest near-term correctness gap is **authorization semantics consistency** (not missing feature breadth). Once permission-token mismatches and integration credential onboarding are normalized, the platform’s documented and runtime behavior will align much more tightly.
