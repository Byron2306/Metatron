# Seraph / Metatron Platform PRD (Living, Code-Aligned)

Generated: 2026-04-18  
Status: Active source-of-truth summary refreshed against current repository behavior

---

## 1) Product Overview

Seraph/Metatron is a unified cyber defense platform combining:
- SOC operations (threats, alerts, hunting, response, reporting),
- endpoint and agent operations (Unified Agent control plane + monitor telemetry),
- advanced services (MCP, vector memory, VNS, quantum, AI),
- enterprise governance controls (identity, policy, token broker, tool gateway, telemetry chain),
- cloud/email/mobile security domains.

The platform is designed for breadth and composability, with production use requiring explicit handling of optional integrations and governed high-impact actions.

---

## 2) Current Product Scope (Code-Evidenced)

### 2.1 Backend/API scope
- 62 router modules under `backend/routers`.
- ~694 route decorators (`@router.get/post/put/delete/patch`) across router files.
- 65 `app.include_router(...)` registrations in `backend/server.py`.

### 2.2 Frontend scope
- 69 page files under `frontend/src/pages` (JS/TS variants).
- Dashboard and domain pages for core SOC, unified agent, advanced, enterprise, email, MDM, mobile, and cloud/CSPM workflows.

### 2.3 Unified agent scope
- 27 concrete monitor modules instantiated in `unified_agent/core/agent.py`.
- Supports registration, heartbeat telemetry, command dispatch, monitor payload transport, and EDM dataset telemetry/control interactions.

---

## 3) Functional Requirements by Domain

## FR-A: Unified Agent Control Plane
**Must provide**
1. Agent registration and authenticated heartbeat ingestion.
2. Per-agent command queueing and result handling.
3. Deployment task submission/listing/detail retrieval.
4. Agent download/install artifact endpoints for multiple OS targets.
5. Monitor telemetry ingestion and dashboard summaries.

**Primary evidence**
- `backend/routers/unified_agent.py` (`/api/unified/*` endpoints)

---

## FR-B: EDM Governance and Data Protection
**Must provide**
1. Dataset version creation/publish with quality gates.
2. Progressive rollouts with staged advancement.
3. Readiness computation and rollback pathways (manual + auto-rollback conditions).
4. EDM telemetry summary and rollout visibility endpoints.

**Primary evidence**
- `backend/routers/unified_agent.py` (EDM dataset + rollout sections)

---

## FR-C: Email Security

### C1. Email Protection
**Must provide**
1. SPF/DKIM/DMARC check APIs and integrated scoring.
2. URL and attachment analysis.
3. Impersonation/BEC indicator detection.
4. DLP checks and quarantine management.
5. Protected-user and sender/domain list management.

**Primary evidence**
- `backend/email_protection.py`
- `backend/routers/email_protection.py`

### C2. Email Gateway
**Must provide**
1. Message processing endpoint (raw/base64 or structured payload).
2. Threat-scored decisioning (accept/reject/quarantine/defer/tag).
3. Blocklist/allowlist/policy management endpoints.
4. Quarantine release/delete operations.

**Primary evidence**
- `backend/email_gateway.py`
- `backend/routers/email_gateway.py`

---

## FR-D: Mobile + MDM Security

### D1. Mobile Security
**Must provide**
1. Device registration, status update, and unenrollment.
2. Threat detection categories (jailbreak/root, risky apps, network threats, compliance gaps).
3. App analysis with OWASP-style checks.
4. Compliance checks and dashboard views.

**Primary evidence**
- `backend/mobile_security.py`
- `backend/routers/mobile_security.py`

### D2. MDM Connectors
**Must provide**
1. Connector lifecycle endpoints (add/remove/connect/disconnect/connect-all).
2. Device/policy sync operations.
3. Remote device action endpoints (lock/wipe/retire/sync/action).
4. Platform metadata endpoint.

**Reality constraint**
- Concrete connector classes currently implemented for **Intune** and **JAMF**.
- Workspace ONE and Google Workspace are represented in platform enums/metadata and router API surface, but not yet implemented as dedicated connector classes in `backend/mdm_connectors.py`.

---

## FR-E: Identity, Governance, and Enterprise Controls

### E1. Identity Protection
**Must provide**
1. Identity threat/incident and stats endpoints.
2. Incident status transitions with durability fields/state logs.
3. Ingestion APIs for Entra, Okta, and M365 OAuth consent events.
4. Token-abuse analytics and optional auto-dispatch policy routes.

**Primary evidence**
- `backend/routers/identity.py`

### E2. Governance
**Must provide**
1. Pending decision listing.
2. Decision approve/deny endpoints.
3. Executor run-once trigger.

**Primary evidence**
- `backend/routers/governance.py`

### E3. Enterprise Security Plane
**Must provide**
1. Identity attestation + nonce retrieval.
2. Policy evaluation and canonical decision integration.
3. Token issue/revoke/validate control APIs (write actions gated).
4. Tool execution workflow (gated).
5. Telemetry ingest/audit/verify endpoints with chain integrity support.

**Primary evidence**
- `backend/routers/enterprise.py`

---

## FR-F: CSPM and Cloud Security
**Must provide**
1. Provider config/list/remove APIs.
2. Scan start and scan history/detail APIs.
3. Findings, resources, compliance report, checks, export, and dashboard APIs.
4. Durable state transitions for scan/finding records in DB-backed mode.

**Security/governance requirements**
- Scan start endpoint requires authenticated user dependency.
- Provider configuration/removal is gated through outbound governance flow.

**Primary evidence**
- `backend/routers/cspm.py`

---

## FR-G: Browser Isolation
**Must provide**
1. Session create/list/detail/delete.
2. URL analysis and HTML sanitization.
3. Blocklist CRUD and mode metadata endpoint.

**Reality note**
- Core isolation APIs are real and functional; full enterprise-grade remote isolation depth remains partial.

**Primary evidence**
- `backend/routers/browser_isolation.py`

---

## 4) Non-Functional Requirements

1. **Authentication + authorization**
   - JWT-based user auth and role permissions (`read`, `write`, `manage_users`, etc.).
   - Machine-token dependencies for selected ingestion/control paths.
2. **Durability**
   - Transition logs and state_version fields on key domains (CSPM findings/scans, identity incidents, deployment tasks).
3. **Operational safety**
   - High-impact enterprise actions use outbound-gate/triune queueing patterns.
4. **Degraded operation**
   - Optional integrations may degrade; core SOC and API flows should remain available.

---

## 5) Deployment and Runtime Contract

### Core practical baseline
- `mongodb`, `backend`, `frontend` are minimum for platform UI/API operation.

### Common local full stack
- Add `redis`, `elasticsearch`, `kibana`, `ollama`, optionally `wireguard`.

### Profile-gated optional services
- `security` profile: `trivy`, `falco`, `suricata`, `zeek`, `volatility`.
- `sandbox` profile: `cuckoo`, `cuckoo-web`, `cuckoo-mongo`.
- `bootstrap` profile: `admin-bootstrap`, `ollama-pull`.

### Network defaults
- Compose binds many services to loopback by default via `BIND_*` envs (for safer local posture).

---

## 6) Known Product Constraints (Current)

1. **MDM connector depth gap**
   - API/platform metadata > concrete connector class coverage (Intune/JAMF implemented; Workspace ONE/Google Workspace pending).
2. **Browser isolation depth**
   - Endpoint/API coverage exists; full remote isolation hardening remains partial.
3. **Integration-coupled behavior**
   - Real depth of some domains depends on external credentials/services being configured and reachable.
4. **Deployment mode interpretation**
   - Simulation paths exist in deployment service only when explicitly enabled by env flag; documentation must distinguish demo from production behavior.

---

## 7) Acceptance Baseline for “Working System”

System should be considered operational when:
1. Backend health endpoint responds and auth flow works.
2. Core dashboard and major SOC pages load data.
3. Unified agent registration + heartbeat + command loop functions.
4. EDM dataset + rollout APIs operate without contract mismatch.
5. Email/mobile/CSPM core APIs respond with valid payloads.
6. Optional integrations fail/degrade explicitly, without collapsing core workflows.

---

## 8) Priority PRD Backlog (Reality-Driven)

1. Implement concrete connector classes for Workspace ONE and Google Workspace in MDM service.
2. Expand browser isolation depth toward full remote-isolation parity.
3. Increase adversarial/denial-path regression coverage around high-impact enterprise and governance flows.
4. Continue run-mode and integration status clarity in docs/UI to reduce operator ambiguity.

---

## 9) Product Position (Current)

Best-fit description: **broad, composable security platform with strong control-plane implementation and active hardening trajectory**, rather than complete depth parity in every integration domain.
