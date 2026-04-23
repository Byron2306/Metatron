# Seraph / Metatron Product Requirements Document (Current-State PRD)

Generated: 2026-04-23  
Source of truth: current repository code and active route wiring

---

## 1. Product goal

Deliver a unified security platform that combines:
- endpoint telemetry and command/control,
- detection/response operations,
- governance-constrained automation,
- cloud/email/mobile security surfaces,
- operator workspaces in a single web frontend.

This PRD is intentionally **code-first**: requirements are written to match what exists in the current codebase and what should remain true.

---

## 2. Scope boundary (current implementation)

### In scope now
- FastAPI backend with modular router architecture.
- React frontend with workspace-first route model.
- Unified agent control plane and endpoint monitor suite.
- Governance pipeline (outbound gate -> triune decision -> executor).
- Security domains: EDR-ish endpoint monitoring, CSPM, email protection/gateway, mobile security, MDM connectors.
- Supporting services: identity/policy/token/tool/telemetry chain.

### Explicitly conditional/optional
- External integrations requiring runtime credentials/services (Cuckoo, SIEM variants, model providers, etc.).
- Advanced sensors that depend on host capabilities.
- Production hardening posture beyond code-level controls (environment dependent).

---

## 3. Functional requirements

## FR-1: Authentication and authorization
1. System SHALL require JWT bearer authentication for protected routes.
2. System SHALL support role-based permissions (`admin`, `analyst`, `viewer`) with explicit permission checks.
3. System SHALL support machine-token verification for internal/agent endpoints.
4. System SHALL enforce stricter JWT secret requirements in production/strict mode.

Code anchors:
- `backend/routers/dependencies.py`
- `backend/routers/auth.py`

## FR-2: API composition and route governance
1. Backend SHALL expose domain routers via centralized registration in `backend/server.py`.
2. All active domain routes SHALL be discoverable under mounted prefixes (`/api`, `/api/v1`, domain-specific prefixes).
3. API root and health endpoints SHALL provide baseline service liveness metadata.

Code anchors:
- `backend/server.py`
- `backend/routers/*`

## FR-3: Unified agent lifecycle
1. System SHALL support agent registration with authenticated enrollment.
2. System SHALL process heartbeat payloads (status, telemetry, monitor summaries, EDM hits).
3. System SHALL support governed command dispatch and command-result ingestion.
4. System SHALL provide deployment queue/list/detail endpoints.
5. System SHALL expose monitor telemetry and dashboard aggregates for fleet visibility.

Code anchors:
- `backend/routers/unified_agent.py`
- `unified_agent/core/agent.py`

## FR-4: Governance-constrained operations
1. High-impact actions SHALL be queued through outbound gate service.
2. Decisions SHALL be represented in triune decision/outbound queue records.
3. Approved decisions SHALL be released by governance executor to operational queues/domains.
4. Decision approval/denial APIs SHALL mutate decision state through authority service.
5. Governance execution events SHALL be auditable through event and telemetry pathways.

Code anchors:
- `backend/services/outbound_gate.py`
- `backend/services/governed_dispatch.py`
- `backend/services/governance_executor.py`
- `backend/services/governance_authority.py`
- `backend/routers/governance.py`

## FR-5: CSPM operations
1. System SHALL support provider configuration lifecycle.
2. System SHALL support CSPM scans, scan history, findings, finding transitions, and compliance views.
3. System SHALL implement durable transition handling for scans/findings (state version + transition log).
4. System SHALL expose dashboard and export endpoints.

Code anchors:
- `backend/routers/cspm.py`
- `backend/cspm_engine.py`

## FR-6: Email security
1. System SHALL support deep email protection analysis endpoints (message/url/attachment/auth/DLP/quarantine).
2. System SHALL support SMTP gateway processing with policy/quarantine/list management.
3. Email security actions SHALL emit world events for traceability.

Code anchors:
- `backend/routers/email_protection.py`
- `backend/email_protection.py`
- `backend/routers/email_gateway.py`
- `backend/email_gateway.py`

## FR-7: Endpoint mobility security
1. System SHALL support mobile device registration/status/compliance/threat/app analysis APIs.
2. System SHALL support MDM connector management, sync, and remote actions (lock/wipe/retire).
3. Mobility APIs SHALL enforce role checks on high-impact operations.

Code anchors:
- `backend/routers/mobile_security.py`
- `backend/mobile_security.py`
- `backend/routers/mdm_connectors.py`
- `backend/mdm_connectors.py`

## FR-8: Telemetry integrity and auditability
1. System SHALL provide tamper-evident telemetry chain primitives.
2. System SHALL support action/audit record creation and integrity validation semantics.
3. Core governed flows SHOULD emit telemetry-chain records.

Code anchors:
- `backend/services/telemetry_chain.py`

## FR-9: Frontend operator experience
1. Frontend SHALL provide authenticated route shell with primary workspaces:
   - command,
   - ai-activity,
   - investigation,
   - detection-engineering,
   - response-operations,
   - email-security,
   - endpoint-mobility.
2. Legacy paths SHALL redirect to current workspace/tab routes.
3. Frontend SHALL integrate to backend APIs through configured API URL strategy.

Code anchors:
- `frontend/src/App.js`
- `frontend/src/pages/*`

---

## 4. Non-functional requirements

1. **Modularity:** router/service decomposition SHALL be maintained.
2. **Security defaults:** production/strict mode SHALL reject unsafe JWT/CORS configuration.
3. **State safety:** high-value transition workflows SHOULD remain conflict-safe and auditable.
4. **Degraded behavior clarity:** optional integration failures SHOULD not break core auth/dashboard/control-plane workflows.
5. **Observability:** critical state changes SHOULD emit events and audit traces.

---

## 5. Deployment/runtime requirements

Baseline stack includes:
- `mongodb`, `redis`, `backend`, `frontend`.

Extended stack can include:
- `elasticsearch`, `kibana`, `ollama`, `wireguard`,
- optional profile services (`trivy`, `falco`, `suricata`, `zeek`, `cuckoo`).

Code anchors:
- `docker-compose.yml`

---

## 6. Acceptance criteria (current-state)

1. Backend boots with configured DB and exposes `/api/health`.
2. Auth flow works (`/api/auth/register|login|me`) with JWT.
3. Unified agent register/heartbeat/list paths are functional.
4. Governance queues receive high-impact actions before execution.
5. CSPM scan + findings + dashboard paths respond.
6. Email protection, email gateway, mobile security, and MDM endpoints respond under authenticated context.
7. Frontend route shell loads and legacy redirects resolve to workspace paths.

---

## 7. Known constraints and risks

1. `backend/server.py` remains a dense composition unit.
2. Some advanced integrations depend on external credentials/services.
3. Production quality relies on operational configuration discipline (env, secrets, dependency health).
4. Feature breadth is high; verification depth must stay aligned with change velocity.

---

## 8. Backlog priorities (code-aligned)

1. Reduce server bootstrap coupling and preserve router modularity.
2. Expand automated contract and denial-path tests for governed operations.
3. Continue converting in-memory fallback surfaces to durable state where operationally critical.
4. Standardize degraded-mode semantics and status signaling for optional integrations.

---

## 9. Product statement

Current code implements a broad, integrated security platform with real control-plane and domain-plane logic. The next requirement phase is about **operational consistency, assurance depth, and maintainability**, not rebuilding core feature foundations.
