# Metatron Security Features Analysis (Code-Verified)

**Last revalidated:** 2026-04-21  
**Scope:** Security controls and security-feature implementation status based on current code.

---

## 1) Security Control Baseline

## Authentication and identity

- JWT authentication implemented in shared router dependencies.
- `JWT_SECRET` handling is strict in production/strict mode and warns on weak secrets in non-prod.
- `/api/auth/setup` supports guarded first-admin bootstrap (`X-Setup-Token` when configured).
- Remote access guardrail exists: `REMOTE_ADMIN_ONLY` and optional `REMOTE_ADMIN_EMAILS`.

## API surface hardening

- CORS requires explicit origins in prod/strict mode (`backend/server.py`).
- Core auth dependency is used widely across routers.
- Machine-token utilities exist for service-to-service/agent flows (`require_machine_token`, websocket token verification).

## Notable caveat

- Permission model defines permission strings in `ROLES`, but some endpoints use `check_permission("admin")` (role-like token, not permission string). This should be normalized.

---

## 2) Core Security Feature Domains

## Endpoint and agent security

- Unified agent supports register/heartbeat/command lifecycle.
- Agent includes monitor modules for process/network/registry, ransomware, rootkit/kernel security, DLP/EDM, CLI telemetry, email/mobile monitors, etc.
- Agent self-protection and heartbeat/telemetry loops are present in `unified_agent/core/agent.py`.

## Data protection (DLP + EDM)

- DLP monitor supports regex and exact-data-match scanning paths.
- EDM dataset update path includes checksum/signature/version checks with optional required signing.
- Backend unified-agent router exposes dataset versioning, publish, rollout, readiness, and rollback APIs.

## Cloud security posture (CSPM)

- CSPM router supports provider config workflow, scans, findings, posture, compliance, export.
- Scan/finding transition logs and optimistic-version updates are implemented for durable state behavior.
- Provider configure/remove actions are triune-gated (returns queue/decision IDs).
- If no providers are configured, a demo seed fallback can be used to keep UI operational.

## Email security

- Email protection service includes SPF/DKIM/DMARC lookup, URL and attachment analysis, impersonation checks, and DLP checks.
- Email gateway service includes blocklist/allowlist, threat scoring via email-protection integration, quarantine flow, and policy thresholds.
- Both services currently store runtime state in-memory (quarantine, assessments, lists/policies).

## Mobile security and MDM

- Mobile security service includes device registration/status updates, threat detection categories, compliance scoring, and app analysis.
- MDM router exposes a broad connector/action API.
- Current manager implementation instantiates Intune and JAMF connectors; Workspace ONE and Google Workspace remain declared in enums/docs but are not fully instantiated in manager add flow.

## Deployment and runtime controls

- Deployment service has real SSH and WinRM execution paths with retry logic and state transitions.
- Simulated deployment is explicitly controlled by `ALLOW_SIMULATED_DEPLOYMENTS`.
- Agent install scripts are served by backend unified-agent routes.

---

## 3) Security Reality Matrix

| Area | Status | Evidence notes |
|---|---|---|
| JWT auth + password hashing | Implemented | `backend/routers/dependencies.py`, `backend/routers/auth.py` |
| Prod strict JWT/CORS checks | Implemented | `backend/routers/dependencies.py`, `backend/server.py` |
| Remote admin restriction | Implemented | `get_current_user` remote gating logic |
| Machine-token websocket protection | Implemented | `/ws/agent/{agent_id}` token verification |
| Unified-agent security telemetry loops | Implemented | `unified_agent/core/agent.py`, unified router |
| EDM governance pipeline | Implemented | Unified router dataset/rollout APIs + agent EDM update logic |
| CSPM durability + transitions | Implemented | `backend/routers/cspm.py` |
| CSPM provider governance queueing | Implemented | triune gate action with queue/decision IDs |
| Email protection engine | Implemented (in-memory state) | `backend/email_protection.py` |
| Email gateway engine | Implemented (in-memory state) | `backend/email_gateway.py` |
| Mobile security engine | Implemented (in-memory state) | `backend/mobile_security.py` |
| MDM integration breadth | Partial vs claims | Manager currently supports Intune + JAMF instantiation |

---

## 4) Key Security Risks (Current)

1. **Authorization semantic mismatch risk**
   - Permission checks are not fully normalized to one model.

2. **In-memory state in key security modules**
   - Email/mobile/gateway service state durability is limited without additional persistence patterns.

3. **Demo-mode and production evidence separation**
   - CSPM demo fallback is valuable but must remain explicitly labeled in operations/reporting.

4. **Surface-area consistency**
   - Large route footprint requires stronger contract and security regression gating.

---

## 5) Recommended Next Security Steps

1. Normalize RBAC checks (role vs permission API usage).
2. Add persistence for in-memory security-state domains where operational durability is required.
3. Expand denial-path and regression tests for authz-sensitive endpoints.
4. Mark and segregate demo-seeded evidence from production scans in dashboards/reports.
5. Continue hardening parity pass on all legacy/compatibility endpoints.

---

## 6) Conclusion

Security implementation is broad and materially real in core control-plane and enforcement logic. The main remaining work is **consistency and durability hardening**, not feature absence.
