# Metatron Run-Mode Contract (Current)

**Updated:** 2026-04-18  
**Purpose:** Define required vs optional runtime components and document behavior expectations in healthy and degraded modes.

---

## 1) Core Required Services

For baseline platform operation:
- `mongodb`
- `backend`
- `frontend`

When these are unavailable, the platform is not considered healthy.

---

## 2) Extended Runtime Components (Current docker-compose)

The compose file currently defines a broader runtime set:
- Data / Queue: `mongodb`, `redis`
- API / Workers: `backend`, `celery-worker`, `celery-beat`
- UI / Edge: `frontend`, `nginx`
- Optional/Domain integrations: `elasticsearch`, `kibana`, `ollama`, `wireguard`, `trivy`, `falco`, `suricata`, `zeek`
- Sandbox profile components: `cuckoo`, `cuckoo-web`, `cuckoo-mongo`
- Utility/bootstrap components: `admin-bootstrap`, `ollama-pull`, `volatility`

Not all of these are strictly required for baseline UI + core API workflows.

---

## 3) Minimal, Recommended, and Extended Modes

### Minimal mode (baseline SOC operations)
Bring up:
- `mongodb`
- `backend`
- `frontend`

### Recommended local mode
Add commonly expected dependencies:
- `redis`
- `nginx`
- optional observability (`elasticsearch`, `kibana`) as needed

### Extended detection mode
Include container/network security tool services:
- `trivy`, `falco`, `suricata`, `zeek`

### Sandbox mode
Enable sandbox profile components:
- `cuckoo`, `cuckoo-web`, `cuckoo-mongo`

---

## 4) API Routing Contract

- Frontend routes authenticate users then call backend APIs through `/api/...` contracts.
- Backend mounts many routers under `/api`, with some specialized namespaces using `/api/v1/...` (for example CSPM and selected identity/deception surfaces).
- Governance endpoints are available under `/api/governance/...`.
- Unified agent control plane is under `/api/unified/...`.

---

## 5) Security Contract Expectations by Mode

Across modes, these controls are expected:
- JWT validation and role checks on protected endpoints.
- Production/strict mode rejects weak/missing JWT secret.
- CORS origin validation in production/strict configuration.
- High-impact outbound actions are triune-gated via outbound queue + decision records.
- Governance executor loop processes approved decisions.

If these controls are disabled or bypassed, system should be considered non-compliant for enterprise posture claims.

---

## 6) Degraded-Mode Contract

When optional integrations are unavailable:
- Core SOC flows (auth, dashboard shell, unified agent control plane, primary threat/alert/timeline reads) should still function.
- Features dependent on missing integrations should return explicit status/degraded responses, not generic failures.
- UI should preserve navigation and display actionable degraded-state messaging.

Known caveat:
- Some feature pages may still assume dependency presence and need better degraded-state consistency.

---

## 7) Known Reality Constraints (Current)

1. **MDM platform declaration vs runtime support**
   - API/platform metadata lists Intune, JAMF, Workspace ONE, and Google Workspace.
   - Connector manager currently instantiates Intune and JAMF only.
   - Workspace ONE / Google Workspace should be treated as declared-but-not-runtime-implemented.

2. **Integration-backed capability depth**
   - Email gateway and MDM operations are framework-complete but production efficacy depends on valid environment credentials/configuration.

3. **Contract drift risk**
   - Large router/page surface means API drift can still occur without tighter CI contract checks.

---

## 8) Health Validation Sequence

1. Verify service state (`docker compose ps`).
2. Verify backend health endpoint (`/api/health`).
3. Verify frontend availability (root UI load).
4. Verify authenticated API access (`/api/auth/login` then protected route checks).
5. Verify governance loop readiness by checking pending/approve/executor run-once flow on governance endpoints.
6. Verify integration-specific pages only when corresponding services/credentials are configured.

---

## 9) Definition of "Working" (Updated)

System is considered **working** when:
1. Core required services are healthy.
2. Authenticated user can access and operate primary SOC workflows.
3. Unified agent register/heartbeat and command queue flows function.
4. Governance-gated high-impact actions enter and transition through queue/decision/executor paths correctly.
5. Optional integration failures remain isolated and explicit (no cascade into core workflows).

