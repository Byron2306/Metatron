# Metatron Run-Mode Contract (Current Code Baseline)

**Last updated:** 2026-04-16  
**Purpose:** Define required vs optional runtime expectations with current compose/app wiring

---

## 1) Required Core Services

Minimum platform health requires:

- `mongodb`
- `redis`
- `backend`
- `frontend`

Notes:

- Backend uses MongoDB as primary data store.
- Redis is required for Celery broker/result backend in current compose definitions.

---

## 2) Optional/Conditional Services

These services are valuable but not universally required for baseline UI/API operation:

- `elasticsearch`
- `kibana`
- `ollama`
- `wireguard`
- `trivy` (security profile)
- `falco` (security profile)
- `suricata` (security profile)
- `zeek` (security profile)
- `volatility` (security profile)
- `cuckoo`, `cuckoo-web`, `cuckoo-mongo` (sandbox profile)

Behavior expectation:

- Core SOC flows should remain available when optional integrations are unavailable.
- Integration-specific pages should return explicit degraded/unavailable status where applicable.

---

## 3) Compose Profiles and Modes

### Baseline mode

```bash
docker compose up -d mongodb redis backend frontend
```

### Full local mode (without profile-gated security/sandbox extras)

```bash
docker compose up -d mongodb redis backend frontend elasticsearch kibana ollama wireguard celery-worker celery-beat
```

### Security profile mode

```bash
docker compose --profile security up -d
```

### Sandbox profile mode

```bash
docker compose --profile sandbox up -d
```

### Bootstrap profile mode (admin/account + model helper jobs)

```bash
docker compose --profile bootstrap up -d
```

---

## 4) API Routing Contract

- Primary backend route base is `/api` (most routers).
- CSPM and selected routers expose explicit `/api/v1/...` prefixes.
- Frontend uses `REACT_APP_BACKEND_URL` when configured, otherwise same-origin relative paths.

Workspace routing contract:

- `/email-protection` -> `/email-security?tab=protection`
- `/email-gateway` -> `/email-security?tab=gateway`
- `/mobile-security` -> `/endpoint-mobility?tab=mobile`
- `/mdm` -> `/endpoint-mobility?tab=mdm`

---

## 5) Security Runtime Contract

From backend startup/dependency behavior:

- In strict/production mode, weak or missing JWT secret is rejected.
- CORS wildcards are rejected in strict/production mode.
- Remote admin-only gate can block non-local non-admin access.
- Integration machine-token checks can reject internal ingestion paths if tokens are missing.

Operational implication:

- Environment variables are part of runtime correctness, not optional tuning.

---

## 6) Health Verification Sequence

1. `docker compose ps`
2. Backend health: `curl -fsS http://127.0.0.1:8001/api/health`
3. Frontend health: `curl -fsS http://127.0.0.1:3000`
4. Auth sanity:
   - register/login or `/api/auth/setup` (bootstrap path)
5. Domain checks:
   - `/api/unified/agents`
   - `/api/email-protection/stats`
   - `/api/email-gateway/stats`
   - `/api/mobile-security/stats`
   - `/api/mdm/status`
   - `/api/v1/cspm/dashboard`

---

## 7) Known Reality Constraints

1. MDM concrete connector implementations currently present for Intune and JAMF classes; additional platform labels exist in enum/comments.
2. CSPM includes demo fallback behavior when no providers are configured.
3. Optional integrations can affect depth/quality of some feature outputs.
4. Governance and approval-heavy flows should be validated for restart durability in production operations.

---

## 8) "Working" Definition (Current)

System is considered working when:

1. Required core services are healthy.
2. Authenticated UI loads and core workspaces render.
3. Core APIs for unified agent, email security, endpoint mobility, and command/intelligence paths return data without fatal errors.
4. Optional integration failures do not crash core workflows.

---

## 9) Documentation Integrity Rule

All runtime documentation must distinguish:

- **implemented now** (code paths present and wired),
- **implemented but integration-dependent** (requires external credentials/services),
- **planned/not yet concrete** (no current concrete class/path).

This avoids capability inflation and keeps operations predictable.
