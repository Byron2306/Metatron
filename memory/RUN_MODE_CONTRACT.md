# Metatron Run-Mode Contract (2026-04 Refresh)

## Purpose

Define **what is required** to run core platform functionality and what is **optional/integration-dependent** so operators can reason about degraded behavior.

Primary evidence:
- `docker-compose.yml`
- `backend/server.py`
- `backend/routers/dependencies.py`
- `frontend/src/App.js`

---

## 1) Required core runtime

For a baseline functional stack, the following are core:

1. **backend** (`backend/server.py`)
2. **frontend**
3. **mongodb** (or mock DB mode for dev/test)

In compose, these are represented by:
- `backend`
- `frontend`
- `mongodb`

If any of these are unavailable, platform health is degraded beyond normal operations.

---

## 2) Core-adjacent runtime in compose

Current compose file also includes:
- `redis`
- `celery-worker`
- `celery-beat`

These support async/background workflows. The API still has many direct paths, but production behavior is fuller with queue workers online.

---

## 3) Optional integrations (degraded-mode expected)

The following are optional/service-profile dependent:
- `wireguard`
- `elasticsearch`
- `kibana`
- `ollama`
- `trivy` (security profile)
- `falco` (security profile)
- `suricata` (security profile)
- `zeek` (security profile)
- `volatility` (security profile)
- `cuckoo`, `cuckoo-web` (sandbox profile)

Contract:
- Core SOC/API workflows should continue when optional services are down.
- Feature pages tied to unavailable integrations should fail **explicitly and safely**, not silently.

---

## 4) Authentication + operator access contract

- API auth uses bearer JWT (`backend/routers/dependencies.py`).
- Role-based permission gates (`read`, `write`, `manage_users`, etc.) enforce endpoint access.
- Remote access can be constrained by:
  - `REMOTE_ADMIN_ONLY`
  - `REMOTE_ADMIN_EMAILS`
- Machine token flows are implemented for agent/system integration endpoints.

---

## 5) Agent run-mode contract

Unified agent endpoints require one of:
- Enrollment key / trusted enrollment context for register/bootstrap
- Agent/machine token for heartbeat, command polling, command results, websocket

Source:
- `backend/routers/unified_agent.py`
- `backend/routers/dependencies.py`

---

## 6) Governance run-mode contract

High-impact actions are expected to pass through triune governance queueing:
- Outbound gate queues decisions (`services/outbound_gate.py`)
- Governed dispatch persists command/decision context (`services/governed_dispatch.py`)
- Governance executor releases approved actions (`services/governance_executor.py`)

When governance path is unavailable, behavior should default to deny/queue semantics for high-impact operations.

---

## 7) CORS/security mode contract

- `CORS_ORIGINS` is parsed and enforced.
- In production/strict mode (`ENVIRONMENT=prod|production` or `SERAPH_STRICT_SECURITY=true`):
  - wildcard CORS is disallowed
  - weak/missing JWT secret is disallowed

Source:
- `backend/server.py`
- `backend/routers/dependencies.py`

---

## 8) API routing contract

- Main API surface is mounted under `/api` via `backend/server.py`.
- Some routers retain prefixed namespaces (for example `/api/v1/...`) as defined by each router module.
- Frontend route shell (`frontend/src/App.js`) maps to workspace pages and preserves compatibility redirects from legacy page paths.

---

## 9) Acceptance definition: "working"

System is considered working when:

1. Backend + frontend + DB are healthy.
2. Auth/login succeeds and role checks are effective.
3. Core pages (command workspace, unified agent, response ops, investigation, detection engineering) can load.
4. Agent register/heartbeat/command lifecycle works with expected token/enrollment controls.
5. High-impact actions are queued and tracked through governance paths.
6. Optional integrations degrade cleanly when unavailable.

---

## 10) Current risk posture (run-mode specific)

1. **Composition density:** central backend wiring is large and operationally sensitive.
2. **Integration variance:** optional services can produce uneven depth if not explicitly configured.
3. **Mixed maturity:** broad feature surface exists; runbook discipline determines production consistency.

