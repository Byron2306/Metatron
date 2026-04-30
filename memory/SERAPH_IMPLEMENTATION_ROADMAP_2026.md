# Seraph AI Defender - Technical Implementation Roadmap

**Updated:** 2026-04-30  
**Goal:** Converge the current broad platform into a more deterministic, contract-stable, production-verifiable security system.

---

## 1. Current Source-of-Truth Baseline

- Backend: `backend/server.py`, port `8001`, health at `GET /api/health`.
- Frontend: `frontend/src/App.js`, protected layout, 68 route declarations with workspace redirects.
- Endpoint agent: `unified_agent/core/agent.py`, a large endpoint runtime with 28 monitor-class families.
- Runtime: Docker Compose includes MongoDB, Redis, backend, Celery worker/beat, frontend, Elasticsearch, Kibana, Ollama, WireGuard, nginx, and optional security/sandbox profiles.
- Current maturity: broad implementation with integration-dependent production depth.

---

## 2. Workstreams

| Workstream | Objective |
|---|---|
| Contract integrity | Keep `/api`, `/api/v1`, frontend workspaces, scripts, and agent contracts aligned. |
| Runtime reliability | Ensure success states represent verified execution and optional services degrade clearly. |
| Governance durability | Persist policy, token, approval, and execution evidence with restart/scale safety. |
| Detection quality | Add measurable precision/recall, replay, suppression, and regression loops. |
| Integration readiness | Separate framework-present integrations from credentialed production integrations. |
| Operator experience | Make health, degraded states, run modes, and route behavior clear in UI and docs. |

---

## 3. Priority Roadmap

### Priority 1 - Contract and Route Truth

- Generate a canonical endpoint compatibility map from backend routers.
- Add tests for workspace redirects in `frontend/src/App.js`.
- Validate `/api` versus native `/api/v1` prefixes for major pages and scripts.
- Add route smoke tests for email security and endpoint mobility workspaces.

### Priority 2 - Runtime Health and Degraded-State Semantics

- Add deep health/status endpoints for MongoDB, Redis/Celery, Elasticsearch/Kibana, Ollama, WireGuard, SMTP, MDM, sandbox, cloud credentials, and security sensors.
- Surface optional/fail-open router availability in an operator-visible status payload.
- Ensure background startup failures are visible beyond logs.

### Priority 3 - Production Integration Hardening

- Email gateway: document and test MTA/SMTP relay deployment path, TLS behavior, queue durability, and quarantine persistence.
- MDM connectors: add provider credential validation, permission probes, sync result evidence, and remote-action verification.
- CSPM/SIEM/sandbox: distinguish configured, degraded, and unavailable states.

### Priority 4 - Durable Governance and Action Evidence

- Persist governance executor queues and outcomes.
- Add idempotency, TTL, actor, policy decision, reason code, and evidence fields to high-risk action records.
- Add denial-path regression tests for admin/write/machine-token surfaces.

### Priority 5 - Detection Quality Engineering

- Build replayable event corpora for endpoint, email, mobile, cloud, identity, and network events.
- Track false-positive suppression lifecycle and expiration.
- Measure precision/recall for high-value detection categories before expanding rules.

### Priority 6 - Deployment Truth

- Add preflight checks for SSH/WinRM/agent deployment prerequisites.
- Ensure deployment success requires install evidence and heartbeat confirmation.
- Mark simulations and test-mode results explicitly in API responses.

---

## 4. Acceptance Signals

A release should be considered meaningfully improved when:

1. Route compatibility tests pass across backend, frontend, scripts, and agent paths.
2. Optional integrations have explicit healthy/degraded/unavailable state.
3. High-risk actions have durable audit evidence.
4. Email/MDM production paths have credential and permission probes.
5. `/api/health` remains shallow but is complemented by deep dependency status.
6. Documentation avoids claiming production completion for unconfigured integrations.

---

## 5. Roadmap Principle

Do not expand feature breadth unless the corresponding contract, health, permission, durability, and regression story is clear. The platform already has breadth; the next technical gains come from truthfulness, determinism, and verifiable operations.
