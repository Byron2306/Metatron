# Metatron / Seraph AI Defense Platform

Code-current architecture and operations guide (updated 2026-04-15).

---

## Overview

This repository is a multi-surface security platform with three primary runtime layers:

1. **Backend control plane** (`backend/server.py`)  
   FastAPI API surface, websocket channels, startup workers, governance/event orchestration.

2. **SOC frontend** (`frontend/`)  
   React application with workspace-based operations views.

3. **Unified endpoint agent** (`unified_agent/`)  
   Local monitor/response runtime plus local dashboard experiences.

The platform includes world-state modeling, Triune strategic reasoning (Metatron/Michael/Loki), governance-gated action flows, and broad domain routers (threats, response, integrations, identity, CSPM, email, mobile, deception, and more).

---

## Repository Layout

```text
/backend                  # Main API/control-plane implementation
/frontend                 # React SOC dashboard
/unified_agent            # Endpoint runtime, local dashboards, installers
/memory                   # Internal architecture and review documents
/docs                     # Additional product/feature documentation
/test_reports             # Generated/system test reports
/docker-compose.yml       # Full containerized runtime definition
```

---

## What Is Canonical vs Secondary

### Canonical enterprise surfaces

- **API control plane:** `backend/server.py` (port 8001)
- **SOC web UI:** `frontend` (port 3000)
- **Primary datastore:** MongoDB (port 27017)
- **Canonical local agent dashboard:** `unified_agent/ui/web/app.py` (port 5000)

### Secondary/compatibility surface

- `unified_agent/server_api.py` is a separate FastAPI app with in-memory/JSON state.
- Treat it as local/demo compatibility tooling, not as the canonical enterprise control plane.

---

## Backend Architecture Summary

### Entry point

- `backend/server.py`

### Major characteristics

- Registers a large router set under `/api` (plus explicit `/api/v1` routers).
- Configures MongoDB via Motor, with optional mock mode for test/dev behavior.
- Enforces auth dependencies from `backend/routers/dependencies.py`.
- Exposes websocket endpoints:
  - `/ws/threats`
  - `/ws/agent/{agent_id}` (machine-token validated)
- Starts background services on startup (CCE, discovery, deployment service, integrations scheduler, governance executor).

### Strategic pipeline

World events and strategic reasoning are implemented through:

- `backend/services/world_events.py` (`emit_world_event`)
- `backend/services/world_model.py`
- `backend/services/cognition_fabric.py`
- `backend/services/triune_orchestrator.py`
- `backend/triune/metatron.py`, `michael.py`, `loki.py`

Flow: event classification -> world snapshot -> cognition fusion -> Metatron assessment -> Michael planning -> Loki challenge.

### Governance/action control

Primary modules:

- `backend/services/outbound_gate.py`
- `backend/services/governed_dispatch.py`
- `backend/services/governance_authority.py`
- `backend/services/governance_executor.py`
- `backend/services/policy_engine.py`
- `backend/routers/governance.py`

These provide gated high-impact action handling, decision queues, approvals, and execution release.

---

## Frontend Architecture Summary

### Entry and shell

- `frontend/src/App.js`
- `frontend/src/components/Layout.jsx`
- `frontend/src/context/AuthContext.jsx`

### Route model

The app is organized around workspace routes, with many legacy paths redirected:

- `/command`
- `/investigation`
- `/ai-activity`
- `/response-operations`
- `/detection-engineering`
- `/email-security`
- `/endpoint-mobility`
- `/world`

Additional specialized pages include unified agent, identity, zero trust, CSPM, deception, kernel sensors, reports, settings, and tools.

### Auth behavior

- Auth context uses `/api/auth/login`, `/api/auth/register`, `/api/auth/me`.
- Protected route wrapper gates non-login routes.

---

## Unified Agent Summary

### Core runtime

- `unified_agent/core/agent.py`

Key behaviors:

- monitor scan loop (`scan_all`)
- periodic command polling and execution
- heartbeat emission
- remediation hooks
- endpoint fortress controls
- integration runtime execution with tool allowlist

### Backend API contract

- `backend/routers/unified_agent.py`

Includes register/heartbeat/commands, deployment, monitor views, EDM dataset/version/rollout endpoints, and installer/bootstrap endpoints.

### Local dashboard ownership

- Canonical dashboard: `unified_agent/ui/web/app.py` on port 5000
- Launcher: `unified_agent/run_local_dashboard.sh`
- Built-in minimal UI in `core/agent.py` is fallback/diagnostic and policy-gated by `SERAPH_ALLOW_MINIMAL_UI`.

---

## Run Modes

### Minimal reliable core

```bash
docker compose up -d mongodb backend frontend
```

### Extended local mode (common optional services)

```bash
docker compose up -d mongodb backend frontend wireguard elasticsearch kibana ollama
```

### Security profile mode

```bash
docker compose --profile security up -d
```

### Sandbox profile mode

```bash
docker compose --profile sandbox up -d
```

---

## Environment and Security Notes

Important backend environment controls include:

- `MONGO_URL`, `DB_NAME`, `MONGO_USE_MOCK`
- `JWT_SECRET`
- `ENVIRONMENT`, `SERAPH_STRICT_SECURITY`
- `CORS_ORIGINS`
- `INTEGRATION_API_KEY`
- `REMOTE_ADMIN_ONLY`, `REMOTE_ADMIN_EMAILS`

Production/strict behavior is intentionally tighter for secret strength and CORS origin handling.

---

## Verification and Testing

Representative suites:

- Triune and world logic:
  - `backend/tests/test_triune_orchestrator.py`
  - `backend/tests/test_triune_routes.py`
- Governance controls:
  - `backend/tests/test_governance_token_enforcement.py`
- Unified agent backend contract:
  - `backend/tests/test_unified_agent_*.py`
- Unified agent runtime/UI:
  - `unified_agent/tests/test_monitor_scan_regression.py`
  - `unified_agent/tests/test_endpoint_fortress.py`
  - `unified_agent/tests/test_cli_identity_signals.py`
  - `unified_agent/tests/test_canonical_ui_contract.py`

Additional environment-dependent system scripts exist at repo root (`e2e_system_test.py`, `full_feature_test.py`, `test_unified_agent.py`).

---

## Current Reality and Limitations

The platform is materially implemented across backend, frontend, and agent surfaces.  
Remaining high-value engineering work is primarily assurance-oriented:

1. stronger cross-surface contract invariants,
2. durable/replay-safe governance semantics under restart/scale,
3. consistent degraded-mode behavior for optional integrations,
4. reduced ambiguity between canonical and compatibility runtime surfaces.

---

## Related Internal Artifacts

Updated architecture/review references:

- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`
- `memory/RUN_MODE_CONTRACT.md`
- `memory/SERAPH_BOARD_BRIEF_2026.md`
