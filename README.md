# Metatron / Seraph AI Defense Platform

Code-verified platform summary for the current repository state.

---

## Overview

Seraph is a multi-domain security platform composed of:

- A FastAPI backend with broad router-based domain separation
- A unified endpoint agent with monitor-based telemetry and control loops
- A React frontend SOC console
- A Docker Compose runtime for local full-stack operation

The platform includes implemented paths for unified agent operations, CSPM workflows, deployment automation, email/mobile security modules, and governance-related control surfaces.

---

## Repository Layout

```text
backend/                FastAPI app, routers, services, domain engines
frontend/               React dashboard application
unified_agent/          Endpoint agent runtime and monitor modules
memory/                 Architecture and review documentation
test_reports/           Validation outputs and integration reports
docker-compose.yml      Full local stack definition
```

---

## Backend Architecture (Current)

Main app entrypoint:

- `backend/server.py`

Notable backend characteristics:

- Router composition is centralized in `server.py` and includes both `/api/*` and selected `/api/v1/*` namespaces.
- Startup initializes background workers/services (CCE worker, network discovery, deployment service, governance executor) with guarded error handling.
- CORS and JWT behavior include strict production/strict-mode checks.

### Core router families

- `backend/routers/unified_agent.py` — register/heartbeat/commands/deployments/EDM control plane
- `backend/routers/cspm.py` — provider config, scans, findings, posture, compliance, exports
- `backend/routers/email_protection.py` — email threat assessment and controls
- `backend/routers/email_gateway.py` — gateway processing, policies, lists, quarantine actions
- `backend/routers/mobile_security.py` — device, threat, compliance, app-analysis endpoints
- `backend/routers/mdm_connectors.py` — connector and device action APIs
- `backend/routers/auth.py` + `backend/routers/dependencies.py` — auth, RBAC helpers, shared dependencies

---

## Unified Agent (Current)

Primary runtime:

- `unified_agent/core/agent.py`

Key implemented behavior:

- Agent registration and heartbeat to `/api/unified/agents/register` and `/api/unified/agents/{agent_id}/heartbeat`
- Periodic monitor execution with monitor telemetry included in heartbeat payloads
- Command handling (including EDM dataset reload/update paths)
- DLP + EDM matching and EDM hit loop-back telemetry

### Agent auth model

- Initial enrollment uses enrollment key derived from `SERAPH_AGENT_SECRET`
- Ongoing auth uses server-issued per-agent token
- Optional trusted-network fallback exists but is disabled by default unless enabled

---

## Security Controls (Implemented)

- JWT secret handling is enforced in production/strict mode (`backend/routers/dependencies.py`)
- CORS origin strictness in production/strict mode (`backend/server.py`)
- Remote non-local access can be restricted with `REMOTE_ADMIN_ONLY`
- Websocket machine-token validation is applied on `/ws/agent/{agent_id}`

### Important consistency note

Permission checks are mixed in current code:

- Permission table is capability-based (`read`, `write`, etc.)
- Some routes use `check_permission("admin")`

This should be normalized to avoid authorization ambiguity.

---

## Domain Modules: Real vs Conditional

### Implemented and operational

- Unified agent control plane and telemetry loops
- EDM dataset/version/rollout APIs
- Email protection analysis engine
- Email gateway processing and controls
- Mobile security device/threat/compliance workflows

### Conditional or partial areas

- **Deployment:** real SSH/WinRM paths exist; success depends on remote credentials/connectivity
- **CSPM:** durable scan/finding workflows exist; if no providers configured, demo-seed fallback may be used
- **MDM:** API/enum surface names 4 platforms; manager currently instantiates Intune and JAMF connectors

---

## Runtime / Deployment

Primary runtime descriptor:

- `docker-compose.yml`

Current compose includes 21 services (including optional profile-driven components), notably:

- Core: `backend`, `frontend`, `mongodb`, `redis`
- Workers: `celery-worker`, `celery-beat`
- Analytics/search: `elasticsearch`, `kibana`
- Local AI/runtime extras: `ollama`, `ollama-pull`
- Security tooling (profile-based): `trivy`, `falco`, `suricata`, `zeek`, `cuckoo`, `volatility`
- Network edge: `wireguard`, `nginx`

Most key service port binds default to localhost-oriented bindings in compose vars.

---

## Quick Start

### 1) Start stack

```bash
docker compose up -d
```

### 2) Run smoke test

```bash
python3 smoke_test.py
```

### 3) Verify backend health

```bash
curl -s http://127.0.0.1:8001/api/health
```

---

## Recommended Environment Variables

Minimum production-relevant values to set explicitly:

- `JWT_SECRET` (strong, length >= 32)
- `INTEGRATION_API_KEY`
- `SERAPH_AGENT_SECRET`
- `CORS_ORIGINS` (explicit list)
- `REMOTE_ADMIN_ONLY` / `REMOTE_ADMIN_EMAILS` as required

Optional but important depending on enabled domains:

- Cloud provider credentials for CSPM
- MDM connector credentials
- SMTP and mail-routing integration details for email gateway deployment patterns

---

## Documentation

Refreshed review docs are in `memory/`, including:

- `memory/SYSTEM_CRITICAL_EVALUATION.md`
- `memory/SYSTEM_WIDE_EVALUATION_MARCH_2026.md`
- `memory/FEATURE_REALITY_REPORT.md`
- `memory/FEATURE_REALITY_MATRIX.md`
- `memory/SECURITY_FEATURES_ANALYSIS.md`

These documents were updated to align with current code behavior and to identify partial/conditional areas explicitly.

---

## Current Positioning Guidance

Accurate current description:

> A high-breadth security platform with strong core control-plane implementation and active hardening progress, with remaining work focused on consistency (RBAC semantics), durability normalization, and contract assurance.

