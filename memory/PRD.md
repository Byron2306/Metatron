# Seraph AI Defense System - Product Requirements Document

**Rebaselined:** 2026-04-29

## 1) Product Overview

Seraph AI is a cybersecurity defense platform for SOC operations, endpoint/agent control, governed response automation, world-model security context, deception, cloud/identity posture, email/mobile protection, and optional AI-assisted investigation. The current product should be described as a broad implemented platform with explicit maturity boundaries rather than a uniformly complete enterprise suite.

## 2) Current Product Requirements

### Core required capabilities

1. **Authenticated operator console**
   - React SPA with login, protected routes, and workspace navigation.
   - Default route `/command`; compatibility redirects for older URLs.

2. **Backend API platform**
   - FastAPI app in `backend/server.py`.
   - MongoDB-backed service initialization.
   - REST APIs under `/api` and selected `/api/v1` prefixes.
   - WebSockets for threats and authenticated agent communication.

3. **SOC command workspace**
   - Dashboard, command center, alerts, and threats in the command workspace.
   - Graceful degraded behavior when optional services are unavailable.

4. **World model**
   - Machine-token protected ingestion for entities, edges, detections, alerts, and policy violations.
   - Persisted world state and event emission with triune metadata where available.

5. **Governed high-impact actions**
   - Outbound queue and decision records.
   - Approval/denial APIs.
   - Executor processing for approved decisions.
   - Governance context enforcement for sensitive token/tool paths.

6. **Unified agent operations**
   - Backend unified-agent/swarm APIs.
   - Local agent API/UI for endpoint-side workflows.
   - Clear distinction between verified execution and queued/simulated behavior.

7. **Security domain coverage**
   - Threat intel, hunting, correlation, timelines, reports.
   - Response, EDR, SOAR, quarantine.
   - CSPM, identity, zero trust, deception, browser isolation, sandbox, kernel sensors, secure boot.
   - Email protection/gateway and mobile/MDM workspaces with provider-dependent production fidelity.

## 3) Runtime Requirements

- Required services: MongoDB, backend, frontend.
- Optional services: Redis/Celery, WireGuard, Elasticsearch/Kibana, Ollama, Falco/Suricata/Trivy, sandbox tooling, external providers.
- Production/strict mode must use explicit CORS origins and an internal integration API key.
- Optional integrations must expose clear `unconfigured`, `degraded`, `simulated`, or `live` states where applicable.

## 4) Product Maturity Language

Use these labels in docs and UI where appropriate:

- **Implemented:** code path exists and runs in normal configured environments.
- **Provider-dependent:** code path exists but requires external credentials/services for production fidelity.
- **Simulation-safe:** safe framework or fallback behavior that should not be presented as live execution.
- **Limited:** local/in-memory/demo behavior or an incomplete production workflow.

## 5) Current Version Summary

The current documentation baseline is the April 2026 rebaseline of the March feature set. It includes:

- Workspace-oriented frontend routing.
- FastAPI router mesh with governance, world ingest, enterprise, advanced, email, mobile, MDM, CSPM, identity, and deception domains.
- Mongo-backed governance records for decisions, queues, policy decisions, and agent commands.
- In-process vector memory and local-agent in-memory state where noted.
- Clearer run-mode and maturity boundaries.

## 6) Acceptance Criteria

A release is acceptable when:

1. Minimal stack starts and exposes backend/frontend health.
2. Login and core protected routes render.
3. Command, world, investigation, response, and unified-agent workflows can read representative data.
4. A high-impact action can be queued, approved/denied, and audited.
5. Optional integrations show explicit live/degraded/unconfigured/simulated state.
6. Documentation reflects actual code paths and does not rely on stale feature counts.

## 7) Documentation Policy

Historical changelog material should be maintained separately from the living PRD. This PRD is the current product contract and should stay concise, code-evidence based, and aligned with the run-mode contract and feature reality matrix.
